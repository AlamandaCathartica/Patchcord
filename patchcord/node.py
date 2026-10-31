"""High level: a Worker and a Controller that wire the pieces together.

    # controller (one machine)
    ctl = Controller(tunnel="cloudflared", registry_path="/content/workers.json")
    join = ctl.start()                       # print this join code: workers use it to register themselves
    ctl.syncer("/content/models", channel="models", policy=Policy(extensions=(".safetensors",)))

    # worker (each other machine)
    w = Worker("worker1", sync={"models": "/content/models"}, expose={"comfy": 8188}, join=join)
    code = w.start()                         # pairing code; with `join` set there is nothing to paste

On a LAN, listen on every interface but tell others the machine's real address:

    ctl = Controller(tunnel="local", host="0.0.0.0", advertise_host="192.168.1.10", allow_insecure=True)

`host` is where the node *listens*; `advertise_host` is what it *tells other machines*. If you give only
host="0.0.0.0" the advertised address is detected. 0.0.0.0 is never advertised.
"""
import ipaddress
import socket
import threading
import time

from . import auth, mdns as mdns_mod, network, pairing, tunnel
from .agent import Agent
from .events import Emitter
from .peer import Peer, PeerError
from .registry import Registry
from .transfer import Policy, Pusher, Receiver, SyncLoop


class _Lan:
    """Shared by Worker and Controller: which address to advertise, and LAN announcements (mDNS)."""

    def _setup_address(self, host, advertise_host, provider, mdns):
        self.advertise_host = None
        if provider == "local" or advertise_host is not None:
            self.advertise_host = network.resolve_advertise_host(host, advertise_host, self.log)   # ValueError if unusable
        self._auto_advertise = provider == "local" and advertise_host is None and network.is_unspecified(host)
        self._advertise_setting, self._mdns_setting, self._mdns = advertise_host, mdns, None

    def _refresh_address(self):
        """Re-detect the LAN address (it changes when you move between Wi-Fi networks or DHCP renews)."""
        if self._auto_advertise:
            self.advertise_host = network.resolve_advertise_host(self.agent.host, None, self.log)
        return self.advertise_host

    def _warn_exposure(self):
        if network.is_unspecified(self.agent.host):
            self.log(f"[mesh] listening on all interfaces (port {self.agent.port}): anyone on your network can reach "
                     "this node. Every endpoint except /_mesh/health needs the node key; keep pairing codes private.")

    def _mdns_wanted(self):
        if self._mdns_setting is False or self.advertise_host is None:
            return False
        if network.is_loopback(self.advertise_host):
            return False                                            # announcing 127.0.0.1 to the LAN would be useless
        return self._mdns_setting is True or self.tunnel_provider == "local"

    def _start_mdns(self, role):
        self._stop_mdns()
        if not self._mdns_wanted():
            return
        try:
            try:
                ip = str(ipaddress.IPv4Address(self.advertise_host))
            except ValueError:
                ip = socket.gethostbyname(self.advertise_host)
            self._mdns = mdns_mod.Advertiser(self.name, self.agent.port, ip, role, log=self.log).start()
            self.log(f"[mesh] announcing '{self.name}' on the LAN at {ip}:{self.agent.port} (mDNS)")
        except (OSError, ValueError) as e:                          # multicast is blocked on some networks: not fatal
            self._mdns = None
            self.log(f"[mesh] could not announce on the LAN ({e}); machines can still connect by address")

    def _stop_mdns(self):
        if self._mdns:
            try:
                self._mdns.stop()
            except Exception:  # noqa: BLE001
                pass
            self._mdns = None


def _close(handles):
    for h in handles:
        try:
            h.stop()
        except Exception:  # noqa: BLE001  (closing must never raise: it runs during error handling)
            pass


class Worker(Emitter, _Lan):
    """Run a machine as a Patchcord worker.

    A worker exposes an authenticated agent, can receive synchronized folders, and can register itself with a
    controller using its join code. It keeps itself connected: if the tunnel dies (quick tunnels do) or the
    machine's address changes, it reconnects and registers again.

        w = Worker("gpu-01", join=join_code, tunnel="local", host="0.0.0.0", allow_insecure=True)
        w.start()
        w.status, w.is_running, w.uptime        # "running", True, 93.4
        w.on("worker.disconnected", lambda e: print("lost:", e.reason))
        w.reconnect()                           # open fresh tunnels and register again now
        w.restart()                             # full stop + start, keeping name and key
        w.stop()

    status: "stopped", "starting", "running", "reconnecting", "stopping" or "failed" (the last start failed).
    """

    def __init__(self, name, *, port=0, host="127.0.0.1", advertise_host=None, tunnel="cloudflared", cache_dir=None,
                 sync=None, policy=None, logs=None, expose=None, join=None, allow_insecure=None, key=None, log=print,
                 mdns=None, auto_reconnect=True, monitor_interval=5.0, max_reconnect_attempts=None,
                 reconnect_delay=(2.0, 60.0)):
        """sync: {channel: folder} to receive pushed files into. expose: {name: local_port} of apps to tunnel as well.
        join: the controller's join code; the worker then registers (and re-registers after a restart) by itself.
        host: address to listen on. advertise_host: address to tell others (LAN mode; detected if host is 0.0.0.0).
        mdns: announce on the LAN (None = automatically, when tunnel="local" and the address is a LAN address).
        allow_insecure: accept plain http:// addresses (None = yes in LAN mode, tunnel="local"; no otherwise).
        auto_reconnect / monitor_interval / max_reconnect_attempts / reconnect_delay=(first, longest) seconds:
        how the worker recovers when its tunnel or address goes bad."""
        self.name, self.log, self.tunnel_provider, self.cache_dir = name, log, tunnel, cache_dir
        self.expose, self.join = dict(expose or {}), join
        self.allow_insecure = (tunnel == "local") if allow_insecure is None else allow_insecure
        self.auto_reconnect, self.monitor_interval = auto_reconnect, monitor_interval
        self.max_reconnect_attempts, self.reconnect_delay = max_reconnect_attempts, reconnect_delay
        self._setup_address(host, advertise_host, tunnel, mdns)
        self.agent = Agent(name, key or auth.new_key(), host=host, port=port, logs=logs, log=log, role="worker")
        self.receivers = {c: Receiver(root, c, policy or Policy(), log, on_complete=self._received(c))
                          .attach(self.agent, start=False)
                          for c, root in (sync or {}).items()}
        self.url, self.urls, self.code = "", {}, ""
        self.registered, self.last_error, self.reconnects = False, "", 0
        self._lock = threading.RLock()                 # one lifecycle operation at a time
        self._state, self._started_at, self._connected = "stopped", None, False
        self._stop, self._wake = threading.Event(), threading.Event()
        self._handles, self._join_thread, self._monitor_thread = [], None, None
        self._health_fails = 0

    # ------------------------------------------------------------------ state
    @property
    def status(self):
        return self._state

    @property
    def is_running(self):
        """True while the worker is up (including while it is reconnecting)."""
        return self._state in ("running", "reconnecting")

    @property
    def uptime(self):
        """Seconds since start(); 0.0 when not running. A reconnect does not reset it."""
        return time.monotonic() - self._started_at if self.is_running and self._started_at else 0.0

    def info(self):
        """A small dict for dashboards and `patchcord status` (never contains the key or the pairing code)."""
        return {"name": self.name, "status": self._state, "running": self.is_running, "uptime": round(self.uptime, 1),
                "url": self.url, "urls": dict(self.urls), "port": self.agent.port, "registered": self.registered,
                "connected": self._connected, "reconnects": self.reconnects, "last_error": self.last_error,
                "advertise_host": self.advertise_host}

    def __repr__(self):
        return f"Worker({self.name!r}, status={self._state!r}, url={self.url!r})"

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *exc):
        self.stop()

    def _received(self, channel):
        return lambda path, size: self.emit("transfer.completed", channel=channel, path=path, size=size)

    def _fail(self, phase, error):
        self.last_error = str(error)
        self.emit("worker.error", worker=self.name, phase=phase, error=str(error))

    def _set_connected(self, flag, reason=""):
        """Raise worker.connected / worker.disconnected only when the state actually changes."""
        if flag == self._connected:
            return
        self._connected = flag
        if flag:
            self.emit("worker.connected", worker=self.name, url=self.url)
        else:
            self.emit("worker.disconnected", worker=self.name, reason=reason)

    # ------------------------------------------------------------------ opening and closing the network side
    def _open_tunnels(self, timeout, cancel):
        """Open a tunnel for the agent and for every exposed app. Returns (url, urls, handles). If anything fails,
        whatever was already opened is closed again before the error is raised."""
        handles, urls = [], {}
        kw = dict(cache_dir=self.cache_dir, timeout=timeout, log=self.log, host=self.agent.host,
                  advertise_host=self.advertise_host, cancel=cancel)
        try:
            url, h = tunnel.open_tunnel(self.agent.port, self.tunnel_provider, **kw)
            handles.append(h)
            for name, port in self.expose.items():
                urls[name], h = tunnel.open_tunnel(port, self.tunnel_provider, **kw)
                handles.append(h)
                self._check_exposed_app(name, port)
        except BaseException:
            _close(handles)
            raise
        return url, urls, handles

    def _check_exposed_app(self, name, port):
        if self.tunnel_provider != "local" or not self.advertise_host or network.is_loopback(self.advertise_host):
            return
        try:
            with socket.create_connection((self.advertise_host, port), timeout=1):
                pass
        except OSError:
            self.log(f"[mesh] note: '{name}' (port {port}) does not accept connections at {self.advertise_host} yet. "
                     "If that app listens only on 127.0.0.1, start it on 0.0.0.0 so other machines can reach it.")

    def _make_code(self):
        return pairing.make_code(self.name, self.url, self.agent.key, [r.cap for r in self.receivers.values()], self.urls)

    def _rollback(self):
        """Undo a failed start completely: nothing keeps running, no port stays bound."""
        self._stop_mdns()
        _close(self._handles)
        self._handles = []
        for r in self.receivers.values():
            r.stop()
        self.agent.stop(grace=0)
        self.url, self.urls, self.code = "", {}, ""

    # ------------------------------------------------------------------ lifecycle
    def start(self, timeout=120):
        """Start the agent and tunnels and return the pairing code. Calling start() on a running worker changes
        nothing and returns the current code. If starting fails, everything is rolled back and the error raised."""
        with self._lock:
            if self.is_running:
                self.log(f"[mesh] worker '{self.name}' is already running")
                return self.code
            self._state = "starting"
            self._stop, self._wake = threading.Event(), threading.Event()
            self.last_error, self.registered, self._health_fails = "", False, 0
            try:
                self.agent.start()
                for r in self.receivers.values():
                    r.start()
                self._refresh_address()
                self.url, self.urls, self._handles = self._open_tunnels(timeout, self._stop)
                self.code = self._make_code()
            except BaseException as e:
                self._rollback()
                cancelled = self._stop.is_set()
                self._state = "stopped" if cancelled else "failed"
                if not cancelled:
                    self._fail("start", e)
                raise
            self._warn_exposure()
            self._start_mdns("worker")
            self._started_at, self._state = time.monotonic(), "running"
            self.log(f"[mesh] worker '{self.name}' ready")
            self.emit("worker.started", worker=self.name, url=self.url)
            if self.join:
                self._join_thread = threading.Thread(target=self._join_loop, args=(self._stop, self._wake),
                                                     daemon=True, name="mesh-join")
                self._join_thread.start()
            else:
                self._set_connected(True)
            self._monitor_thread = threading.Thread(target=self._monitor, args=(self._stop,), daemon=True,
                                                    name="mesh-monitor")
            self._monitor_thread.start()
            return self.code

    def stop(self, grace=5.0):
        """Shut down gracefully: end the background threads, close tunnels, let requests already in progress finish
        (up to `grace` seconds), then close the agent. Safe to call at any time, any number of times."""
        self._stop.set()                                   # also abandons a start() that is still waiting for a tunnel
        self._wake.set()
        me = threading.current_thread()
        for t in (self._monitor_thread, self._join_thread):    # outside the lock: a reconnect may be holding it
            if t and t is not me:
                t.join(5)
        with self._lock:
            if self._state == "stopped":
                return
            self._state = "stopping"
            self._set_connected(False, "stopped")
            for t in (self._monitor_thread, self._join_thread):      # started while we waited for the lock
                if t and t is not me:
                    t.join(5)
            self._monitor_thread = self._join_thread = None
            self._stop_mdns()
            _close(self._handles)
            self._handles = []
            for r in self.receivers.values():
                r.stop()
            self.agent.stop(grace=grace)
            self.registered, self._started_at = False, None
            self._state = "stopped"
            self.emit("worker.stopped", worker=self.name)

    def restart(self, timeout=120):
        """Stop and start again, keeping the name, key and port. Returns the new pairing code (the address of a
        quick tunnel changes, which is why registered workers re-register by themselves)."""
        self.stop()
        return self.start(timeout)

    def reconnect(self, timeout=120):
        """Open fresh tunnels and register with the controller again, without stopping the agent (so transfers that
        are in progress are not cut off). Raises RuntimeError if the worker is not running, or whatever made the
        tunnel fail; in that case the worker keeps trying in the background when auto_reconnect is on."""
        with self._lock:
            if not self.is_running:
                raise RuntimeError(f"worker '{self.name}' is not running; use start()")
            previous = self._state
            self._state = "reconnecting"
            self.emit("worker.reconnecting", worker=self.name)
            try:
                if not self.agent.running:
                    self.agent.start()
                self._refresh_address()
                url, urls, handles = self._open_tunnels(timeout, self._stop)
            except BaseException as e:
                if self._stop.is_set():
                    self._state = previous
                else:
                    self._fail("reconnect", e)
                raise
            old, self._handles = self._handles, handles
            _close(old)
            self.url, self.urls = url, urls
            self.code = self._make_code()
            self._start_mdns("worker")
            self.reconnects += 1
            self._health_fails = 0
            self._state, self.last_error = "running", ""
            self.log(f"[mesh] worker '{self.name}' reconnected")
            if self.join:
                self.registered = False
                self._wake.set()                           # register the new address now, not in a minute
            else:
                self._set_connected(True)
            return self.code

    # ------------------------------------------------------------------ background threads
    def _join_loop(self, stop, wake):
        delay, bad_code_reported = 3, False
        while not stop.is_set():
            try:
                info = pairing.parse_join_code(self.join, allow_insecure=self.allow_insecure)
                Peer(info["url"]).request("POST", "/_mesh/register", json_body={"code": self.code},
                                          headers={auth.JOIN_HEADER: info["token"]}, timeout=15)
                if stop.is_set():
                    return                                  # stop() ran while we were talking: no events after worker.stopped
                bad_code_reported = False
                if not self.registered:
                    self.registered = True
                    self.emit("worker.registered", worker=self.name)
                self._set_connected(True)
                delay = 60                                  # registered: check again later (idempotent, keeps us listed)
            except ValueError as e:                         # the join code itself is unusable; waiting will not fix it
                if not bad_code_reported:
                    bad_code_reported = True
                    self.log(f"[mesh] the join code cannot be used: {e}")
                    self._fail("register", e)
                delay = 30
            except PeerError as e:
                if stop.is_set():
                    return
                self.log(f"[mesh] could not register with the controller ({e}); retrying")
                self.last_error = f"could not register with the controller: {e}"
                self.registered = False
                self._set_connected(False, "controller unreachable")
                delay = min(delay * 2, 30) if delay < 60 else 3
            wake.wait(delay)
            wake.clear()

    def _diagnose(self):
        """None if everything is fine, otherwise a short reason."""
        if not self.agent.running:
            return "the agent stopped"
        for h in self._handles:
            alive = getattr(h, "alive", None)
            if alive is not None and not alive():
                return "the tunnel closed"
        if self._auto_advertise:
            now = network.local_ip()
            if not network.is_loopback(now) and now != self.advertise_host:
                return f"this machine's network address changed ({self.advertise_host} -> {now})"
        host = "127.0.0.1" if network.is_unspecified(self.agent.host) else self.agent.host
        if Peer(f"http://{network.format_host(host)}:{self.agent.port}").health(3):
            self._health_fails = 0
        else:
            self._health_fails += 1
            if self._health_fails >= 2:                     # one slow answer is not a failure
                return "the agent does not answer"
        return None

    def _monitor(self, stop):
        attempts, wait = 0, self.monitor_interval
        first, longest = self.reconnect_delay
        while not stop.wait(wait):
            try:
                problem = self._diagnose()
            except Exception as e:  # noqa: BLE001  (never let the monitor die)
                problem = None
                self.log(f"[mesh] monitor: {e}")
            if problem is None:
                attempts, wait = 0, self.monitor_interval
                continue
            if attempts == 0:
                self.log(f"[mesh] worker '{self.name}': {problem}")
                self._fail("monitor", problem)
                self._set_connected(False, problem)
            if not self.auto_reconnect:
                wait = self.monitor_interval
                continue
            attempts += 1
            if self.max_reconnect_attempts and attempts > self.max_reconnect_attempts:
                self.log(f"[mesh] worker '{self.name}': giving up after {attempts - 1} reconnect attempts")
                with self._lock:
                    if not stop.is_set():
                        self._state = "failed"
                return
            try:
                self.reconnect()
                attempts, wait = 0, self.monitor_interval
            except Exception as e:  # noqa: BLE001
                if stop.is_set():
                    return
                wait = min(longest, first * 2 ** (attempts - 1))
                self.log(f"[mesh] reconnect attempt {attempts} failed ({e}); trying again in {wait:.0f}s")


class Controller(Emitter, _Lan):
    """Manage a group of Patchcord workers.

    Start the controller, share its join code with workers, and optionally use syncer() to keep selected folders
    synchronized across online workers. React to changes with events instead of polling:

        ctl.on("worker.connected", lambda e: print(e.worker, "is online"))
        ctl.on("transfer.completed", lambda e: print(e.worker, e.path))

    Pick a machine by what it can do:

        for w in ctl.workers:
            print(w.name, w.online, w.stats["gpus"])
        w = ctl.select_worker(gpu_required=True, min_vram=12000)     # None if no worker has 12 GB free
    """

    def __init__(self, *, name="controller", port=0, host="127.0.0.1", advertise_host=None, tunnel="cloudflared",
                 cache_dir=None, registry_path=None, allow_insecure=None, allow_hosts=None, logs=None,
                 probe_interval=10, stats_interval=30, log=print, mdns=None):
        """host: address to listen on. advertise_host: address to tell workers (LAN mode; detected if host is 0.0.0.0).
        mdns: announce on the LAN (None = automatically, when tunnel="local" and the address is a LAN address).
        allow_insecure: accept plain http:// worker addresses (None = yes in LAN mode, tunnel="local"; no otherwise).
        stats_interval: seconds between refreshes of each online worker's CPU/RAM/disk/GPU numbers."""
        self.name, self.log, self.tunnel_provider, self.cache_dir = name, log, tunnel, cache_dir
        self.allow_insecure = (tunnel == "local") if allow_insecure is None else allow_insecure
        self._setup_address(host, advertise_host, tunnel, mdns)
        self.agent = Agent(name, auth.new_key(), host=host, port=port, logs=logs, log=log, role="controller")
        self.registry = Registry(registry_path, probe_interval, self.allow_insecure, allow_hosts, log=log, emit=self.emit,
                                 stats_interval=stats_interval)
        self.registry.attach(self.agent)
        self.url, self.join_code, self._handle, self.syncers = "", "", None, []
        self._lock, self._state, self._started_at = threading.RLock(), "stopped", None
        self._cancel = threading.Event()

    # ------------------------------------------------------------------ state
    @property
    def status(self):
        return self._state

    @property
    def is_running(self):
        return self._state == "running"

    @property
    def uptime(self):
        return time.monotonic() - self._started_at if self.is_running and self._started_at else 0.0

    def __repr__(self):
        return f"Controller({self.name!r}, status={self._state!r}, url={self.url!r})"

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *exc):
        self.stop()

    # ------------------------------------------------------------------ lifecycle
    def start(self, timeout=120):
        """Start listening and open the tunnel. Returns the join code. Calling it on a running controller returns
        the current join code. If starting fails, everything is rolled back and the error raised."""
        with self._lock:
            if self.is_running:
                self.log(f"[mesh] controller '{self.name}' is already running")
                return self.join_code
            self._state, self._cancel = "starting", threading.Event()
            try:
                self.agent.start()
                self._refresh_address()
                self.url, self._handle = tunnel.open_tunnel(
                    self.agent.port, self.tunnel_provider, cache_dir=self.cache_dir, timeout=timeout, log=self.log,
                    host=self.agent.host, advertise_host=self.advertise_host, cancel=self._cancel)
                self.registry.start_polling()
                self.join_code = pairing.make_join_code(self.url, self.registry.join_token)
            except BaseException:
                self.registry.stop()
                if self._handle:
                    _close([self._handle])
                    self._handle = None
                self.agent.stop(grace=0)
                self.url, self.join_code = "", ""
                self._state = "stopped"
                raise
            self._warn_exposure()
            self._start_mdns("controller")
            self._started_at, self._state = time.monotonic(), "running"
            self.log("[mesh] controller ready")
            self.emit("controller.started", url=self.url)
            return self.join_code

    def stop(self, grace=3.0):
        """Stop syncing, probing and listening. Safe to call any number of times. syncer() loops end with the
        controller: call syncer() again after the next start()."""
        self._cancel.set()
        with self._lock:
            if self._state == "stopped":
                return
            self._state = "stopping"
            for s in self.syncers:
                s.stop()
            self.syncers = []
            self.registry.stop()
            self._stop_mdns()
            if self._handle:
                _close([self._handle])
                self._handle = None
            self.agent.stop(grace=grace)
            self._started_at, self._state = None, "stopped"
            self.emit("controller.stopped")

    # ------------------------------------------------------------------ syncing
    def syncer(self, root, channel="files", policy=None, interval=20):
        """Keep `root` mirrored to every online worker that has the channel. Returns the running SyncLoop."""
        pusher = Pusher(root, channel, policy or Policy(), self.log, emit=self.emit)
        loop = SyncLoop(pusher, self.registry, interval, self.log, emit=self.emit).start()
        self.registry.on_change = lambda _name: [s.wake() for s in self.syncers]   # a worker joined: sync now
        self.syncers.append(loop)
        return loop

    # ------------------------------------------------------------------ workers and their resources
    @property
    def workers(self):
        """Every known worker as a `WorkerInfo` (name, url, online, caps, stats with `gpus`, ...)."""
        return self.registry.workers()

    def worker(self, name):
        """One `WorkerInfo` by name (KeyError if unknown)."""
        return self.registry.worker(name)

    def select_workers(self, **requirements):
        """Workers that meet the requirements, best first. See `Registry.select_workers`
        (gpu_required, min_gpus, min_vram, min_ram, min_disk in MiB, caps, exclude)."""
        return self.registry.select_workers(**requirements)

    def select_worker(self, **requirements):
        """The best worker for the requirements, or None: select_worker(gpu_required=True, min_vram=12000)."""
        return self.registry.select_worker(**requirements)

    def check(self, name, timeout=4.0):
        """Test the connection to one registered worker, in both directions when it is on the LAN.
        Returns the dict described in `patchcord.network.check`."""
        peer = self.registry.peer(name)
        lan = peer.url.startswith("http://")                # a tunnelled worker connects from elsewhere: no return path
        return network.check(peer.url, peer.key, reverse=self.agent.port if lan and self.is_running else False,
                             timeout=timeout)
