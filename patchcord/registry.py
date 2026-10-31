"""The controller's list of workers: add by code, probe, persist, and let workers register themselves.

Every worker is also described by what it can do (`stats`: CPU, RAM, disk, GPUs, refreshed while it is online), so a
controller can pick a machine for a job:

    reg.select_worker(gpu_required=True, min_vram=12000)       # best worker with a GPU that has 12 GB free, or None
"""
import json
import os
import threading
import time

from . import auth, pairing
from .peer import Peer, PeerError

MIB = 1 << 20


class WorkerInfo:
    """A read-only description of one worker (no key). `stats` always has a `gpus` list, empty while unknown."""

    def __init__(self, entry):
        self.name, self.url, self.online = entry["name"], entry["url"], bool(entry.get("online"))
        self.enabled, self.caps, self.urls = bool(entry.get("enabled", True)), list(entry.get("caps", [])), dict(entry.get("urls", {}))
        self.last_seen, self.stats_time = entry.get("last_seen"), entry.get("stats_time")
        self.stats = {"gpus": [], **(entry.get("stats") or {})}
        self.has_stats = bool(entry.get("stats"))

    @property
    def gpus(self):
        return self.stats.get("gpus") or []

    @property
    def free_vram(self):
        """Free memory (MiB) of the GPU with the most free memory; 0 without a GPU."""
        return max((g.get("mem_free_mib", 0) for g in self.gpus), default=0)

    @property
    def free_ram(self):
        """Available RAM in MiB, or None when unknown."""
        ram = self.stats.get("ram") or {}
        free = ram.get("available", (ram["total"] - ram["used"]) if "total" in ram and "used" in ram else None)
        return None if free is None else free / MIB

    @property
    def free_disk(self):
        """Free disk space in MiB, or None when unknown."""
        free = (self.stats.get("disk") or {}).get("free")
        return None if free is None else free / MIB

    def to_dict(self):
        return {"name": self.name, "url": self.url, "online": self.online, "enabled": self.enabled, "caps": self.caps,
                "urls": self.urls, "last_seen": self.last_seen, "stats": self.stats if self.has_stats else None}

    def __repr__(self):
        return f"WorkerInfo({self.name!r}, online={self.online}, gpus={len(self.gpus)})"


class Registry:
    def __init__(self, path=None, probe_interval=10, allow_insecure=False, allow_hosts=None,
                 reserved=("all", "controller"), log=print, on_change=None, emit=None, stats_interval=30):
        """emit(event, **data): worker.connected / worker.disconnected / worker.removed (worker=name, url=...).
        stats_interval: seconds between refreshes of each online worker's CPU/RAM/disk/GPU numbers."""
        self.path, self.probe_interval, self.log, self.on_change = path, probe_interval, log, on_change
        self.emit, self.stats_interval, self._poller = emit, stats_interval, None
        self.allow_insecure, self.allow_hosts, self.reserved = allow_insecure, allow_hosts, set(reserved)
        self.join_token = auth.new_key()
        self._peers, self._lock, self._stop = {}, threading.RLock(), threading.Event()
        self._load()

    # ------------------------------------------------------------------ persistence
    def _load(self):
        if not self.path or not os.path.isfile(self.path):
            return
        try:
            with open(self.path, encoding="utf-8") as f:
                data = json.load(f)
            if auth.valid_key(data.get("join_token")):
                self.join_token = data["join_token"]          # workers already running keep working after a restart
            for w in data.get("peers", []):
                info = pairing.validate(w, self.allow_insecure, self.allow_hosts)
                self._peers[info["name"]] = {**info, "enabled": bool(w.get("enabled", True)), "online": False,
                                             "last_seen": w.get("last_seen")}
        except (OSError, ValueError, TypeError, AttributeError):
            self.log("[mesh] could not read the saved worker list; starting empty")

    def _save(self):
        if not self.path:
            return
        data = json.dumps({"join_token": self.join_token,
                           "peers": [{k: p[k] for k in ("name", "url", "key", "caps", "urls", "enabled", "last_seen")}
                                     for p in self._peers.values()]})
        try:
            os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
            tmp = self.path + ".part"
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)   # it holds secret keys
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(data)
            os.replace(tmp, self.path)
        except OSError as e:
            self.log(f"[mesh] could not save the worker list: {e}")

    # ------------------------------------------------------------------ changing the list
    def add(self, code_or_info, verify=True):
        """Add (or update) a worker from a pairing code or a dict. Same name = new address replaces the old.
        Raises ValueError if the data is bad, the name is reserved, the address belongs to another worker, or (verify)
        the worker does not answer."""
        info = (pairing.parse_code(code_or_info, self.allow_insecure, self.allow_hosts)
                if isinstance(code_or_info, str)
                else pairing.validate(code_or_info, self.allow_insecure, self.allow_hosts))
        name = info["name"]
        if name.lower() in self.reserved:
            raise ValueError(f"the name '{name}' is reserved")
        with self._lock:
            for other in self._peers.values():
                if other["url"] == info["url"] and other["name"] != name:
                    raise ValueError(f"that address is already paired as '{other['name']}'")
        online = False
        if verify:
            online = Peer(info["url"], info["key"], name).health(10)
            if not online:
                raise ValueError(f"'{name}' does not answer. Restart it and use its new code.")
        with self._lock:
            old = self._peers.get(name, {})
            entry = {**info, "enabled": old.get("enabled", True), "online": online,
                     "last_seen": time.time() if online else old.get("last_seen"),
                     "stats": old.get("stats") if old.get("url") == info["url"] else None,
                     "stats_time": old.get("stats_time") if old.get("url") == info["url"] else None}
            changed = old.get("url") != entry["url"] or old.get("key") != entry["key"] or old.get("online") != online
            self._peers[name] = entry
            self._save()
        if online and not old.get("online"):
            self._event("worker.connected", worker=name, url=entry["url"])
        if online and (not old.get("online") or entry.get("stats") is None):
            self._stats_soon(name)
        if changed and self.on_change:
            self.on_change(name)
        return self._public(entry)

    def _stats_soon(self, name):
        """A worker just came online: fetch its numbers now, not at the next poll."""
        threading.Thread(target=self.refresh_stats, kwargs={"force": True, "only": name}, daemon=True,
                         name="mesh-stats").start()

    def _event(self, name, **data):
        if self.emit:
            try:
                self.emit(name, **data)
            except Exception as e:  # noqa: BLE001
                self.log(f"[mesh] event {name}: {e}")

    def remove(self, name):
        with self._lock:
            if name not in self._peers:
                raise KeyError(name)
            url = self._peers.pop(name)["url"]
            self._save()
        self._event("worker.removed", worker=name, url=url)

    def set_enabled(self, name, enabled):
        with self._lock:
            self._peers[name]["enabled"] = bool(enabled)
            self._save()

    # ------------------------------------------------------------------ reading
    @staticmethod
    def _public(p):
        return {k: v for k, v in p.items() if k != "key"} | {"stats": p.get("stats")}

    def workers(self):
        """Every worker as a `WorkerInfo`."""
        with self._lock:
            return [WorkerInfo(p) for p in self._peers.values()]

    def worker(self, name):
        """One `WorkerInfo`; KeyError if unknown."""
        with self._lock:
            return WorkerInfo(self._peers[name])

    def select_workers(self, gpu_required=False, min_gpus=None, min_vram=None, min_ram=None, min_disk=None, caps=(),
                       exclude=()):
        """Online, enabled workers that meet every requirement, best first.

        gpu_required   at least one GPU            min_gpus   at least this many GPUs (each with min_vram, if given)
        min_vram       MiB free on one GPU        min_ram / min_disk   MiB available / free
        caps           capability strings the worker must advertise (e.g. "sync:models")
        exclude        worker names to skip

        A requirement about something a worker has not reported yet (no stats so far) counts as not met. Best =
        most free GPU memory, then most free RAM, then name."""
        caps, exclude, out = set(caps or ()), set(exclude or ()), []
        for w in self.workers():
            if not (w.online and w.enabled) or w.name in exclude or not caps <= set(w.caps):
                continue
            usable = [g for g in w.gpus if min_vram is None or g.get("mem_free_mib", 0) >= min_vram]
            if (gpu_required or min_vram is not None) and not usable:
                continue
            if min_gpus and len(usable) < min_gpus:
                continue
            if min_ram is not None and (w.free_ram is None or w.free_ram < min_ram):
                continue
            if min_disk is not None and (w.free_disk is None or w.free_disk < min_disk):
                continue
            out.append(w)
        out.sort(key=lambda w: (-w.free_vram, -(w.free_ram or 0), w.name))
        return out

    def select_worker(self, **requirements):
        """The best worker for the requirements (see select_workers), or None."""
        found = self.select_workers(**requirements)
        return found[0] if found else None

    def snapshot(self):
        """Every worker without its secret key, for showing in a UI."""
        with self._lock:
            return [self._public(p) for p in self._peers.values()]

    def peer(self, name):
        with self._lock:
            p = self._peers[name]
            return Peer(p["url"], p["key"], p["name"], p["caps"], p["urls"])

    def online(self):
        with self._lock:
            return [Peer(p["url"], p["key"], p["name"], p["caps"], p["urls"])
                    for p in self._peers.values() if p["online"] and p["enabled"]]

    # ------------------------------------------------------------------ probing
    def probe_all(self):
        with self._lock:
            items = [(p["name"], p["url"], p["key"]) for p in self._peers.values()]
        for name, url, key in items:
            ok = Peer(url, key, name).health(5)
            with self._lock:
                p = self._peers.get(name)
                if not p or p["url"] != url:
                    continue                                    # removed or re-registered while we were asking
                flipped = p["online"] != ok
                p["online"] = ok
                if ok:
                    p["last_seen"] = time.time()
            if flipped:
                self._event("worker.connected" if ok else "worker.disconnected", worker=name, url=url)
                if ok:
                    self._stats_soon(name)
                if self.on_change:
                    self.on_change(name)

    def refresh_stats(self, force=False, only=None):
        """Ask each online worker for its CPU/RAM/disk/GPU numbers (at most every `stats_interval` seconds each).
        `only`: just this worker."""
        now = time.time()
        with self._lock:
            due = [(p["name"], p["url"], p["key"]) for p in self._peers.values()
                   if p["online"] and (only is None or p["name"] == only)
                   and (force or now - (p.get("stats_time") or 0) >= self.stats_interval)]
        for name, url, key in due:
            try:
                stats = Peer(url, key, name).stats(8)
            except PeerError:
                continue                                        # the next probe decides whether it is offline
            with self._lock:
                p = self._peers.get(name)
                if p and p["url"] == url:
                    p["stats"], p["stats_time"] = stats, time.time()

    def start_polling(self):
        """Probe workers (and refresh their stats) in the background. Safe to call again after stop()."""
        if self._poller and self._poller.is_alive():
            return self
        self._stop = threading.Event()
        stop = self._stop

        def loop():
            while not stop.is_set():
                try:
                    self.probe_all()
                    self.refresh_stats()
                except Exception as e:  # noqa: BLE001
                    self.log(f"[mesh] probe: {e}")
                stop.wait(self.probe_interval)
        self._poller = threading.Thread(target=loop, daemon=True, name="mesh-probe")
        self._poller.start()
        return self

    def stop(self):
        self._stop.set()
        if self._poller and self._poller is not threading.current_thread():
            self._poller.join(3)
        self._poller = None

    # ------------------------------------------------------------------ self-registration
    def attach(self, agent):
        """Add POST /_mesh/register (workers call it with the join token) and GET /_mesh/peers (node key)."""
        from .agent import ApiError

        @agent.route("POST", "/_mesh/register",
                     auth=lambda req: auth.check(self.join_token, req.headers.get(auth.JOIN_HEADER)))
        def _register(req):
            body = req.json()
            try:
                return self.add(body.get("code") or body)
            except ValueError as e:
                raise ApiError(400, str(e)) from None

        @agent.route("GET", "/_mesh/peers")
        def _peers(req):
            return {"peers": self.snapshot()}
        return self
