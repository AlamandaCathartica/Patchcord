"""patchcord.doctor(): find out why a machine cannot connect.

    import patchcord
    patchcord.doctor()                                          # this machine
    patchcord.doctor(target="MJ1-....")                         # ...and can it reach this controller? (join code,
    patchcord.doctor(target="http://192.168.1.10:8080")         #  pairing code, URL or host:port)

Nothing here changes anything: it only looks (it briefly opens a throw-away server on a free port to test the LAN
path, and opens one TCP connection to a public address to see whether the internet is reachable).
"""
import os
import platform
import shutil
import sys

from . import auth, mdns, network, pairing

OK, WARN, FAIL, INFO = "ok", "warn", "fail", "info"
_TAG = {OK: "[OK]  ", WARN: "[WARN]", FAIL: "[FAIL]", INFO: "[INFO]"}


class Check:
    def __init__(self, status, title, hint=""):
        self.status, self.title, self.hint = status, title, hint

    def to_dict(self):
        return {"status": self.status, "title": self.title, "hint": self.hint}


class Report:
    """The result of doctor(): `checks`, `network` and `security` (ordered key/value pairs) and the totals."""

    def __init__(self):
        self.checks, self.network, self.security = [], [], []

    def add(self, status, title, hint=""):
        self.checks.append(Check(status, title, hint))
        return status == OK

    @property
    def passed(self):
        return sum(c.status == OK for c in self.checks)

    @property
    def warnings(self):
        return sum(c.status == WARN for c in self.checks)

    @property
    def failures(self):
        return sum(c.status == FAIL for c in self.checks)

    @property
    def ok(self):
        """True when nothing failed (warnings are allowed)."""
        return self.failures == 0

    def to_dict(self):
        return {"ok": self.ok, "passed": self.passed, "warnings": self.warnings, "failures": self.failures,
                "checks": [c.to_dict() for c in self.checks], "network": dict(self.network),
                "security": dict(self.security)}

    def format(self):
        out = ["PATCHCORD DIAGNOSTICS", ""]
        for c in self.checks:
            out.append(f"{_TAG[c.status]} {c.title}")
            if c.hint and c.status in (WARN, FAIL):
                out.append(f"       {c.hint}")
        for title, rows in (("NETWORK", self.network), ("SECURITY", self.security)):
            if rows:
                out += ["", title] + [f"  {k + ':':<16}{v}" for k, v in rows]
        out += ["", "RESULT", f"  {self.passed} check{'s' if self.passed != 1 else ''} passed"]
        if self.warnings:
            out.append(f"  {self.warnings} warning{'s' if self.warnings != 1 else ''}")
        if self.failures:
            out.append(f"  {self.failures} failed")
        return "\n".join(out)


def _target_url(target):
    target = str(target).strip()
    if target.startswith(pairing.JOIN_PREFIX):
        return pairing.parse_join_code(target, allow_insecure=True)["url"]
    if target.startswith(pairing.PREFIX):
        return pairing.parse_code(target, allow_insecure=True)["url"]
    return target


def _http_server_check(r):
    try:
        from http.server import ThreadingHTTPServer
        srv = ThreadingHTTPServer(("127.0.0.1", 0), None)
        srv.server_close()
        r.add(OK, "HTTP server available")
    except Exception as e:  # noqa: BLE001
        r.add(FAIL, f"HTTP server cannot start ({e})",
              "Patchcord's agent needs to open a listening socket. Check for a sandbox or security software.")


def _lan_loopback_check(r, ip):
    """Start a throw-away agent on every interface and connect to it through the LAN address, the way another
    machine would. Catches a wrong advertised address and local firewalls that also block self-connections."""
    from .agent import Agent
    agent = Agent("doctor", auth.new_key(), host="0.0.0.0")
    try:
        agent.start()
        res = network.check(f"http://{ip}:{agent.port}", timeout=3)
        if res["ok"]:
            r.add(OK, f"Agent reachable on the LAN address ({ip})")
        else:
            r.add(WARN, f"Agent not reachable at {ip}: {res['error']}", res["hint"] or
                  "A firewall or VPN may be blocking connections to this machine's own LAN address.")
    except OSError as e:
        r.add(WARN, f"Could not open a listening socket on all interfaces ({e})",
              "LAN mode (host=\"0.0.0.0\") will not work until this is allowed.")
    finally:
        agent.stop(grace=0)


def doctor(port=8080, *, target=None, registry_path=None, internet=True, show=True, file=None):
    """Check this machine for everything Patchcord needs. Prints a report and returns a `Report`.

    port           the port you intend to use (a node started with port=0 picks a free one on its own)
    target         optional: a URL, host:port, join code or pairing code to test the connection to
    registry_path  optional: a saved worker list, to check its file permissions (it holds secret keys)
    internet       False skips the internet check (offline machines, quick runs)
    show / file    print the report (to `file`, default stdout)
    """
    r = Report()

    # --- Python and the standard library pieces Patchcord relies on
    v = sys.version_info
    ver = f"{v.major}.{v.minor}.{v.micro}"
    if v >= (3, 9):
        r.add(OK, f"Python version: {v.major}.{v.minor}")
    else:
        r.add(FAIL, f"Python version: {ver}", "Patchcord needs Python 3.9 or newer.")
    _http_server_check(r)

    # --- port
    if network.port_available(port):
        r.add(OK, f"Port {port} available")
    else:
        r.add(WARN, f"Port {port} is already in use",
              "Another program is using it. Pick another port, or leave port=0 so Patchcord chooses a free one.")

    # --- interfaces
    lan = [i for i in network.interfaces(include_loopback=False) if not i.link_local]
    ip = network.local_ip()
    if lan:
        r.add(OK, "Network interface detected" + f" ({lan[0].name} {lan[0].ip})" if len(lan) == 1
              else f"Network interfaces detected ({len(lan)})")
    else:
        r.add(WARN, "No network interface with an address found",
              "Connect to a network. Controller and worker on this same machine still work with the default settings.")
    if lan and not network.is_loopback(ip):
        _lan_loopback_check(r, ip)

    # --- LAN discovery
    try:
        sock, _ = mdns._multicast_socket(mdns.lan_ips())
        sock.close()
        r.add(OK, "LAN discovery (mDNS) available")
    except OSError as e:
        r.add(WARN, f"LAN discovery (mDNS) unavailable ({e})",
              "Machines can still connect by address: patchcord.discovery.add_host(\"192.168.1.20\", 8080).")

    # --- cloudflared
    exe = shutil.which("cloudflared")
    cached = os.path.join(os.path.expanduser("~"), ".cache", "patchcord", "cloudflared" + (".exe" if os.name == "nt" else ""))
    if exe or os.path.isfile(cached):
        r.add(OK, "cloudflared installed")
    else:
        r.add(WARN, "cloudflared not installed",
              "Only needed for public tunnels. Patchcord downloads it on first use (needs internet), or install it "
              "yourself. LAN mode (tunnel=\"local\") does not use it.")

    # --- internet
    online = None
    if internet:
        online = network.internet_connected()
        if not online:
            r.add(WARN, "No internet connection",
                  "Public tunnels (cloudflared) need it; LAN mode (tunnel=\"local\") does not.")

    # --- optional extras (information only)
    try:
        import psutil  # noqa: F401
        r.add(INFO, "psutil installed (detailed CPU and memory statistics)")
    except ImportError:
        r.add(INFO, "psutil not installed (optional: pip install psutil for detailed CPU and memory statistics)")
    r.add(INFO, "GPU statistics available (nvidia-smi found)" if shutil.which("nvidia-smi")
          else "No GPU statistics (nvidia-smi not found)")

    # --- the connection the user is asking about
    if target:
        try:
            url = _target_url(target)
        except ValueError as e:
            r.add(FAIL, f"Cannot read target: {e}", "Paste a full join code (MJ1-...), pairing code (MK1-...), URL or host:port.")
        else:
            res = network.check(url)
            if res["ok"]:
                r.add(OK, f"Can reach {res['url']} ({res['latency_ms']} ms)")
            else:
                r.add(FAIL, f"Cannot reach {res['url'] or url}: {res['error']}", res["hint"])

    # --- network and security summary
    r.network = [("Local IP", ip if lan else "none found"), ("Gateway", network.gateway() or "unknown")]
    if internet:
        r.network.append(("Internet", "Connected" if online else "Not connected"))
    r.network += [("Interface", f"{i.name}  {i.ip}" + (f"  ({i.network})" if i.network else "")) for i in lan[:4]]
    try:
        key_ok = auth.valid_key(auth.new_key())
    except Exception:  # noqa: BLE001
        key_ok = False
    r.add(OK if key_ok else FAIL, "Node key generation works" if key_ok else "Cannot generate node keys",
          "" if key_ok else "The secrets module failed; the system random source may be unavailable.")
    r.security = [("Node key", "Available" if key_ok else "UNAVAILABLE"),
                  ("TLS", "Not enabled (LAN mode is plain HTTP; cloudflared tunnels use HTTPS)")]
    if registry_path:
        if not os.path.isfile(registry_path):
            r.security.append(("Worker list", "not created yet"))
        elif os.name == "nt":
            r.security.append(("Worker list", "permission bits do not apply on Windows; keep it in your user folder"))
        else:
            mode = os.stat(registry_path).st_mode & 0o777
            if mode & 0o077:
                r.add(WARN, f"Worker list is readable by other users (mode {mode:o})",
                      f"It holds secret keys. Run: chmod 600 {registry_path}")
            r.security.append(("Worker list", f"mode {mode:o}" + ("" if not mode & 0o077 else "  (too open)")))

    if show:
        print(r.format(), file=file)
    return r


def system_summary():
    return f"Python {platform.python_version()} on {platform.platform()}"