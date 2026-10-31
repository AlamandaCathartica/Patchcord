"""Network helpers: which addresses this machine has, which one to tell others, and whether two machines can talk.

    patchcord.network.interfaces()            # [Interface(name, ip, network, ...)]
    patchcord.network.local_ip()              # the address other machines on your LAN would use
    patchcord.network.check("192.168.1.20:8080")   # can this machine reach that node? says why not if it cannot

Standard library only (psutil is used for the interface list when it happens to be installed).

Two rules everything else relies on:
  * 0.0.0.0 (and ::) mean "listen everywhere". They are a bind address, never an address you can connect to, so
    they are never advertised (see `resolve_advertise_host`).
  * A machine on the LAN is reached at its LAN address; 127.0.0.1 only ever reaches the machine you are on.
"""
import ipaddress
import json
import os
import re
import socket
import struct
import subprocess
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit

DEFAULT_PORT = 8080
_HOST_RE = re.compile(r"[A-Za-z0-9]([A-Za-z0-9._-]{0,251}[A-Za-z0-9])?")


# ------------------------------------------------------------------------------------------------ addresses
def _ip(host):
    try:
        return ipaddress.ip_address(str(host).strip().strip("[]").split("%")[0])
    except ValueError:
        return None


def is_unspecified(host):
    """True for 0.0.0.0, :: and an empty host: 'listen everywhere', never a place to connect to."""
    if host is None or str(host).strip() == "":
        return True
    ip = _ip(host)
    return bool(ip and ip.is_unspecified)


def is_loopback(host):
    """True for 127.x.x.x, ::1 and 'localhost': only this very machine can be reached there."""
    if str(host).strip().lower() == "localhost":
        return True
    ip = _ip(host)
    return bool(ip and ip.is_loopback)


def is_link_local(host):
    ip = _ip(host)
    return bool(ip and ip.is_link_local)


def is_private(host):
    ip = _ip(host)
    return bool(ip and (ip.is_private or ip.is_loopback or ip.is_link_local))


def format_host(host):
    """Host as it must appear in a URL: IPv6 addresses get brackets."""
    host = str(host)
    return f"[{host}]" if ":" in host and not host.startswith("[") else host


def split_host_port(text, port=None):
    """'192.168.1.20:8080', '[::1]:8080', 'http://host:8080' or 'host' (+ a default `port`) -> (host, port).
    A port in the text wins over `port`. Raises ValueError with a message fit to show a person."""
    text = str(text or "").strip()
    if "://" in text:
        u = urlsplit(text)
        text = u.netloc
        if port is None and u.port is None:
            port = {"https": 443, "http": 80}.get(u.scheme)
    if not text:
        raise ValueError("no address given")
    host, found = text, None
    if text.startswith("["):                                        # [ipv6]:port
        end = text.find("]")
        if end < 0:
            raise ValueError(f"bad address: {text!r}")
        host, rest = text[1:end], text[end + 1:]
        if rest:
            if not rest.startswith(":"):
                raise ValueError(f"bad address: {text!r}")
            found = rest[1:]
    elif text.count(":") == 1:
        host, found = text.split(":")
    elif text.count(":") > 1 and _ip(text) is None:
        raise ValueError(f"bad address: {text!r}")
    if found is not None:
        port = found
    host = host.strip()
    try:
        port = int(port)
    except (TypeError, ValueError):
        raise ValueError(f"{text!r} needs a port, like 192.168.1.20:8080") from None
    if not 1 <= port <= 65535:
        raise ValueError(f"port {port} is out of range (1-65535)")
    if not (_ip(host) or _HOST_RE.fullmatch(host)):
        raise ValueError(f"bad address: {host!r}")
    return host, port


# ------------------------------------------------------------------------------------------------ interfaces
class Interface:
    """One IPv4 address on this machine."""

    def __init__(self, name, ip, netmask="", multicast=True, up=True):
        self.name, self.ip, self.netmask, self.multicast, self.up = name, ip, netmask, multicast, up
        self.loopback, self.link_local = is_loopback(ip), is_link_local(ip)
        try:
            self.network = str(ipaddress.ip_interface(f"{ip}/{netmask}").network) if netmask else ""
        except ValueError:
            self.network = ""

    def to_dict(self):
        return {"name": self.name, "ip": self.ip, "network": self.network, "multicast": self.multicast,
                "loopback": self.loopback, "link_local": self.link_local}

    def __repr__(self):
        return f"Interface({self.name!r}, {self.ip!r}, network={self.network!r})"


def _from_psutil():
    import psutil
    stats, out = psutil.net_if_stats(), []
    for name, addrs in psutil.net_if_addrs().items():
        st = stats.get(name)
        for a in addrs:
            if a.family == socket.AF_INET and a.address:
                flags = getattr(st, "flags", "") or ""
                out.append(Interface(name, a.address, a.netmask or "", "multicast" in flags or not flags,
                                     bool(st.isup) if st else True))
    return out


def _from_ioctl():
    """Linux: one ioctl per interface name (no external programs)."""
    import fcntl
    out = []
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        for _, name in socket.if_nameindex():
            req = struct.pack("256s", name.encode()[:15])
            try:
                flags = struct.unpack("H", fcntl.ioctl(s, 0x8913, req)[16:18])[0]            # SIOCGIFFLAGS
                ip = socket.inet_ntoa(fcntl.ioctl(s, 0x8915, req)[20:24])                    # SIOCGIFADDR
                mask = socket.inet_ntoa(fcntl.ioctl(s, 0x891b, req)[20:24])                  # SIOCGIFNETMASK
            except OSError:
                continue                                                                      # no IPv4 address
            out.append(Interface(name, ip, mask, bool(flags & 0x1000), bool(flags & 0x1)))
    return out


def _from_ifconfig():
    """macOS / BSD: parse `ifconfig`."""
    text = subprocess.run(["ifconfig"], capture_output=True, text=True, timeout=5).stdout
    out, name, flags = [], "", ""
    for line in text.splitlines():
        m = re.match(r"^(\S+?):\s+flags=\w+<([^>]*)>", line)
        if m:
            name, flags = m.group(1), m.group(2)
            continue
        m = re.match(r"\s+inet (\d+\.\d+\.\d+\.\d+) netmask (0x[0-9a-fA-F]+|\d+\.\d+\.\d+\.\d+)", line)
        if m and name:
            mask = m.group(2)
            if mask.startswith("0x"):
                mask = socket.inet_ntoa(struct.pack(">I", int(mask, 16)))
            out.append(Interface(name, m.group(1), mask, "MULTICAST" in flags, "UP" in flags))
    return out


def _from_hostname():
    """Last resort (e.g. Windows without psutil): the addresses the hostname resolves to, plus the routed one."""
    seen, out = set(), []
    try:
        names = [i[4][0] for i in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET)]
    except OSError:
        names = []
    for ip in names + [_routed_ip() or ""]:
        if ip and ip not in seen:
            seen.add(ip)
            out.append(Interface("?", ip))
    if "127.0.0.1" not in seen:
        out.append(Interface("lo", "127.0.0.1", "255.0.0.0"))
    return out


def interfaces(include_loopback=True):
    """The IPv4 addresses of this machine that are up: [Interface(name, ip, network, multicast, link_local, ...)]."""
    found = []
    for source in (_from_psutil, _from_ioctl, _from_ifconfig, _from_hostname):
        try:
            found = source()
        except Exception:  # noqa: BLE001  (a source that does not work on this OS: try the next one)
            continue
        if found:
            break
    out = [i for i in found if i.up and not is_unspecified(i.ip) and (include_loopback or not i.loopback)]
    out.sort(key=lambda i: (i.loopback, i.link_local, i.name))
    return out


def _routed_ip():
    """The local address the OS would use to reach the outside. A UDP connect() sends nothing."""
    for probe in ("10.255.255.255", "192.0.2.1", "8.8.8.8"):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect((probe, 9))
                ip = s.getsockname()[0]
            if ip and not is_unspecified(ip):
                return ip
        except OSError:
            continue
    return None


def local_ip():
    """The address other machines on your network use to reach this one. Falls back to 127.0.0.1 when there is no
    network (then only this machine can connect)."""
    ip = _routed_ip()
    if ip and not is_loopback(ip) and not is_link_local(ip):
        return ip
    usable = [i for i in interfaces(include_loopback=False) if not i.link_local]
    return usable[0].ip if usable else "127.0.0.1"


def local_addresses():
    """Every address that means 'this machine' (for telling local nodes from remote ones)."""
    mine = {"127.0.0.1", "::1", "localhost"}
    mine.update(i.ip for i in interfaces())
    return mine


def resolve_advertise_host(host, advertise_host=None, log=print):
    """Pick the address a node tells other machines to use. Raises ValueError if the choice cannot work.

        advertise_host given      used as is (a hostname, a NAT or port-forward address, ...), but never 0.0.0.0
        listening on 0.0.0.0      this machine's LAN address is detected
        listening on one address  that address
    """
    if advertise_host is not None:
        adv = str(advertise_host).strip().strip("[]")
        if is_unspecified(adv):
            raise ValueError("advertise_host cannot be 0.0.0.0: that means 'every interface', not an address other "
                             "machines can connect to. Use this machine's LAN address, e.g. advertise_host=\"192.168.1.10\"")
        if not (_ip(adv) or _HOST_RE.fullmatch(adv)):
            raise ValueError(f"advertise_host {advertise_host!r} is not an address or host name")
        ip = _ip(adv)
        if ip and not is_unspecified(host) and not is_loopback(host) and adv != str(host).strip("[]"):
            log(f"[mesh] note: listening on {host} but advertising {adv}; other machines must be able to reach {adv}")
        elif ip and not is_loopback(adv) and adv not in local_addresses():
            log(f"[mesh] note: {adv} is not an address of this machine (NAT, port forwarding or a typo?)")
        return adv
    if is_unspecified(host):
        ip = local_ip()
        if is_loopback(ip):
            log("[mesh] no network address found: advertising 127.0.0.1, so only this machine can connect")
        return ip
    host = str(host).strip().strip("[]")
    return "127.0.0.1" if host.lower() == "localhost" else host


def port_available(port, host=""):
    """True if nothing is listening on `port` (0 = 'any free port' = always available)."""
    if not port:
        return True
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            if os.name == "nt":
                if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            else:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)         # same as the agent: TIME_WAIT is fine
            s.bind((host, int(port)))
            return True
        except OSError:
            return False


def gateway():
    """The default gateway's address, or None when it cannot be found."""
    try:
        if os.path.exists("/proc/net/route"):
            with open("/proc/net/route") as f:
                for line in f.read().splitlines()[1:]:
                    p = line.split()
                    if len(p) > 2 and p[1] == "00000000" and int(p[3], 16) & 2:
                        return socket.inet_ntoa(struct.pack("<I", int(p[2], 16)))
        cmd = (["route", "print", "0.0.0.0"] if os.name == "nt" else ["route", "-n", "get", "default"])
        text = subprocess.run(cmd, capture_output=True, text=True, timeout=5).stdout
        m = re.search(r"gateway:\s*(\S+)", text) or re.search(r"0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)", text)
        return m.group(1) if m else None
    except (OSError, ValueError, subprocess.SubprocessError):
        return None


def internet_connected(timeout=2.0):
    """True if a TCP connection to a public address works (one connection, nothing is sent)."""
    for addr in (("1.1.1.1", 443), ("8.8.8.8", 53)):
        try:
            socket.create_connection(addr, timeout=timeout).close()
            return True
        except OSError:
            continue
    return False


# ------------------------------------------------------------------------------------------------ checking a connection
def _explain(exc, host, port):
    """(error text, hint) for a failed connection, in words a person can act on."""
    reason = getattr(exc, "reason", exc)
    text = str(reason)
    if isinstance(reason, socket.gaierror):
        return f"cannot find a machine called '{host}'", "Check the spelling, or use its IP address instead."
    if isinstance(reason, ConnectionRefusedError):
        hint = (f"The machine answered, but nothing is listening on port {port}. Is the node running? If it is, it may "
                "be listening on 127.0.0.1 only: start it with host=\"0.0.0.0\" (or `--lan`) so other machines can connect.")
        return "connection refused", hint
    if isinstance(reason, (socket.timeout, TimeoutError)) or "timed out" in text:
        return "timed out", ("No answer. Usual causes: a firewall dropping port {p} (allow it on the machine that runs the "
                             "node), a wrong IP address, machines on different networks or VLANs, guest Wi-Fi that isolates "
                             "devices, or a VPN.").format(p=port)
    if isinstance(reason, OSError) and getattr(reason, "errno", None) in (101, 113, 10051, 10065):
        return "no route to that machine", "The two machines are not on a network that can reach each other."
    return text or exc.__class__.__name__, ""


def check(target, key=None, *, reverse=False, timeout=4.0):
    """Can this machine reach a Patchcord node? `target`: URL or host:port. Returns a dict, never raises:

        ok, url, name, role, latency_ms, error, hint, authenticated, reverse

    key      the node's key: also checks that the node accepts it (authenticated is True/False, else None)
    reverse  a port on *this* machine: also asks the node to connect back to it, so you learn whether the node can
             reach you too (a worker must, to register with a controller). Needs `key`.
    """
    res = {"ok": False, "url": "", "name": "", "role": "", "latency_ms": None, "error": "", "hint": "",
           "authenticated": None, "reverse": None}
    try:
        text = str(target or "").strip()
        if text.startswith(("http://", "https://")):
            u = urlsplit(text)
            if not u.hostname:
                raise ValueError("bad address")
            url, host, port = f"{u.scheme}://{u.netloc}", u.hostname, u.port or (443 if u.scheme == "https" else 80)
        else:
            host, port = split_host_port(text, DEFAULT_PORT)
            url = f"http://{format_host(host)}:{port}"
    except ValueError as e:
        res.update(error=str(e), hint="Use a URL (http://192.168.1.20:8080) or host:port.")
        return res
    res["url"] = url
    if is_unspecified(host):
        res.update(error="0.0.0.0 is not an address you can connect to",
                   hint="That means 'listen on every interface'. Use the machine's real address (see patchcord.network.local_ip() "
                        "on it).")
        return res

    def get(path, method="GET", body=None, headers=None):
        req = urllib.request.Request(url + path, data=body, method=method,
                                     headers={"User-Agent": "patchcord/0.1", **(headers or {})})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8") or "{}")

    t0 = time.monotonic()
    try:
        info = get("/_mesh/health")
    except urllib.error.HTTPError as e:
        res.update(error=f"answered with HTTP {e.code}", hint="Something is listening there, but it is not a Patchcord node.")
        return res
    except (urllib.error.URLError, OSError) as e:
        res["error"], res["hint"] = _explain(e, host, port)
        if is_loopback(host):
            res["hint"] += " (127.0.0.1 only reaches the machine you are on.)"
        return res
    except ValueError:
        res.update(error="answered, but not with Patchcord's reply", hint="Something else is listening on that port.")
        return res
    res["latency_ms"] = round((time.monotonic() - t0) * 1000)
    if not isinstance(info, dict) or not info.get("ok") or not str(info.get("protocol", "")).startswith("mesh"):
        res.update(error="answered, but not with Patchcord's reply", hint="Something else is listening on that port.")
        return res
    res.update(ok=True, name=str(info.get("name", "")), role=str(info.get("role", "")))
    if key:
        try:
            get("/_mesh/whoami", headers={"X-Mesh-Key": key})
            res["authenticated"] = True
        except urllib.error.HTTPError as e:
            res.update(ok=False, authenticated=False, error="the node rejected the key" if e.code == 401 else f"HTTP {e.code}",
                       hint="The pairing code is out of date (the node was restarted?). Use its newest code.")
            return res
        except (urllib.error.URLError, OSError, ValueError):
            pass
        if reverse and res["ok"]:
            try:
                back = get("/_mesh/reach", "POST", json.dumps({"port": int(reverse)}).encode(),
                           {"X-Mesh-Key": key, "Content-Type": "application/json"})
                res["reverse"] = {"ok": bool(back.get("ok")), "error": back.get("error", ""), "address": back.get("address", "")}
            except (urllib.error.URLError, OSError, ValueError):
                res["reverse"] = {"ok": None, "error": "the node could not be asked", "address": ""}
            if res["reverse"]["ok"] is False:
                res.update(ok=False, error=f"{res['name'] or 'the node'} cannot connect back to this machine on port {reverse}",
                           hint=f"Allow incoming connections to port {reverse} here (firewall), or the worker cannot register.")
    return res


def describe(res):
    """A check() result as readable text."""
    lines = []
    if res.get("ok"):
        who = res.get("name") or "node"
        role = f" ({res['role']})" if res.get("role") else ""
        lines.append(f"[OK]   Reached {who}{role} at {res['url']} in {res['latency_ms']} ms")
        if res.get("authenticated"):
            lines.append("[OK]   The node accepts the key")
        if res.get("reverse") and res["reverse"].get("ok"):
            lines.append(f"[OK]   The node can connect back to this machine ({res['reverse'].get('address', '')})")
    else:
        lines.append(f"[FAIL] Cannot reach {res.get('url') or '?'}: {res.get('error')}")
        if res.get("hint"):
            lines.append(f"       {res['hint']}")
    return "\n".join(lines)


def to_json(obj):
    return json.dumps(obj, indent=2, default=lambda o: o.to_dict() if hasattr(o, "to_dict") else str(o))
