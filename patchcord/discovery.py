"""Find other Patchcord machines on your network.

    patchcord.discover()                              # mDNS + the machines you registered by hand; prints a table
    patchcord.discovery.add_host("192.168.1.20", 8080)   # register one manually (kept in ~/.patchcord/hosts.json)

Two sources:
  * mDNS: nodes started in LAN mode announce themselves (`tunnel="local"` with a real LAN address).
  * Manual: some networks block multicast (guest Wi-Fi, many VLANs, some VPNs). Register the address yourself.

Every candidate is then asked `/_mesh/health` (the one open endpoint), so the list shows which machines can
actually be reached from *here*, with a hint for those that cannot. Finding a machine does not authorise anything:
to use it you still need its pairing code or the controller's join code.
"""
import threading

from . import mdns, network, state

HOSTS_FILE = "hosts.json"


# ------------------------------------------------------------------------------------------------ manual hosts
def _hosts_path():
    return state.path(HOSTS_FILE)


def hosts():
    """The manually registered machines: [{host, port, label}]."""
    data = state.read_json(_hosts_path(), {})
    out = []
    for h in (data.get("hosts") if isinstance(data, dict) else None) or []:
        try:
            out.append({"host": str(h["host"]), "port": int(h["port"]), "label": str(h.get("label", ""))})
        except (KeyError, TypeError, ValueError):
            continue
    return out


def add_host(host, port=None, label=""):
    """Register a machine by address. `host` may also be "ip:port". Returns the saved entry. Raises ValueError."""
    host, port = network.split_host_port(f"{host}:{port}" if port and ":" not in str(host) else host, port)
    if network.is_unspecified(host):
        raise ValueError("0.0.0.0 is not a machine you can connect to; use its real address")
    entry = {"host": host, "port": port, "label": str(label or "")}
    current = [h for h in hosts() if (h["host"], h["port"]) != (host, port)]
    state.write_json(_hosts_path(), {"hosts": current + [entry]}, private=False)
    return entry


def remove_host(host, port=None):
    """Forget a registered machine. Returns True if it was there."""
    host, port = network.split_host_port(f"{host}:{port}" if port and ":" not in str(host) else host, port)
    current = hosts()
    kept = [h for h in current if (h["host"], h["port"]) != (host, port)]
    if len(kept) == len(current):
        return False
    state.write_json(_hosts_path(), {"hosts": kept}, private=False)
    return True


# ------------------------------------------------------------------------------------------------ discovery
def _candidates(mdns_on, manual_on, timeout, log):
    found = {}
    if mdns_on:
        try:
            for m in mdns.browse(timeout):
                for ip in m["ips"][:1]:
                    found.setdefault((ip, m["port"]), {"name": m["name"], "role": m["role"], "host": ip,
                                                        "port": m["port"], "source": "mdns"})
        except OSError as e:
            log(f"[mesh] mDNS is not available here ({e}); showing manually registered machines only")
    if manual_on:
        for h in hosts():
            key = (h["host"], h["port"])
            if key in found:
                found[key]["source"] = "mdns+manual"
            else:
                found[key] = {"name": h["label"], "role": "", "host": h["host"], "port": h["port"], "source": "manual"}
    return list(found.values())


def _probe(entry, timeout):
    res = network.check(f"http://{network.format_host(entry['host'])}:{entry['port']}", timeout=timeout)
    entry.update(url=res["url"], reachable=res["ok"], latency_ms=res["latency_ms"], error=res["error"],
                 hint=res["hint"])
    if res["name"]:
        entry["name"] = res["name"]
    if res["role"]:
        entry["role"] = res["role"]


def discover(timeout=3.0, *, mdns=True, manual=True, probe=True, show=True, log=print):
    """Find Patchcord machines. Returns a list of dicts and (show=True) prints a table.

        {name, role, host, port, url, source, reachable, latency_ms, local, error, hint}

    source     "mdns", "manual" or "mdns+manual"
    reachable  this machine could open the node's /_mesh/health (only checked when probe=True)
    local      the node runs on this very machine
    """
    out = _candidates(mdns, manual, timeout, log)
    mine = network.local_addresses()
    for e in out:
        e.update(url=f"http://{network.format_host(e['host'])}:{e['port']}", reachable=None, latency_ms=None,
                 local=e["host"] in mine, error="", hint="")
    if probe and out:
        threads = [threading.Thread(target=_probe, args=(e, 2.5), daemon=True) for e in out]
        for t in threads:
            t.start()
        for t in threads:
            t.join(6)
    out.sort(key=lambda e: (not e.get("reachable"), e["name"].lower(), e["host"]))
    if show:
        print(format_table(out))
    return out


def format_table(machines):
    if not machines:
        return ("No Patchcord machines found.\n"
                "  - Start a node in LAN mode: Controller(tunnel=\"local\", host=\"0.0.0.0\")\n"
                "  - If your network blocks multicast, register one by hand:\n"
                "      patchcord.discovery.add_host(\"192.168.1.20\", 8080)")
    rows = [("NAME", "ROLE", "ADDRESS", "STATUS", "SOURCE")]
    for m in machines:
        state_ = {True: f"reachable ({m['latency_ms']} ms)", False: "UNREACHABLE", None: "not checked"}[m["reachable"]]
        rows.append((m["name"] or "?", m["role"] or "?", f"{m['host']}:{m['port']}" + (" (this machine)" if m["local"] else ""),
                     state_, m["source"]))
    widths = [max(len(r[i]) for r in rows) for i in range(5)]
    lines = ["  ".join(c.ljust(w) for c, w in zip(r, widths)).rstrip() for r in rows]
    for m in machines:
        if m["reachable"] is False and m["hint"]:
            lines.append(f"\n{m['host']}:{m['port']}: {m['error']}\n  {m['hint']}")
    return "\n".join(lines)
