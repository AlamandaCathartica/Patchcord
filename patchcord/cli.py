"""The `patchcord` command (also `python -m patchcord`).

    patchcord version
    patchcord doctor [--target JOIN_CODE_OR_URL]       why can't my worker connect?
    patchcord discover                                  find Patchcord machines on this network
    patchcord hosts add 192.168.1.20:8080               register a machine by hand (multicast blocked?)
    patchcord check 192.168.1.20:8080                   can this machine talk to that one?
    patchcord status                                    nodes started from this account on this machine
    patchcord workers                                   workers known to the running (or a saved) controller
    patchcord controller start --lan                    run a controller; prints the join code
    patchcord worker start gpu-01 --lan --join MJ1-...  run a worker

`controller start` and `worker start` run in the foreground until Ctrl-C (or SIGTERM), then shut down cleanly.
"""
import argparse
import json
import os
import signal
import sys
import threading
import time

from . import __version__, discovery, network, state
from .peer import Peer, PeerError

JOIN_ENV = "PATCHCORD_JOIN"


# ------------------------------------------------------------------------------------------------ helpers
def _emit_json(obj):
    print(network.to_json(obj))


def _table(rows):
    widths = [max(len(str(r[i])) for r in rows) for i in range(len(rows[0]))]
    return "\n".join("  ".join(str(c).ljust(w) for c, w in zip(r, widths)).rstrip() for r in rows)


def _duration(seconds):
    seconds = int(seconds or 0)
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    return f"{h}h{m:02d}m" if h else (f"{m}m{s:02d}s" if m else f"{s}s")


def _pairs(values, what, number=False):
    out = {}
    for v in values or []:
        if "=" not in v:
            raise SystemExit(f"patchcord: {what} must look like NAME=VALUE, got {v!r}")
        k, val = v.split("=", 1)
        if number:
            try:
                val = int(val)
            except ValueError:
                raise SystemExit(f"patchcord: {what} {k!r} needs a port number, got {val!r}") from None
        out[k] = val
    return out


def _pid_alive(pid):
    """True/False on Linux and macOS, None where it cannot be told safely (os.kill(pid, 0) is not harmless on Windows)."""
    if os.name == "nt" or not isinstance(pid, int):
        return None
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return None


def _run_dir():
    return state.path("run")


def _write_record(role, name, info):
    file = os.path.join(_run_dir(), f"{role}-{name}.json".replace(os.sep, "_"))
    state.write_json(file, {"role": role, "name": name, "pid": os.getpid(), "started": time.time(), **info})
    return file


def _records():
    out = []
    folder = _run_dir()
    for fn in sorted(os.listdir(folder)) if os.path.isdir(folder) else []:
        if not fn.endswith(".json"):
            continue
        file = os.path.join(folder, fn)
        rec = state.read_json(file)
        if not isinstance(rec, dict) or "port" not in rec:
            continue
        rec["_file"] = file
        alive = _pid_alive(rec.get("pid"))
        if alive is False:                                  # the process is gone: tidy up its record
            try:
                os.remove(file)
            except OSError:
                pass
            continue
        host = "127.0.0.1" if network.is_unspecified(rec.get("host")) else rec.get("host", "127.0.0.1")
        rec["local_url"] = f"http://{network.format_host(host)}:{rec['port']}"
        rec["healthy"] = Peer(rec["local_url"]).health(2)
        out.append(rec)
    return out


# ------------------------------------------------------------------------------------------------ simple commands
def cmd_version(args):
    print(f"Patchcord {__version__}")
    return 0


def cmd_doctor(args):
    from .doctor import doctor
    rep = doctor(args.port, target=args.target, registry_path=args.registry, internet=not args.no_internet,
                 show=not args.json)
    if args.json:
        _emit_json(rep.to_dict())
    return 0 if rep.ok else 1


def cmd_discover(args):
    found = discovery.discover(args.timeout, mdns=not args.no_mdns, show=not args.json)
    if args.json:
        _emit_json(found)
    return 0


def cmd_hosts(args):
    try:
        if args.action == "add":
            e = discovery.add_host(args.address, label=args.label)
            print(f"Registered {e['host']}:{e['port']}" + (f" ({e['label']})" if e["label"] else ""))
        elif args.action == "remove":
            ok = discovery.remove_host(args.address)
            print("Removed." if ok else "That address was not registered.")
            return 0 if ok else 1
        else:
            hs = discovery.hosts()
            if args.json:
                _emit_json(hs)
            elif hs:
                print(_table([("ADDRESS", "LABEL")] + [(f"{h['host']}:{h['port']}", h["label"]) for h in hs]))
            else:
                print("No machines registered. Add one: patchcord hosts add 192.168.1.20:8080")
    except ValueError as e:
        print(f"patchcord: {e}", file=sys.stderr)
        return 2
    return 0


def cmd_check(args):
    res = network.check(args.target)
    if args.json:
        _emit_json(res)
    else:
        print(network.describe(res))
    return 0 if res["ok"] else 1


def cmd_status(args):
    recs = _records()
    if args.json:
        _emit_json([{k: v for k, v in r.items() if k not in ("key", "_file")} for r in recs])
        return 0
    if not recs:
        print("No Patchcord nodes started with the `patchcord` command are running on this machine.")
        return 0
    rows = [("ROLE", "NAME", "STATE", "UPTIME", "PID", "ADDRESS")]
    for r in recs:
        rows.append((r["role"], r["name"], "running" if r["healthy"] else "not answering",
                     _duration(time.time() - r.get("started", time.time())), r.get("pid", "?"), r.get("url", "")))
    print(_table(rows))
    return 0


def cmd_workers(args):
    peers, source = None, ""
    try:
        if args.url:
            peers = Peer(args.url, args.key or os.environ.get("PATCHCORD_KEY", "")).get("/_mesh/peers", timeout=8)["peers"]
            source = args.url
        else:
            ctl = next((r for r in _records() if r["role"] == "controller" and r["healthy"] and r.get("key")), None)
            if ctl and not args.registry:
                peers = Peer(ctl["local_url"], ctl["key"]).get("/_mesh/peers", timeout=8)["peers"]
                source = f"controller '{ctl['name']}'"
            elif args.registry:
                data = state.read_json(args.registry, None)
                if not isinstance(data, dict):
                    print(f"patchcord: cannot read {args.registry}", file=sys.stderr)
                    return 2
                peers = [{k: v for k, v in p.items() if k != "key"} | {"online": None} for p in data.get("peers", [])]
                source = f"{args.registry} (saved list; run a controller for live status)"
    except (PeerError, KeyError) as e:
        print(f"patchcord: could not read the worker list: {e}", file=sys.stderr)
        return 1
    if peers is None:
        print("No controller found. Start one (`patchcord controller start`), or use --registry FILE or --url URL --key KEY.")
        return 1
    if args.json:
        _emit_json(peers)
        return 0
    print(f"Workers from {source}")
    if not peers:
        print("  none yet")
        return 0
    rows = [("NAME", "ONLINE", "GPUS", "FREE VRAM", "ADDRESS", "CAPABILITIES")]
    for p in peers:
        gpus = (p.get("stats") or {}).get("gpus") or []
        online = {True: "yes", False: "no", None: "?"}[p.get("online")] + ("" if p.get("enabled", True) else " (disabled)")
        rows.append((p["name"], online, len(gpus) if p.get("stats") else "?",
                     f"{int(max((g.get('mem_free_mib', 0) for g in gpus), default=0))} MiB" if gpus else "-",
                     p.get("url", ""), ",".join(p.get("caps", []))))
    print(_table(rows))
    return 0


# ------------------------------------------------------------------------------------------------ running nodes
def _wait_until_signal(is_failed):
    """Block until Ctrl-C / SIGTERM (returns 0) or until is_failed() turns true (returns 1)."""
    done = threading.Event()
    for sig in (signal.SIGINT, getattr(signal, "SIGTERM", None)):
        if sig is not None:
            try:
                signal.signal(sig, lambda *_: done.set())
            except ValueError:                              # not the main thread (tests)
                pass
    while not done.wait(0.5):
        if is_failed():
            return 1
    return 0


def _common_node_args(p):
    p.add_argument("--lan", action="store_true", help="LAN mode: --tunnel local --host 0.0.0.0 (address detected)")
    p.add_argument("--tunnel", choices=["cloudflared", "local"], default=None, help="default: cloudflared")
    p.add_argument("--host", default=None, help="address to listen on (default 127.0.0.1; --lan uses 0.0.0.0)")
    p.add_argument("--advertise-host", default=None, help="address other machines should use (default: detected)")
    p.add_argument("--port", type=int, default=0, help="port to listen on (default: any free port)")
    p.add_argument("--no-mdns", action="store_true", help="do not announce this node on the LAN")
    p.add_argument("--ext", default=None, help="only sync these file types, e.g. .safetensors,.ckpt")


def _net_settings(args):
    tunnel = args.tunnel or ("local" if args.lan else "cloudflared")
    host = args.host or ("0.0.0.0" if args.lan else "127.0.0.1")
    return dict(tunnel=tunnel, host=host, advertise_host=args.advertise_host, port=args.port,
                mdns=False if args.no_mdns else None, allow_insecure=(tunnel == "local"))


def _policy(args):
    from .transfer import Policy
    return Policy(extensions=tuple(e if e.startswith(".") else "." + e for e in args.ext.split(",")) if args.ext else None)


def _read_join(args):
    value = args.join or os.environ.get(JOIN_ENV, "")
    if value == "-":
        value = sys.stdin.readline().strip()
    return value or None


def cmd_controller_start(args):
    from .node import Controller
    try:
        kw = _net_settings(args)
        ctl = Controller(name=args.name, registry_path=args.registry, probe_interval=args.probe_interval, **kw)
    except ValueError as e:
        print(f"patchcord: {e}", file=sys.stderr)
        return 2
    try:
        join = ctl.start(timeout=args.timeout)
    except (OSError, RuntimeError, TimeoutError, ValueError) as e:
        print(f"patchcord: the controller could not start: {e}", file=sys.stderr)
        return 1
    for item in args.sync or []:
        chan, _, folder = item.partition("=")
        if not folder or not os.path.isdir(folder):
            print(f"patchcord: --sync {item!r}: expected CHANNEL=EXISTING_FOLDER", file=sys.stderr)
            ctl.stop()
            return 2
        ctl.syncer(folder, chan, _policy(args))
    record = _write_record("controller", args.name, {"url": ctl.url, "port": ctl.agent.port, "host": ctl.agent.host,
                                                     "key": ctl.agent.key})
    ctl.on("worker.connected", lambda e: print(f"worker connected:    {e.worker}", flush=True))
    ctl.on("worker.disconnected", lambda e: print(f"worker disconnected: {e.worker}", flush=True))
    ctl.on("transfer.completed", lambda e: print(f"sent {e.path} -> {e.worker}", flush=True))
    print(f"\nController '{args.name}' is running at {ctl.url}\n\nJoin code (keep it private):\n  {join}\n\n"
          f"On each worker:\n  patchcord worker start NAME{' --lan' if kw['tunnel'] == 'local' else ''} --join {join}\n\n"
          "Press Ctrl-C to stop.", flush=True)
    try:
        return _wait_until_signal(lambda: False)
    finally:
        print("\nStopping...", flush=True)
        ctl.stop()
        try:
            os.remove(record)
        except OSError:
            pass


def cmd_worker_start(args):
    from .node import Worker
    try:
        kw = _net_settings(args)
        w = Worker(args.name, join=_read_join(args), sync={c: d for c, d in _pairs(args.sync, "--sync").items()},
                   expose=_pairs(args.expose, "--expose", number=True), policy=_policy(args),
                   max_reconnect_attempts=args.max_reconnects, **kw)
    except ValueError as e:
        print(f"patchcord: {e}", file=sys.stderr)
        return 2
    w.on("worker.registered", lambda e: print("registered with the controller", flush=True))
    w.on("worker.disconnected", lambda e: print(f"disconnected: {e.reason}", flush=True))
    w.on("worker.connected", lambda e: print("connected", flush=True))
    w.on("worker.reconnecting", lambda e: print("reconnecting...", flush=True))
    w.on("transfer.completed", lambda e: print(f"received {e.path}", flush=True))
    try:
        code = w.start(timeout=args.timeout)
    except (OSError, RuntimeError, TimeoutError, ValueError) as e:
        print(f"patchcord: the worker could not start: {e}", file=sys.stderr)
        return 1
    record = _write_record("worker", args.name, {"url": w.url, "port": w.agent.port, "host": w.agent.host})
    print(f"\nWorker '{args.name}' is running at {w.url}")
    if not w.join:
        print(f"\nPairing code (keep it private; give it to the controller):\n  {code}")
    print("\nPress Ctrl-C to stop.", flush=True)
    try:
        return _wait_until_signal(lambda: w.status == "failed")
    finally:
        print("\nStopping...", flush=True)
        w.stop()
        try:
            os.remove(record)
        except OSError:
            pass


# ------------------------------------------------------------------------------------------------ parser
def build_parser():
    p = argparse.ArgumentParser(prog="patchcord", description="Connect machines into one cluster.")
    p.add_argument("--version", action="version", version=f"Patchcord {__version__}")
    sub = p.add_subparsers(dest="command", metavar="COMMAND")

    sub.add_parser("version", help="print the version").set_defaults(fn=cmd_version)

    d = sub.add_parser("doctor", help="check this machine and find connection problems")
    d.add_argument("--port", type=int, default=8080, help="port you plan to use (default 8080)")
    d.add_argument("--target", help="a controller/worker to test: join code, pairing code, URL or host:port")
    d.add_argument("--registry", help="a saved worker list, to check its file permissions")
    d.add_argument("--no-internet", action="store_true", help="skip the internet check")
    d.add_argument("--json", action="store_true")
    d.set_defaults(fn=cmd_doctor)

    d = sub.add_parser("discover", help="find Patchcord machines on the network")
    d.add_argument("--timeout", type=float, default=3.0)
    d.add_argument("--no-mdns", action="store_true", help="only check machines registered with `hosts add`")
    d.add_argument("--json", action="store_true")
    d.set_defaults(fn=cmd_discover)

    h = sub.add_parser("hosts", help="machines registered by hand")
    h.add_argument("action", choices=["list", "add", "remove"], nargs="?", default="list")
    h.add_argument("address", nargs="?", help="host:port")
    h.add_argument("--label", default="")
    h.add_argument("--json", action="store_true")
    h.set_defaults(fn=cmd_hosts)

    c = sub.add_parser("check", help="test the connection to a machine")
    c.add_argument("target", help="URL or host:port")
    c.add_argument("--json", action="store_true")
    c.set_defaults(fn=cmd_check)

    s = sub.add_parser("status", help="nodes started with this command on this machine")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_status)

    w = sub.add_parser("workers", help="list the workers a controller knows")
    w.add_argument("--url", help="a controller URL (needs --key)")
    w.add_argument("--key", help="that controller's node key (or set PATCHCORD_KEY)")
    w.add_argument("--registry", help="read a saved worker list file instead of asking a running controller")
    w.add_argument("--json", action="store_true")
    w.set_defaults(fn=cmd_workers)

    cs = sub.add_parser("controller", help="run a controller").add_subparsers(dest="sub", metavar="start")
    st = cs.add_parser("start", help="start a controller and print the join code")
    st.add_argument("--name", default="controller")
    st.add_argument("--registry", help="file that remembers the workers between runs")
    st.add_argument("--probe-interval", type=float, default=10.0)
    st.add_argument("--sync", action="append", metavar="CHANNEL=FOLDER", help="keep FOLDER mirrored to workers")
    st.add_argument("--timeout", type=float, default=120.0, help="seconds to wait for the tunnel")
    _common_node_args(st)
    st.set_defaults(fn=cmd_controller_start)

    ws = sub.add_parser("worker", help="run a worker").add_subparsers(dest="sub", metavar="start")
    st = ws.add_parser("start", help="start a worker")
    st.add_argument("name")
    st.add_argument("--join", help=f"controller join code ('-' reads it from stdin; or set {JOIN_ENV}; "
                                   "an argument is visible in `ps`)")
    st.add_argument("--sync", action="append", metavar="CHANNEL=FOLDER", help="receive channel files into FOLDER")
    st.add_argument("--expose", action="append", metavar="NAME=PORT", help="also tunnel a local app on PORT")
    st.add_argument("--max-reconnects", type=int, default=None, help="give up after this many failed reconnects")
    st.add_argument("--timeout", type=float, default=120.0, help="seconds to wait for the tunnel")
    _common_node_args(st)
    st.set_defaults(fn=cmd_worker_start)
    return p


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "fn", None):
        parser.print_help()
        return 0
    if args.command == "hosts" and args.action in ("add", "remove") and not args.address:
        parser.error(f"hosts {args.action} needs an address, e.g. 192.168.1.20:8080")
    try:
        return args.fn(args) or 0
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
