"""The small server every node runs. Standard library only.

    agent = Agent("worker1", key=auth.new_key(), logs={"engine": "/content/engine.log"})

    @agent.rpc("add")                       # POST /_mesh/rpc/add  -> Peer.call("add", a=1, b=2)
    def add(a, b): return a + b

    @agent.route("GET", "/hello/<who>")     # your own endpoints; auth=True (default) needs the node key
    def hello(req): return {"hi": req.params["who"]}

    agent.start()                           # background thread; agent.port is the real port

Built in: GET /_mesh/health (open, tiny), GET /_mesh/stats, GET /_mesh/log?name=..&lines=.., GET /_mesh/whoami and
POST /_mesh/reach (connect-back test, only to the caller's own address); all but health need the key.
Handlers return a dict/list (JSON, 200), (status, obj), or raise ApiError(status, message, **extra).
"""
import json
import os
import re
import shutil
import socket
import subprocess
import threading
import time
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qsl, urlsplit

from . import auth

PROTOCOL = "mesh1"
MAX_JSON = 4 << 20


class ApiError(Exception):
    def __init__(self, status, message, **extra):
        super().__init__(message)
        self.status, self.message, self.extra = status, message, extra


class Request:
    def __init__(self, handler, method, path, query, params):
        self.method, self.path, self.query, self.params = method, path, query, params
        self.headers = handler.headers
        self._h = handler
        self.length = int(handler.headers.get("Content-Length") or 0)
        self.consumed = 0

    def read(self, n=-1):
        """Read up to n bytes of the body (all that is left if n < 0)."""
        left = self.length - self.consumed
        n = left if n is None or n < 0 else min(n, left)
        data = self._h.rfile.read(n) if n else b""
        self.consumed += len(data)
        return data

    def body(self, limit=MAX_JSON):
        if self.length > limit:
            raise ApiError(413, "body too large")
        return self.read()

    def json(self):
        raw = self.body()
        try:
            return json.loads(raw.decode("utf-8")) if raw else {}
        except ValueError:
            raise ApiError(400, "body is not valid JSON") from None

    def int(self, name, default=None):
        try:
            return int(self.query[name])
        except (KeyError, ValueError):
            if default is None:
                raise ApiError(400, f"missing or bad number: {name}") from None
            return default


def tail_file(path, lines=200, max_bytes=256 * 1024):
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - max_bytes))
            data = f.read().decode("utf-8", "replace")
    except OSError:
        return []
    return data.splitlines()[-max(1, min(lines, 2000)):]


def _meminfo():
    """Linux fallback when psutil is missing: (total, available) bytes, or None."""
    try:
        vals = {}
        with open("/proc/meminfo") as f:
            for line in f:
                k, _, v = line.partition(":")
                vals[k] = int(v.split()[0]) * 1024
        return vals["MemTotal"], vals.get("MemAvailable", vals.get("MemFree", 0))
    except (OSError, ValueError, KeyError, IndexError):
        return None


def collect_stats(path="."):
    """CPU, RAM, disk and GPU numbers. `gpus` is always present (an empty list when there is none)."""
    out = {"time": time.time(), "cpu_count": os.cpu_count(), "gpus": []}
    try:
        import psutil
        out["cpu_percent"] = psutil.cpu_percent(interval=0.2)
        vm = psutil.virtual_memory()
        out["ram"] = {"total": vm.total, "used": vm.used, "available": vm.available}
    except ImportError:
        if hasattr(os, "getloadavg"):
            out["load1"] = os.getloadavg()[0]
        mem = _meminfo()
        if mem:
            out["ram"] = {"total": mem[0], "used": mem[0] - mem[1], "available": mem[1]}
    try:
        du = shutil.disk_usage(path)
        out["disk"] = {"total": du.total, "free": du.free}
    except OSError:
        pass
    if shutil.which("nvidia-smi"):
        try:
            r = subprocess.run(["nvidia-smi", "--query-gpu=name,utilization.gpu,memory.used,memory.total,temperature.gpu",
                                "--format=csv,noheader,nounits"], capture_output=True, text=True, timeout=4)
            gpus = []
            for line in r.stdout.strip().splitlines():
                n, util, used, total, temp = [x.strip() for x in line.split(",")]
                gpus.append({"name": n, "util": float(util), "mem_used_mib": float(used),
                             "mem_total_mib": float(total), "mem_free_mib": float(total) - float(used),
                             "temp_c": float(temp)})
            out["gpus"] = gpus
        except (OSError, ValueError, subprocess.SubprocessError):
            pass
    return out


class Agent:
    def __init__(self, name, key, host="127.0.0.1", port=0, logs=None, log=print, stats_path=".", role="node"):
        self.name, self.key, self.host, self.port, self.role = name, key, host, port, role
        self.logs, self.log, self.stats_path = dict(logs or {}), log, stats_path
        self.stats_extra = {}                      # name -> fn() merged into /_mesh/stats
        self._routes, self._server, self._thread = [], None, None
        self._active, self._idle = 0, threading.Condition()      # requests in progress, so stop() can let them finish
        self.route("GET", "/_mesh/health", auth=False)(self._health)
        self.route("GET", "/_mesh/stats")(self._stats)
        self.route("GET", "/_mesh/log")(self._log)
        self.route("GET", "/_mesh/whoami")(self._whoami)
        self.route("POST", "/_mesh/reach")(self._reach)
        self.route("POST", "/_mesh/rpc/<fn>")(self._rpc)
        self._rpcs = {}

    # ------------------------------------------------------------------ registering things
    def route(self, method, pattern, auth=True):
        """Decorator. `auth`: True = node key required, False = open, or a function(req) -> bool."""
        rx = re.compile(re.sub(r"<(\w+)>", r"(?P<\1>[^/]+)", pattern))

        def deco(fn):
            self._routes.append((method.upper(), rx, auth, fn))
            return fn
        return deco

    def rpc(self, name):
        def deco(fn):
            self._rpcs[name] = fn
            return fn
        return deco

    # ------------------------------------------------------------------ built-in endpoints
    def _health(self, req):
        return {"ok": True, "name": self.name, "protocol": PROTOCOL, "role": self.role}

    def _whoami(self, req):
        return {"name": self.name, "role": self.role}

    def _reach(self, req):
        """Connect-back test: can this node open a connection to the machine that is asking, on `port`? Only the
        caller's own address is ever tried, so an authenticated peer cannot use this to probe other machines."""
        port = req.json().get("port")
        if not isinstance(port, int) or not 1 <= port <= 65535:
            raise ApiError(400, "port must be a number from 1 to 65535")
        addr = req._h.client_address[0]
        t0 = time.monotonic()
        try:
            socket.create_connection((addr, port), timeout=3).close()
            return {"ok": True, "address": f"{addr}:{port}", "latency_ms": round((time.monotonic() - t0) * 1000)}
        except OSError as e:
            return {"ok": False, "address": f"{addr}:{port}", "error": str(e)}

    def _stats(self, req):
        out = collect_stats(self.stats_path)
        for k, fn in self.stats_extra.items():
            try:
                out[k] = fn()
            except Exception as e:  # noqa: BLE001
                out[k] = {"error": str(e)}
        return out

    def _log(self, req):
        name = req.query.get("name", "")
        if name not in self.logs:
            raise ApiError(404, f"no such log: {name}", available=sorted(self.logs))
        return {"name": name, "lines": tail_file(self.logs[name], req.int("lines", 200))}

    def _rpc(self, req):
        fn = self._rpcs.get(req.params["fn"])
        if not fn:
            raise ApiError(404, "no such function")
        args = req.json()
        if not isinstance(args, dict):
            raise ApiError(400, "arguments must be a JSON object")
        try:
            return {"result": fn(**args)}
        except TypeError as e:
            raise ApiError(400, f"bad arguments: {e}") from None

    # ------------------------------------------------------------------ server
    def _authorized(self, req, rule):
        if rule is True:
            return auth.check(self.key, req.headers.get(auth.KEY_HEADER))
        return bool(rule(req))

    def _handler_class(agent):  # noqa: N805
        class Handler(BaseHTTPRequestHandler):
            server_version = "patchcord"

            def log_message(self, *a):
                pass

            def _send(self, status, payload):
                body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/octet-stream" if isinstance(payload, bytes)
                                 else "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")      # one request per connection: no half-read bodies
                self.end_headers()
                self.wfile.write(body)

            def _serve(self, method):
                with agent._idle:
                    agent._active += 1
                try:
                    self._dispatch(method)
                finally:
                    with agent._idle:
                        agent._active -= 1
                        agent._idle.notify_all()

            def _dispatch(self, method):
                u = urlsplit(self.path)
                query = dict(parse_qsl(u.query))
                for m, rx, rule, fn in agent._routes:
                    mt = rx.fullmatch(u.path) if m == method else None
                    if not mt:
                        continue
                    req = Request(self, method, u.path, query, mt.groupdict())
                    try:
                        if rule is not False and not agent._authorized(req, rule):
                            raise ApiError(401, "missing or wrong key")
                        out = fn(req)
                        status, payload = out if isinstance(out, tuple) else (200, out)
                    except ApiError as e:
                        status, payload = e.status, {"error": e.message, **e.extra}
                    except Exception as e:  # noqa: BLE001
                        agent.log(f"[mesh] {method} {u.path} failed: {e}\n{traceback.format_exc()}")
                        status, payload = 500, {"error": "internal error"}
                    return self._send(status, payload)
                self._send(404, {"error": "not found"})

            def do_GET(self):
                self._serve("GET")

            def do_POST(self):
                self._serve("POST")

            def do_PUT(self):
                self._serve("PUT")

            def do_DELETE(self):
                self._serve("DELETE")
        return Handler

    @property
    def running(self):
        return self._server is not None

    def start(self):
        """Listen and serve in a background thread. Calling it on a running agent changes nothing."""
        if self._server is not None:
            return self
        server = ThreadingHTTPServer((self.host, self.port), self._handler_class())
        server.daemon_threads = True
        self._server = server
        self.port = server.server_address[1]
        self._thread = threading.Thread(target=server.serve_forever, daemon=True, name="mesh-agent")
        self._thread.start()
        return self

    def stop(self, grace=0.0):
        """Stop accepting connections, give requests already in progress up to `grace` seconds to finish, then close.
        Safe to call at any time, any number of times."""
        server, thread = self._server, self._thread
        if server is None:
            return
        self._server = self._thread = None
        server.shutdown()
        if grace and grace > 0:
            deadline = time.monotonic() + grace
            with self._idle:
                while self._active and time.monotonic() < deadline:
                    self._idle.wait(deadline - time.monotonic())
        server.server_close()
        if thread:
            thread.join(2)
