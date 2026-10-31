"""Client for talking to another node. Standard library only."""
import json
import urllib.error
import urllib.request
from urllib.parse import urlencode

from .auth import KEY_HEADER

# Cloudflare often rejects urllib's default user agent, so always send our own.
USER_AGENT = "patchcord/0.1"


class PeerError(Exception):
    """status 0 = could not connect / timed out; otherwise the HTTP status. `body` is the JSON error body if any."""

    def __init__(self, message, status=0, body=None):
        super().__init__(message)
        self.status, self.body = status, body or {}


def _parse(raw):
    try:
        out = json.loads(raw.decode("utf-8")) if raw else {}
        return out
    except ValueError:
        return {}


class Peer:
    """Send authenticated HTTP requests and RPC calls to another Patchcord node."""
    def __init__(self, url, key="", name="", caps=(), urls=None):
        self.url, self.key, self.name = url.rstrip("/"), key, name
        self.caps, self.urls = list(caps), dict(urls or {})

    def request(self, method, path, params=None, json_body=None, data=None, headers=None, timeout=30):
        url = self.url + path + ("?" + urlencode(params) if params else "")
        h = {"User-Agent": USER_AGENT, **(headers or {})}
        if self.key:
            h.setdefault(KEY_HEADER, self.key)
        body = data
        if json_body is not None:
            body, h["Content-Type"] = json.dumps(json_body).encode(), "application/json"
        req = urllib.request.Request(url, data=body, headers=h, method=method)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return _parse(r.read())
        except urllib.error.HTTPError as e:
            parsed = _parse(e.read())
            raise PeerError(parsed.get("error") or f"HTTP {e.code}", e.code, parsed) from None
        except (urllib.error.URLError, OSError) as e:
            raise PeerError(str(e)) from None

    def get(self, path, timeout=30, **params):
        return self.request("GET", path, params=params or None, timeout=timeout)

    def post(self, path, json_body=None, timeout=30, **params):
        return self.request("POST", path, params=params or None, json_body=json_body if json_body is not None else {},
                            timeout=timeout)

    def health(self, timeout=5):
        try:
            return bool(self.get("/_mesh/health", timeout=timeout).get("ok"))
        except PeerError:
            return False

    def stats(self, timeout=10):
        return self.get("/_mesh/stats", timeout=timeout)

    def log(self, name, lines=200, timeout=10):
        return self.get("/_mesh/log", timeout=timeout, name=name, lines=lines)

    def call(self, rpc_name, timeout=60, **args):
        """Run a function the node registered with @agent.rpc(name)."""
        return self.post(f"/_mesh/rpc/{rpc_name}", json_body=args, timeout=timeout).get("result")
