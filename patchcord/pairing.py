"""Pairing codes: how one machine tells another how to reach it.

worker code   "MK1-" + urlsafe-b64 JSON {name, url, key, caps, urls}
join code     "MJ1-" + urlsafe-b64 JSON {url, token}   (printed by the controller; lets workers register themselves)

`caps` is a list of capability strings, e.g. "sync:models". `urls` maps extra names to public URLs, e.g. the
tunnel of an app running next to the agent: {"comfy": "https://....trycloudflare.com"}.
"""
import base64
import json
import re
from urllib.parse import urlsplit

from .auth import valid_key

PREFIX = "MK1-"
JOIN_PREFIX = "MJ1-"
NAME_RE = re.compile(r"[\w][\w .-]{0,39}")
CAP_RE = re.compile(r"[\w:.\-]{1,60}")


def _enc(data):
    raw = json.dumps(data, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _dec(body):
    return json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))


def check_url(url, allow_insecure=False, allow_hosts=None):
    """Normalise and validate an address. https only unless allow_insecure (LAN / tests).
    allow_hosts: optional list of regexes the host must match (e.g. [r".+\\.trycloudflare\\.com"])."""
    u = urlsplit(str(url))
    if u.scheme not in (("https", "http") if allow_insecure else ("https",)) or not u.hostname or u.username:
        raise ValueError("bad address")
    if u.path not in ("", "/") or u.query or u.fragment:
        raise ValueError("address must be a bare origin")
    if allow_hosts and not any(re.fullmatch(p, u.hostname) for p in allow_hosts):
        raise ValueError("address host not allowed")
    return f"{u.scheme}://{u.netloc}"


def validate(info, allow_insecure=False, allow_hosts=None):
    """Check a worker description {name, url, key, caps?, urls?} and return it normalised. Raises ValueError."""
    try:
        name, key = str(info["name"]), str(info["key"])
        caps = [str(c) for c in info.get("caps") or []]
        urls = {str(k): check_url(v, allow_insecure, allow_hosts) for k, v in (info.get("urls") or {}).items()}
        url = check_url(info["url"], allow_insecure, allow_hosts)
    except (KeyError, TypeError, AttributeError):
        raise ValueError("incomplete pairing data") from None
    if not NAME_RE.fullmatch(name):
        raise ValueError("bad node name")
    if not valid_key(key):
        raise ValueError("bad key")
    if len(caps) > 32 or not all(CAP_RE.fullmatch(c) for c in caps):
        raise ValueError("bad capabilities")
    if len(urls) > 16 or not all(NAME_RE.fullmatch(k) for k in urls):
        raise ValueError("bad extra addresses")
    return {"name": name, "url": url, "key": key, "caps": caps, "urls": urls}


def make_code(name, url, key, caps=(), urls=None):
    data = {"name": name, "url": url, "key": key}
    if caps:
        data["caps"] = list(caps)
    if urls:
        data["urls"] = dict(urls)
    return PREFIX + _enc(data)


def parse_code(code, allow_insecure=False, allow_hosts=None):
    code = (code or "").strip()
    if not code.startswith(PREFIX):
        raise ValueError(f"not a pairing code: {code[:14]}")
    try:
        data = _dec(code[len(PREFIX):])
    except Exception as e:  # noqa: BLE001
        raise ValueError(f"damaged pairing code ({e})") from None
    return validate(data, allow_insecure, allow_hosts)


def parse_codes(text, **kw):
    """Split a pasted block (spaces, commas, new lines) into parsed codes. Placeholders like MK1-.... are skipped."""
    return [parse_code(t, **kw) for t in re.split(r"[\s,]+", text or "")
            if t.startswith(PREFIX) and "...." not in t]


def make_join_code(url, token):
    return JOIN_PREFIX + _enc({"url": url, "token": token})


def parse_join_code(code, allow_insecure=False, allow_hosts=None):
    code = (code or "").strip()
    if not code.startswith(JOIN_PREFIX):
        raise ValueError(f"not a join code: {code[:14]}")
    try:
        data = _dec(code[len(JOIN_PREFIX):])
        url, token = check_url(data["url"], allow_insecure, allow_hosts), str(data["token"])
    except Exception as e:  # noqa: BLE001
        raise ValueError(f"damaged join code ({e})") from None
    if not valid_key(token):
        raise ValueError("bad join token")
    return {"url": url, "token": token}
