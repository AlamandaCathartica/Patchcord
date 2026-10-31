"""Shared-secret auth between machines. One key per node, sent in a header, compared in constant time."""
import hmac
import re
import secrets

KEY_HEADER = "X-Mesh-Key"
JOIN_HEADER = "X-Mesh-Join"
KEY_RE = re.compile(r"[A-Za-z0-9_\-]{16,64}")


def new_key():
    return secrets.token_urlsafe(18)


def valid_key(key):
    return bool(KEY_RE.fullmatch(key or ""))


def check(expected, given):
    """True only if `expected` is non-empty and equals `given`."""
    return bool(expected) and hmac.compare_digest(str(given or ""), str(expected))
