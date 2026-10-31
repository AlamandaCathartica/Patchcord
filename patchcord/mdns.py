"""A small mDNS / DNS-SD implementation (RFC 6762 / 6763), standard library only.

Patchcord nodes that run in LAN mode announce themselves as `_patchcord._tcp.local.` so that other machines can
find them without anyone typing an IP address. Only what is needed is implemented: IPv4, PTR/SRV/TXT/A records,
answering queries, announcing and saying goodbye, and browsing.

The announcement carries no secrets: the node's name, role, protocol version, port and address. It never carries
a key. Finding a machine does not give you access to it; you still need its pairing code.

Everything that arrives from the network is untrusted: the decoder bounds-checks every read, follows at most a few
compression pointers, and raises ValueError (never anything else) for bad packets.
"""
import secrets
import select
import socket
import struct
import threading
import time

GROUP, PORT = "224.0.0.251", 5353
SERVICE = ("_patchcord", "_tcp", "local")
A, PTR, TXT, SRV, ANY = 1, 12, 16, 33, 255
IN, FLUSH = 1, 0x8000
MAX_RECORDS = 64


# ------------------------------------------------------------------------------------------------ names
def _label(text):
    raw = text.encode("utf-8") if isinstance(text, str) else bytes(text)
    if len(raw) > 63:
        raw = raw[:63].decode("utf-8", "ignore").encode("utf-8")      # never cut a character in half
    return raw


def encode_name(labels):
    out = b""
    for lab in labels:
        raw = _label(lab)
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def decode_name(data, pos):
    """Read a (possibly compressed) name at `pos`. Returns (tuple of lower-case labels, position after the name)."""
    labels, end, jumps = [], None, 0
    while True:
        if pos >= len(data):
            raise ValueError("name runs past the packet")
        n = data[pos]
        if n == 0:
            pos += 1
            break
        if n & 0xC0 == 0xC0:
            if pos + 1 >= len(data):
                raise ValueError("bad compression pointer")
            if end is None:
                end = pos + 2
            pos = ((n & 0x3F) << 8) | data[pos + 1]
            jumps += 1
            if jumps > 8:
                raise ValueError("too many compression pointers")
            continue
        if n & 0xC0:
            raise ValueError("bad label")
        if pos + 1 + n > len(data):
            raise ValueError("label runs past the packet")
        labels.append(data[pos + 1:pos + 1 + n].decode("utf-8", "replace"))
        if len(labels) > 32:
            raise ValueError("name too long")
        pos += 1 + n
    return tuple(labels), (end if end is not None else pos)


def same_name(a, b):
    return tuple(x.lower() for x in a) == tuple(x.lower() for x in b)


# ------------------------------------------------------------------------------------------------ packets
def encode_txt(items):
    out = b""
    for k, v in items.items():
        piece = f"{k}={v}".encode("utf-8")[:255]
        out += bytes([len(piece)]) + piece
    return out or b"\x00"


def decode_txt(raw):
    out, pos = {}, 0
    while pos < len(raw):
        n = raw[pos]
        piece = raw[pos + 1:pos + 1 + n]
        pos += 1 + n
        if b"=" in piece:
            k, v = piece.split(b"=", 1)
            out[k.decode("utf-8", "replace").lower()] = v.decode("utf-8", "replace")
    return out


def _record(labels, rtype, rdata, ttl, flush=True):
    return (encode_name(labels) + struct.pack(">HHIH", rtype, IN | (FLUSH if flush else 0), ttl, len(rdata)) + rdata)


def ptr_record(service, instance, ttl):
    return _record(service, PTR, encode_name(instance), ttl, flush=False)


def srv_record(instance, port, target, ttl):
    return _record(instance, SRV, struct.pack(">HHH", 0, 0, port) + encode_name(target), ttl)


def txt_record(instance, items, ttl):
    return _record(instance, TXT, encode_txt(items), ttl)


def a_record(host, ip, ttl):
    return _record(host, A, socket.inet_aton(ip), ttl)


def build_query(questions, qid=0):
    """questions: [(labels, qtype)]"""
    body = b"".join(encode_name(n) + struct.pack(">HH", t, IN) for n, t in questions)
    return struct.pack(">HHHHHH", qid, 0, len(questions), 0, 0, 0) + body


def build_response(records, qid=0, questions=()):
    body = b"".join(encode_name(n) + struct.pack(">HH", t, IN) for n, t in questions)
    return struct.pack(">HHHHHH", qid, 0x8400, len(questions), len(records), 0, 0) + body + b"".join(records)


def parse(data):
    """Decode a packet -> {id, response, questions: [(labels, type)], records: [(labels, type, ttl, value)]}.
    value: PTR -> labels, SRV -> (port, target labels), TXT -> dict, A -> ip string, other -> None."""
    if len(data) < 12:
        raise ValueError("short packet")
    qid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", data[:12])
    if qd + an + ns + ar > MAX_RECORDS:
        raise ValueError("too many records")
    pos, questions, records = 12, [], []
    try:
        for _ in range(qd):
            name, pos = decode_name(data, pos)
            qtype = struct.unpack(">H", data[pos:pos + 2])[0]
            if pos + 4 > len(data):
                raise ValueError("short question")
            questions.append((name, qtype))
            pos += 4
        for _ in range(an + ns + ar):
            name, pos = decode_name(data, pos)
            if pos + 10 > len(data):
                raise ValueError("short record")
            rtype, _cls, ttl, rdlen = struct.unpack(">HHIH", data[pos:pos + 10])
            pos += 10
            if pos + rdlen > len(data):
                raise ValueError("record runs past the packet")
            raw, value = data[pos:pos + rdlen], None
            if rtype == PTR:
                value = decode_name(data, pos)[0]
            elif rtype == SRV and rdlen >= 7:
                value = (struct.unpack(">H", raw[4:6])[0], decode_name(data, pos + 6)[0])
            elif rtype == TXT:
                value = decode_txt(raw)
            elif rtype == A and rdlen == 4:
                value = socket.inet_ntoa(raw)
            records.append((name, rtype, ttl, value))
            pos += rdlen
    except struct.error:
        raise ValueError("truncated packet") from None
    return {"id": qid, "response": bool(flags & 0x8000), "questions": questions, "records": records}


# ------------------------------------------------------------------------------------------------ sockets
def _multicast_socket(ips, bind_port=PORT):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if hasattr(socket, "SO_REUSEPORT"):
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except OSError:
            pass
    s.bind(("", bind_port))
    joined = []
    for ip in ips:
        try:
            s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, socket.inet_aton(GROUP) + socket.inet_aton(ip))
            joined.append(ip)
        except OSError:
            continue
    if not joined:
        s.close()
        raise OSError("could not join the mDNS multicast group on any network interface")
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
    return s, joined


def _send_multicast(sock, ips, packet):
    sent = 0
    for ip in ips:
        try:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(ip))
            sock.sendto(packet, (GROUP, PORT))
            sent += 1
        except OSError:
            continue
    return sent


def lan_ips():
    """Addresses of the interfaces mDNS should use: up, multicast-capable, not loopback, not link-local."""
    from . import network
    return [i.ip for i in network.interfaces(include_loopback=False) if i.multicast and not i.link_local] or \
           [i.ip for i in network.interfaces(include_loopback=True)]


# ------------------------------------------------------------------------------------------------ advertising
class Advertiser:
    """Announce one node on the LAN and answer queries for it, in a background thread."""

    def __init__(self, name, port, ip, role="node", txt=None, log=print, ips=None):
        socket.inet_aton(ip)                                   # ValueError/OSError for anything but an IPv4 address
        if ip == "0.0.0.0":
            raise ValueError("refusing to announce 0.0.0.0")
        self.name, self.port, self.ip, self.role, self.log = name, int(port), ip, role, log
        self.instance = (_label(name).decode("utf-8", "ignore"),) + SERVICE
        self.host = (f"patchcord-{secrets.token_hex(3)}", "local")      # unique, so it never clashes with the OS's own name
        self.txt = {"name": name, "role": role, "protocol": "mesh1", **(txt or {})}
        self.ips, self._sock, self._thread = ips, None, None
        self._stop, self._last = threading.Event(), 0.0

    # -- pure part (tested without a network)
    def records(self, ttl=120):
        return [ptr_record(SERVICE, self.instance, ttl), srv_record(self.instance, self.port, self.host, ttl),
                txt_record(self.instance, self.txt, ttl), a_record(self.host, self.ip, ttl)]

    def answer(self, data, legacy=False):
        """Return the response packet for a query, or None if the query is not about this node."""
        try:
            q = parse(data)
        except ValueError:
            return None
        if q["response"]:
            return None
        want = False
        for name, qtype in q["questions"]:
            if same_name(name, SERVICE) and qtype in (PTR, ANY):
                want = True
            elif same_name(name, self.instance) and qtype in (SRV, TXT, ANY):
                want = True
            elif same_name(name, self.host) and qtype in (A, ANY):
                want = True
        if not want:
            return None
        ttl = 10 if legacy else 120                              # RFC 6762 6.7: legacy resolvers get short TTLs
        if legacy:
            return build_response(self.records(ttl), q["id"], q["questions"])
        return build_response(self.records(ttl))

    def goodbye(self):
        return build_response(self.records(0))

    # -- network part
    def start(self):
        ips = self.ips or lan_ips()
        self._sock, self.ips = _multicast_socket(ips)
        self._thread = threading.Thread(target=self._run, daemon=True, name="mesh-mdns")
        self._thread.start()
        return self

    def _run(self):
        sock = self._sock
        _send_multicast(sock, self.ips, build_response(self.records()))
        again = time.monotonic() + 1.0
        while not self._stop.is_set():
            if again and time.monotonic() >= again:
                _send_multicast(sock, self.ips, build_response(self.records()))
                again = None
            try:
                ready = select.select([sock], [], [], 0.25)[0]
                if not ready:
                    continue
                data, addr = sock.recvfrom(9000)
            except OSError:
                if self._stop.is_set():
                    return
                time.sleep(0.2)
                continue
            try:
                legacy = addr[1] != PORT
                reply = self.answer(data, legacy)
                if reply is None:
                    continue
                if legacy:
                    sock.sendto(reply, addr)
                elif time.monotonic() - self._last >= 1.0:       # at most one multicast answer per second
                    self._last = time.monotonic()
                    _send_multicast(sock, self.ips, reply)
            except Exception as e:  # noqa: BLE001  (a bad packet from the LAN must not kill the responder)
                self.log(f"[mesh] mdns: {e}")

    def stop(self):
        self._stop.set()
        if self._sock:
            try:
                _send_multicast(self._sock, self.ips or [], self.goodbye())
            except OSError:
                pass
        if self._thread:
            self._thread.join(2)
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
        self._sock = self._thread = None


# ------------------------------------------------------------------------------------------------ browsing
def collect(packets):
    """Turn [(packet bytes, sender ip)] into [{name, role, ip, port, txt, instance}]. Pure; tested without a network."""
    instances, srv, txts, addrs, senders = {}, {}, {}, {}, {}
    for data, sender in packets:
        try:
            msg = parse(data)
        except ValueError:
            continue
        if not msg["response"]:
            continue
        for name, rtype, ttl, value in msg["records"]:
            key = tuple(x.lower() for x in name)
            if rtype == PTR and same_name(name, SERVICE) and value:
                ikey = tuple(x.lower() for x in value)
                if ttl == 0:
                    instances.pop(ikey, None)
                else:
                    instances[ikey] = value
                    senders[ikey] = sender
            elif rtype == SRV and value:
                srv[key] = value
            elif rtype == TXT and value is not None:
                txts[key] = value
            elif rtype == A and value:
                addrs.setdefault(key, [])
                if value not in addrs[key] and value != "0.0.0.0":
                    addrs[key].append(value)
    out = []
    for ikey, labels in instances.items():
        if ikey not in srv:
            continue
        port, target = srv[ikey]
        tkey = tuple(x.lower() for x in target)
        txt = txts.get(ikey, {})
        ips = addrs.get(tkey) or [senders[ikey]]
        out.append({"instance": labels[0], "name": txt.get("name") or labels[0], "role": txt.get("role", ""),
                    "port": port, "ips": ips, "ip": ips[0], "txt": txt})
    return out


def browse(timeout=2.0, ips=None):
    """Ask the LAN for Patchcord nodes and return what answers within `timeout` seconds (see `collect`).
    Raises OSError if multicast is unusable on this machine."""
    ips = ips or lan_ips()
    query = build_query([(SERVICE, PTR)])
    ask = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)           # ephemeral port: replies come back as unicast
    ask.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
    ask.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
    listen = None
    try:
        listen, _ = _multicast_socket(ips)                            # best effort: also hear multicast answers
    except OSError:
        pass
    socks = [s for s in (ask, listen) if s]
    packets, deadline = [], time.monotonic() + timeout
    sends = [0.0, timeout * 0.3, timeout * 0.6]
    started, followed = time.monotonic(), False
    try:
        if not _send_multicast(ask, ips, query):
            raise OSError("could not send on any network interface (is multicast blocked or the network down?)")
        sends.pop(0)
        while time.monotonic() < deadline:
            now = time.monotonic() - started
            if sends and now >= sends[0]:
                sends.pop(0)
                _send_multicast(ask, ips, query)
            if not followed and now >= timeout * 0.4:                 # ask for the details of half-answered instances
                followed = True
                missing = _missing_details(packets)
                if missing:
                    _send_multicast(ask, ips, build_query(missing))
            for s in select.select(socks, [], [], 0.1)[0]:
                try:
                    data, addr = s.recvfrom(9000)
                except OSError:
                    continue
                packets.append((data, addr[0]))
                if len(packets) > 500:
                    break
    finally:
        for s in socks:
            s.close()
    return collect(packets)


def _missing_details(packets):
    have_srv, instances = set(), []
    for data, _ in packets:
        try:
            msg = parse(data)
        except ValueError:
            continue
        for name, rtype, _ttl, value in msg["records"]:
            if rtype == SRV:
                have_srv.add(tuple(x.lower() for x in name))
            elif rtype == PTR and same_name(name, SERVICE) and value:
                instances.append(value)
    return [(i, ANY) for i in instances if tuple(x.lower() for x in i) not in have_srv][:8]
