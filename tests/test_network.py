"""LAN addressing, connection checks, mDNS packets, discovery, doctor, events and state files."""
import http.server
import io
import os
import random
import shutil
import tempfile
import threading
import unittest

import patchcord
from patchcord import Agent, Emitter, auth, discovery, mdns, network, state
from patchcord.doctor import doctor

quiet = lambda *_: None  # noqa: E731


class Home(unittest.TestCase):
    """Every test gets its own PATCHCORD_HOME so nothing touches the real ~/.patchcord."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        old = os.environ.get("PATCHCORD_HOME")
        os.environ["PATCHCORD_HOME"] = self.tmp
        self.addCleanup(lambda: os.environ.pop("PATCHCORD_HOME") if old is None else os.environ.update(PATCHCORD_HOME=old))
        self.cleanups = []
        self.addCleanup(lambda: [fn() for fn in self.cleanups])

    def agent(self, role="worker", host="127.0.0.1"):
        a = Agent("n1", auth.new_key(), host=host, role=role).start()
        self.cleanups.append(a.stop)
        return a


class AddressTests(unittest.TestCase):
    def test_classification(self):
        for h in ("0.0.0.0", "::", "", None):
            self.assertTrue(network.is_unspecified(h), h)
        for h in ("127.0.0.1", "127.1.2.3", "::1", "localhost"):
            self.assertTrue(network.is_loopback(h), h)
        self.assertFalse(network.is_loopback("192.168.1.10"))
        self.assertTrue(network.is_link_local("169.254.3.4"))
        self.assertEqual(network.format_host("::1"), "[::1]")
        self.assertEqual(network.format_host("10.0.0.1"), "10.0.0.1")

    def test_split_host_port(self):
        s = network.split_host_port
        self.assertEqual(s("192.168.1.20:8080"), ("192.168.1.20", 8080))
        self.assertEqual(s("192.168.1.20", 9000), ("192.168.1.20", 9000))
        self.assertEqual(s("box.local:80"), ("box.local", 80))
        self.assertEqual(s("[::1]:8080"), ("::1", 8080))
        self.assertEqual(s("http://10.0.0.5:7000"), ("10.0.0.5", 7000))
        self.assertEqual(s("https://x.trycloudflare.com"), ("x.trycloudflare.com", 443))
        self.assertEqual(s("10.0.0.5:7000", 1234), ("10.0.0.5", 7000))          # the port in the text wins
        for bad in ("", "10.0.0.5", "10.0.0.5:0", "10.0.0.5:99999", "10.0.0.5:abc", "a b:80", "1:2:3", "[::1"):
            with self.assertRaises(ValueError, msg=bad):
                s(bad)

    def test_interfaces_and_local_ip(self):
        ifs = network.interfaces()
        self.assertTrue(any(i.loopback for i in ifs))
        self.assertTrue(all(not network.is_unspecified(i.ip) for i in ifs))
        ip = network.local_ip()
        self.assertFalse(network.is_unspecified(ip))
        self.assertIn(ip, network.local_addresses())
        self.assertIn("127.0.0.1", network.local_addresses())
        self.assertTrue(all(not i.loopback for i in network.interfaces(include_loopback=False)))

    def test_resolve_advertise_host_never_returns_wildcard(self):
        r = network.resolve_advertise_host
        self.assertFalse(network.is_unspecified(r("0.0.0.0", None, quiet)))
        self.assertFalse(network.is_unspecified(r("::", None, quiet)))
        self.assertEqual(r("0.0.0.0", "192.168.1.10", quiet), "192.168.1.10")
        self.assertEqual(r("127.0.0.1", None, quiet), "127.0.0.1")
        self.assertEqual(r("localhost", None, quiet), "127.0.0.1")
        self.assertEqual(r("0.0.0.0", "nas.local", quiet), "nas.local")
        for bad in ("0.0.0.0", "::", "", "bad host!"):
            with self.assertRaises(ValueError, msg=bad):
                r("0.0.0.0", bad, quiet)

    def test_resolve_notes_a_foreign_address(self):
        notes = []
        network.resolve_advertise_host("0.0.0.0", "203.0.113.9", notes.append)
        self.assertTrue(any("not an address of this machine" in n for n in notes))

    def test_port_available(self):
        self.assertTrue(network.port_available(0))
        import socket
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        s.listen()
        self.addCleanup(s.close)
        self.assertFalse(network.port_available(s.getsockname()[1], "127.0.0.1"))

    def test_gateway_and_json(self):
        gw = network.gateway()
        self.assertTrue(gw is None or network._ip(gw))
        self.assertIn('"a"', network.to_json({"a": network.Interface("x", "10.0.0.2", "255.255.255.0")}))


class CheckTests(Home):
    def test_reachable_node(self):
        a = self.agent("controller")
        res = network.check(f"127.0.0.1:{a.port}")
        self.assertTrue(res["ok"], res)
        self.assertEqual((res["name"], res["role"]), ("n1", "controller"))
        self.assertIsInstance(res["latency_ms"], int)
        self.assertIn("[OK]", network.describe(res))

    def test_key_and_connect_back(self):
        a = self.agent()
        res = network.check(f"http://127.0.0.1:{a.port}", a.key, reverse=a.port)       # it connects back to itself
        self.assertTrue(res["ok"] and res["authenticated"] and res["reverse"]["ok"], res)
        bad = network.check(f"http://127.0.0.1:{a.port}", "x" * 20)
        self.assertFalse(bad["ok"])
        self.assertIs(bad["authenticated"], False)
        self.assertIn("rejected", bad["error"])
        blocked = network.check(f"http://127.0.0.1:{a.port}", a.key, reverse=1)          # nothing listens on port 1
        self.assertFalse(blocked["ok"])
        self.assertIn("cannot connect back", blocked["error"])
        self.assertIn("firewall", blocked["hint"])

    def test_reach_endpoint_only_tries_the_caller(self):
        a = self.agent()
        peer = patchcord.Peer(f"http://127.0.0.1:{a.port}", a.key)
        self.assertTrue(peer.post("/_mesh/reach", {"port": a.port})["ok"])
        with self.assertRaises(patchcord.PeerError) as ctx:
            peer.post("/_mesh/reach", {"port": 0, "host": "8.8.8.8"})
        self.assertEqual(ctx.exception.status, 400)
        with self.assertRaises(patchcord.PeerError) as ctx:
            patchcord.Peer(f"http://127.0.0.1:{a.port}").post("/_mesh/reach", {"port": a.port})
        self.assertEqual(ctx.exception.status, 401)                                      # needs the key

    def test_refused_gives_a_useful_hint(self):
        res = network.check("127.0.0.1:1")
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"], "connection refused")
        self.assertIn("host=\"0.0.0.0\"", res["hint"])
        self.assertIn("127.0.0.1 only reaches", res["hint"])

    def test_bad_targets_never_raise(self):
        self.assertIn("0.0.0.0", network.check("0.0.0.0:8080")["error"])
        self.assertFalse(network.check("")["ok"])
        self.assertFalse(network.check("not a host")["ok"])
        self.assertFalse(network.check("http://")["ok"])
        self.assertFalse(network.check("nonexistent.invalid:80", timeout=2)["ok"])

    def test_something_else_on_the_port(self):
        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"hi")

            def log_message(self, *a):
                pass
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.cleanups.append(lambda: (srv.shutdown(), srv.server_close()))
        res = network.check(f"127.0.0.1:{srv.server_address[1]}")
        self.assertFalse(res["ok"])
        self.assertIn("not with Patchcord", res["error"])


class MdnsTests(unittest.TestCase):
    def setUp(self):
        self.adv = mdns.Advertiser("gpu-01", 8080, "192.168.1.10", "worker")

    def found(self, *packets):
        return mdns.collect([(p, "192.168.1.10") for p in packets])

    def test_query_answer_roundtrip(self):
        reply = self.adv.answer(mdns.build_query([(mdns.SERVICE, mdns.PTR)]))
        (m,) = self.found(reply)
        self.assertEqual((m["name"], m["role"], m["port"], m["ip"]), ("gpu-01", "worker", 8080, "192.168.1.10"))
        self.assertNotIn("key", m["txt"])

    def test_goodbye_and_unrelated_queries(self):
        reply = self.adv.answer(mdns.build_query([(mdns.SERVICE, mdns.PTR)]))
        self.assertEqual(self.found(reply, self.adv.goodbye()), [])
        self.assertIsNone(self.adv.answer(mdns.build_query([(("_other", "_tcp", "local"), mdns.PTR)])))
        self.assertIsNone(self.adv.answer(b"junk"))

    def test_never_announces_a_wildcard(self):
        for bad in ("0.0.0.0", "not-an-ip"):
            with self.assertRaises((ValueError, OSError)):
                mdns.Advertiser("x", 1, bad)

    def test_bad_packets_only_raise_valueerror(self):
        random.seed(7)
        reply = self.adv.answer(mdns.build_query([(mdns.SERVICE, mdns.PTR)]))
        for _ in range(3000):
            d = bytearray(reply)
            for _ in range(random.randint(1, 6)):
                d[random.randrange(len(d))] = random.randrange(256)
            try:
                mdns.parse(bytes(d[:random.randint(0, len(d))]))
            except ValueError:
                pass
        loop = b"\x00\x00\x84\x00\x00\x00\x00\x01\x00\x00\x00\x00" + b"\xc0\x0c" + b"\x00\x0c\x00\x01\x00\x00\x00\x78\x00\x00"
        with self.assertRaises(ValueError):
            mdns.parse(loop)

    def test_over_the_real_network(self):
        try:
            adv = mdns.Advertiser("live-node", 4242, network.local_ip(), "worker", log=quiet).start()
        except OSError:
            self.skipTest("multicast is not available here")
        self.addCleanup(adv.stop)
        try:
            names = [m["name"] for m in mdns.browse(2.0)]
        except OSError:
            self.skipTest("multicast is not available here")
        self.assertIn("live-node", names)


class DiscoveryTests(Home):
    def test_manual_hosts_roundtrip(self):
        self.assertEqual(discovery.hosts(), [])
        discovery.add_host("192.168.1.20", 8080, "lab box")
        discovery.add_host("192.168.1.21:9000")
        discovery.add_host("192.168.1.20:8080", label="renamed")                         # same machine: replaced, not doubled
        self.assertEqual([(h["host"], h["port"], h["label"]) for h in discovery.hosts()],
                         [("192.168.1.21", 9000, ""), ("192.168.1.20", 8080, "renamed")])
        self.assertTrue(discovery.remove_host("192.168.1.21:9000"))
        self.assertFalse(discovery.remove_host("192.168.1.21:9000"))

    def test_bad_hosts_are_refused(self):
        for bad in ("0.0.0.0:8080", "10.0.0.5", "10.0.0.5:99999", ""):
            with self.assertRaises(ValueError, msg=bad):
                discovery.add_host(bad)
        self.assertEqual(discovery.hosts(), [])

    def test_corrupt_hosts_file_is_ignored(self):
        state.write_json(state.path("hosts.json"), {"hosts": [{"host": "10.0.0.5"}, "junk", {"host": "10.0.0.6", "port": "x"}]})
        self.assertEqual(discovery.hosts(), [])

    def test_discover_marks_reachable_and_unreachable(self):
        a = self.agent("controller")
        discovery.add_host("127.0.0.1", a.port, "mine")
        discovery.add_host("127.0.0.1", 1, "dead")
        out = discovery.discover(mdns=False, show=False)
        by = {m["port"]: m for m in out}
        self.assertTrue(by[a.port]["reachable"])
        self.assertEqual((by[a.port]["name"], by[a.port]["role"], by[a.port]["local"]), ("n1", "controller", True))
        self.assertFalse(by[1]["reachable"])
        self.assertIn("host=\"0.0.0.0\"", by[1]["hint"])
        self.assertEqual(out[0]["port"], a.port)                                          # reachable machines first
        table = discovery.format_table(out)
        self.assertIn("UNREACHABLE", table)
        self.assertIn("reachable (", table)

    def test_discover_without_probe_and_empty(self):
        discovery.add_host("127.0.0.1", 5)
        (m,) = discovery.discover(mdns=False, probe=False, show=False)
        self.assertIsNone(m["reachable"])
        self.assertIn("not checked", discovery.format_table([m]))
        self.assertIn("No Patchcord machines found", discovery.format_table([]))


class DoctorTests(Home):
    def test_report(self):
        out = io.StringIO()
        r = doctor(0, internet=False, file=out)
        text = out.getvalue()
        for part in ("PATCHCORD DIAGNOSTICS", "NETWORK", "SECURITY", "RESULT", "Local IP:", "Node key:"):
            self.assertIn(part, text)
        self.assertTrue(r.ok)
        d = r.to_dict()
        self.assertEqual(d["failures"], 0)
        self.assertEqual(len(d["checks"]), len(r.checks))

    def test_busy_port_is_a_warning(self):
        a = self.agent()
        r = doctor(a.port, internet=False, show=False)
        self.assertTrue(any(c.status == "warn" and "already in use" in c.title for c in r.checks))

    def test_target_checks(self):
        a = self.agent()
        good = doctor(0, target=f"127.0.0.1:{a.port}", internet=False, show=False)
        self.assertTrue(any(c.status == "ok" and "Can reach" in c.title for c in good.checks))
        bad = doctor(0, target="127.0.0.1:1", internet=False, show=False)
        self.assertFalse(bad.ok)
        self.assertTrue(any(c.status == "fail" and c.hint for c in bad.checks))
        junk = doctor(0, target="MK1-!!!", internet=False, show=False)
        self.assertFalse(junk.ok)

    def test_target_from_a_join_code(self):
        a = self.agent()
        code = patchcord.pairing.make_join_code(f"http://127.0.0.1:{a.port}", auth.new_key())
        r = doctor(0, target=code, internet=False, show=False)
        self.assertTrue(any("Can reach" in c.title and c.status == "ok" for c in r.checks))

    @unittest.skipIf(os.name == "nt", "permission bits")
    def test_open_registry_file_is_flagged(self):
        path = os.path.join(self.tmp, "workers.json")
        with open(path, "w") as f:
            f.write("{}")
        os.chmod(path, 0o644)
        r = doctor(0, registry_path=path, internet=False, show=False)
        self.assertTrue(any(c.status == "warn" and "readable by other users" in c.title for c in r.checks))
        os.chmod(path, 0o600)
        self.assertFalse(any("readable by other users" in c.title for c in doctor(0, registry_path=path, internet=False, show=False).checks))


class EventTests(unittest.TestCase):
    def test_on_once_off_wildcard_decorator(self):
        class E(Emitter):
            pass
        e, got = E(), []
        e.on("a", lambda x: got.append(("a", x.v)))
        e.once("a", lambda x: got.append("once"))
        e.on("*", lambda x: got.append(("*", x.name)))

        @e.on("d")
        def d(ev):
            got.append("dec")
        self.assertEqual(e.emit("a", v=1), 3)
        self.assertEqual(e.emit("a", v=2), 2)
        e.emit("d")
        self.assertEqual(got[:3], [("a", 1), "once", ("*", "a")])
        self.assertIn("dec", got)
        e.off("a")
        self.assertEqual(e.emit("a", v=3), 1)                                              # only the wildcard is left

    def test_handler_errors_never_escape(self):
        class E(Emitter):
            log = lambda self, m: seen.append(m)  # noqa: E731
        seen = []
        e = E()
        e.on("x", lambda ev: 1 / 0)
        e.on("x", lambda ev: seen.append("second still ran"))
        e.emit("x")
        self.assertTrue(any("ZeroDivisionError" in s for s in seen))
        self.assertIn("second still ran", seen)

    def test_event_attributes(self):
        ev = patchcord.Event("worker.connected", {"worker": "w1"})
        self.assertEqual((ev.name, ev.worker, ev.data), ("worker.connected", "w1", {"worker": "w1"}))
        with self.assertRaises(AttributeError):
            ev.nothing
        with self.assertRaises(TypeError):
            Emitter().on("x", "not callable")


class StateTests(Home):
    def test_roundtrip_and_permissions(self):
        p = state.path("run", "x.json")
        state.write_json(p, {"a": 1})
        self.assertEqual(state.read_json(p), {"a": 1})
        self.assertEqual(state.read_json(os.path.join(self.tmp, "none"), 7), 7)
        if os.name != "nt":
            self.assertEqual(os.stat(p).st_mode & 0o777, 0o600)
            state.write_json(p, {"a": 2}, private=False)
            self.assertEqual(os.stat(p).st_mode & 0o777, 0o644)
        self.assertEqual([f for f in os.listdir(os.path.dirname(p)) if f.endswith(".part")], [])

    def test_failed_write_leaves_no_temp_file(self):
        p = state.path("y.json")
        with self.assertRaises(TypeError):
            state.write_json(p, {"bad": object()})
        self.assertEqual(os.listdir(self.tmp), [])


if __name__ == "__main__":
    unittest.main()
