import os
import shutil
import tempfile
import threading
import time
import unittest


def slurp(path):
    with open(path, "rb") as f:
        return f.read()


os.environ["MESH_FAST_RETRY"] = "1"

from patchcord import (Agent, ApiError, Controller, Peer, PeerError, Policy, Pusher, Receiver, Registry, SyncLoop,
                     Worker, auth, pairing)
from patchcord.transfer import hash_missing, scan


def wait_for(cond, timeout=10):
    t0 = time.time()
    while time.time() - t0 < timeout:
        if cond():
            return True
        time.sleep(0.05)
    return False


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.cleanups = []

    def tearDown(self):
        for fn in self.cleanups:
            fn()

    def agent(self, name="w1", **kw):
        a = Agent(name, auth.new_key(), host="127.0.0.1", **kw).start()
        self.cleanups.append(a.stop)
        return a, Peer(f"http://127.0.0.1:{a.port}", a.key, name)


class PairingTests(unittest.TestCase):
    def test_roundtrip(self):
        key = auth.new_key()
        code = pairing.make_code("worker1", "https://abc-def.trycloudflare.com", key, ["sync:models"],
                                 {"comfy": "https://x-y.trycloudflare.com"})
        info = pairing.parse_code(code)
        self.assertEqual(info["name"], "worker1")
        self.assertEqual(info["caps"], ["sync:models"])
        self.assertEqual(info["urls"], {"comfy": "https://x-y.trycloudflare.com"})
        self.assertEqual(info["key"], key)

    def test_rejects_bad_input(self):
        key = auth.new_key()
        for bad in ("hello", "MK1-!!!notbase64", pairing.make_code("w", "http://plain.example.com", key),
                    pairing.make_code("w", "https://u:p@host.com", key),
                    pairing.make_code("w", "https://host.com/path", key),
                    pairing.make_code("../x", "https://host.com", key),
                    pairing.make_code("w", "https://host.com", "short")):
            with self.assertRaises(ValueError, msg=bad):
                pairing.parse_code(bad)

    def test_insecure_and_host_rules(self):
        c = pairing.make_code("w", "http://127.0.0.1:9", auth.new_key())
        self.assertEqual(pairing.parse_code(c, allow_insecure=True)["url"], "http://127.0.0.1:9")
        c2 = pairing.make_code("w", "https://evil.example.com", auth.new_key())
        with self.assertRaises(ValueError):
            pairing.parse_code(c2, allow_hosts=[r".+\.trycloudflare\.com"])

    def test_parse_codes_skips_placeholders(self):
        a = pairing.make_code("a", "https://a.example.com", auth.new_key())
        b = pairing.make_code("b", "https://b.example.com", auth.new_key())
        out = pairing.parse_codes(f"{a}, MK1-....\n{b}")
        self.assertEqual([w["name"] for w in out], ["a", "b"])

    def test_join_code(self):
        tok = auth.new_key()
        self.assertEqual(pairing.parse_join_code(pairing.make_join_code("https://c.example.com", tok))["token"], tok)
        with self.assertRaises(ValueError):
            pairing.parse_join_code("MK1-whatever")


class AgentTests(Base):
    def test_auth_health_rpc_routes(self):
        a, peer = self.agent(log=lambda *_: None)      # the 500 below is logged on purpose; keep the test output quiet

        @a.rpc("add")
        def add(a, b):
            return a + b

        @a.route("GET", "/hello/<who>")
        def hello(req):
            return {"hi": req.params["who"], "q": req.query.get("x")}

        @a.route("GET", "/boom")
        def boom(req):
            raise RuntimeError("secret detail")

        self.assertTrue(peer.health())
        self.assertEqual(peer.call("add", a=2, b=3), 5)
        self.assertEqual(peer.get("/hello/bob", x="1"), {"hi": "bob", "q": "1"})
        with self.assertRaises(PeerError) as e:
            Peer(peer.url, "wrong-key-wrong-key-1234").stats()
        self.assertEqual(e.exception.status, 401)
        with self.assertRaises(PeerError) as e:
            Peer(peer.url).get("/hello/bob")
        self.assertEqual(e.exception.status, 401)
        with self.assertRaises(PeerError) as e:
            peer.call("nope")
        self.assertEqual(e.exception.status, 404)
        with self.assertRaises(PeerError) as e:
            peer.call("add", a=1)                        # missing argument -> 400, not 500
        self.assertEqual(e.exception.status, 400)
        with self.assertRaises(PeerError) as e:
            peer.get("/boom")
        self.assertEqual(e.exception.status, 500)
        self.assertNotIn("secret detail", str(e.exception))   # internals do not leak

    def test_stats_and_logs(self):
        logf = os.path.join(self.tmp, "engine.log")
        with open(logf, "w") as f:
            f.write("\n".join(f"line {i}" for i in range(50)))
        a, peer = self.agent(logs={"engine": logf})
        self.assertIn("cpu_count", peer.stats())
        self.assertEqual(peer.log("engine", lines=3)["lines"], ["line 47", "line 48", "line 49"])
        with self.assertRaises(PeerError) as e:
            peer.log("secrets")
        self.assertEqual(e.exception.status, 404)

    def test_unreachable_peer(self):
        self.assertFalse(Peer("http://127.0.0.1:1").health(1))


class TransferTests(Base):
    def setUp(self):
        super().setUp()
        self.src, self.dst = os.path.join(self.tmp, "src"), os.path.join(self.tmp, "dst")
        os.makedirs(self.src)
        os.makedirs(self.dst)
        self.policy = Policy(extensions=(".bin",), chunk=1000, settle=0, reserve=0)
        self.a, self.peer = self.agent()
        self.recv = Receiver(self.dst, "m", self.policy, log=lambda *_: None).attach(self.a)
        self.push = Pusher(self.src, "m", self.policy, log=lambda *_: None)

    def write(self, rel, data):
        p = os.path.join(self.src, *rel.split("/"))
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as f:
            f.write(data)

    def read_dst(self, rel):
        with open(os.path.join(self.dst, *rel.split("/")), "rb") as f:
            return f.read()

    def test_sync_copies_then_noops_then_replaces(self):
        self.write("a/one.bin", os.urandom(4321))
        self.write("two.bin", os.urandom(10))
        self.write("ignored.txt", b"not a model")
        r = self.push.sync(self.peer)
        self.assertEqual((r["sent"], r["errors"]), (2, []))
        self.assertEqual(self.read_dst("a/one.bin"), slurp(os.path.join(self.src, "a", "one.bin")))
        self.assertFalse(os.path.exists(os.path.join(self.dst, "ignored.txt")))
        self.assertTrue(wait_for(lambda: self.push.sync(self.peer)["same"] == 2))      # receiver hashes in background
        self.write("two.bin", b"changed!!!")                                           # same size, new content
        self.assertTrue(wait_for(lambda: self.push.sync(self.peer)["sent"] == 1))
        self.assertEqual(self.read_dst("two.bin"), b"changed!!!")

    def test_dropped_reply_resumes_without_corruption(self):
        data = os.urandom(5000)
        self.write("big.bin", data)
        calls = {"n": 0}
        real = self.peer.request

        def flaky(method, path, **kw):
            out = real(method, path, **kw)
            if path.endswith("/chunk"):
                calls["n"] += 1
                if calls["n"] == 2:                  # the server took slice 2 but we never heard back
                    raise PeerError("connection reset")
            return out
        self.peer.request = flaky
        r = self.push.sync(self.peer)
        self.assertEqual((r["sent"], r["errors"]), (1, []))
        self.assertEqual(self.read_dst("big.bin"), data)

    def test_bad_hash_is_discarded(self):
        with self.assertRaises(PeerError) as e:
            self.peer.request("POST", "/_mesh/sync/m/chunk", params={"path": "x.bin", "offset": 0, "total": 4,
                                                                     "sha256": "0" * 64}, data=b"abcd")
        self.assertEqual(e.exception.status, 422)
        self.assertFalse(os.path.exists(os.path.join(self.dst, "x.bin")))

    def test_paths_are_validated(self):
        for bad in ("../evil.bin", "a/../../evil.bin", "/etc/passwd.bin", "x.txt", ".hidden.bin", "a//b.bin"):
            with self.assertRaises(PeerError, msg=bad) as e:
                self.peer.request("POST", "/_mesh/sync/m/chunk", params={"path": bad, "offset": 0, "total": 4,
                                                                         "sha256": "0" * 64}, data=b"abcd")
            self.assertEqual(e.exception.status, 400, bad)
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "evil.bin")))

    def test_out_of_order_slice_gets_409(self):
        with self.assertRaises(PeerError) as e:
            self.peer.request("POST", "/_mesh/sync/m/chunk", params={"path": "y.bin", "offset": 500, "total": 1000,
                                                                     "sha256": "1" * 64}, data=b"z" * 500)
        self.assertEqual((e.exception.status, e.exception.body["have"]), (409, 0))

    def test_needs_key_and_unknown_channel(self):
        with self.assertRaises(PeerError) as e:
            Peer(self.peer.url).get("/_mesh/sync/m/inventory")
        self.assertEqual(e.exception.status, 401)
        other = Pusher(self.src, "nope", self.policy, log=lambda *_: None)
        with self.assertRaises(PeerError) as e:
            other.sync(self.peer)
        self.assertEqual(e.exception.status, 404)

    def test_scan_skips_symlinks_and_hidden(self):
        self.write("ok.bin", b"x")
        self.write(".hid/den.bin", b"x")
        try:
            os.symlink(os.path.join(self.src, "ok.bin"), os.path.join(self.src, "link.bin"))
        except (OSError, NotImplementedError):
            self.skipTest("cannot create symlinks here (Windows needs admin rights or Developer Mode)")
        files, _ = scan(self.src, self.policy)
        self.assertEqual([f["path"] for f in files], ["ok.bin"])


class RegistryTests(Base):
    def test_add_verify_persist_duplicate_reserved(self):
        a, peer = self.agent("w1")
        path = os.path.join(self.tmp, "workers.json")
        reg = Registry(path, allow_insecure=True, log=lambda *_: None)
        code = pairing.make_code("w1", peer.url, a.key, ["sync:m"])
        self.assertTrue(reg.add(code)["online"])
        self.assertNotIn("key", reg.snapshot()[0])                      # secrets never leave the registry
        with self.assertRaises(ValueError):                             # same address under another name
            reg.add(pairing.make_code("w2", peer.url, a.key))
        with self.assertRaises(ValueError):
            reg.add(pairing.make_code("all", peer.url, a.key))
        with self.assertRaises(ValueError):                             # nothing is listening there
            reg.add(pairing.make_code("ghost", "http://127.0.0.1:1", auth.new_key()))
        reg2 = Registry(path, allow_insecure=True, log=lambda *_: None)
        self.assertEqual([p["name"] for p in reg2.snapshot()], ["w1"])
        self.assertEqual(reg2.join_token, reg.join_token)
        if os.name != "nt":                                              # Windows ignores POSIX permission bits
            self.assertEqual(oct(os.stat(path).st_mode & 0o777), "0o600")
        a.stop()
        reg2.probe_all()
        self.assertFalse(reg2.snapshot()[0]["online"])
        self.assertEqual(reg2.online(), [])

    def test_register_endpoint_needs_join_token(self):
        ctl, ctl_peer = self.agent("ctl")
        reg = Registry(allow_insecure=True, log=lambda *_: None).attach(ctl)
        w, wpeer = self.agent("w1")
        code = pairing.make_code("w1", wpeer.url, w.key)
        with self.assertRaises(PeerError) as e:
            Peer(ctl_peer.url).post("/_mesh/register", {"code": code})
        self.assertEqual(e.exception.status, 401)
        with self.assertRaises(PeerError) as e:                          # the controller's own key is not the join token
            ctl_peer.post("/_mesh/register", {"code": code})
        self.assertEqual(e.exception.status, 401)
        out = Peer(ctl_peer.url).request("POST", "/_mesh/register", json_body={"code": code},
                                         headers={auth.JOIN_HEADER: reg.join_token})
        self.assertEqual(out["name"], "w1")


class ResumeAndParallelTests(Base):
    def make_receiver(self, dst, policy):
        a, peer = self.agent()
        Receiver(dst, "m", policy, log=lambda *_: None).attach(a)
        return a, peer

    def test_partial_file_survives_receiver_restart(self):
        import hashlib
        src, dst = os.path.join(self.tmp, "src"), os.path.join(self.tmp, "dst")
        os.makedirs(src)
        os.makedirs(dst)
        policy = Policy(extensions=(".bin",), chunk=1000, settle=0, reserve=0)
        data = os.urandom(5000)
        with open(os.path.join(src, "big.bin"), "wb") as f:
            f.write(data)
        sha = hashlib.sha256(data).hexdigest()
        a1, p1 = self.make_receiver(dst, policy)
        for off in (0, 1000, 2000):                                   # three slices arrive, then the worker dies
            p1.request("POST", "/_mesh/sync/m/chunk", params={"path": "big.bin", "offset": off, "total": 5000,
                                                              "sha256": sha}, data=data[off:off + 1000])
        a1.stop()
        a2, p2 = self.make_receiver(dst, policy)                      # a new process on the same folder
        inv = p2.get("/_mesh/sync/m/inventory")
        self.assertEqual([(x["path"], x["have"]) for x in inv["partial"]], [("big.bin", 3000)])
        offsets, real = [], p2.request

        def spy(method, path, **kw):
            if path.endswith("/chunk"):
                offsets.append(kw["params"]["offset"])
            return real(method, path, **kw)
        p2.request = spy
        r = Pusher(src, "m", policy, log=lambda *_: None).sync(p2)
        self.assertEqual((r["sent"], r["errors"]), (1, []))
        self.assertEqual(offsets, [3000, 4000])                      # resumed, did not start over
        with open(os.path.join(dst, "big.bin"), "rb") as f:
            self.assertEqual(f.read(), data)
        self.assertEqual(p2.get("/_mesh/sync/m/inventory")["partial"], [])

    def test_tampered_partial_is_caught_and_retried_clean(self):
        import hashlib
        src, dst = os.path.join(self.tmp, "src"), os.path.join(self.tmp, "dst")
        os.makedirs(src)
        os.makedirs(dst)
        policy = Policy(extensions=(".bin",), chunk=1000, settle=0, reserve=0)
        data = os.urandom(3000)
        with open(os.path.join(src, "f.bin"), "wb") as f:
            f.write(data)
        sha = hashlib.sha256(data).hexdigest()
        a1, p1 = self.make_receiver(dst, policy)
        p1.request("POST", "/_mesh/sync/m/chunk", params={"path": "f.bin", "offset": 0, "total": 3000, "sha256": sha},
                   data=data[:1000])
        a1.stop()
        part = [n for n in os.listdir(os.path.join(dst, ".mesh-sync")) if n.endswith(".part")][0]
        with open(os.path.join(dst, ".mesh-sync", part), "r+b") as f:     # corrupted while the worker was down
            f.write(b"\x00" * 10)
        a2, p2 = self.make_receiver(dst, policy)
        push = Pusher(src, "m", policy, log=lambda *_: None)
        r = push.sync(p2)
        self.assertEqual(r["sent"], 0)
        self.assertTrue(r["errors"] and "sha256" in r["errors"][0])
        self.assertFalse(os.path.exists(os.path.join(dst, "f.bin")))      # damaged data never became visible
        r = push.sync(p2)                                                 # the bad partial was discarded: clean retry
        self.assertEqual((r["sent"], r["errors"]), (1, []))
        with open(os.path.join(dst, "f.bin"), "rb") as f:
            self.assertEqual(f.read(), data)

    def test_orphan_stage_files_are_cleaned(self):
        dst = os.path.join(self.tmp, "dst")
        stage = os.path.join(dst, ".mesh-sync")
        os.makedirs(stage)
        for n in ("p-aaa.part", "p-bbb.json"):
            open(os.path.join(stage, n), "w").close()
        Receiver(dst, "m", Policy(), log=lambda *_: None)
        self.assertEqual([n for n in os.listdir(stage) if n.startswith("p-")], [])

    def test_peers_sync_in_parallel_and_busy_peer_is_skipped(self):
        src = os.path.join(self.tmp, "src")
        os.makedirs(src)
        policy = Policy(extensions=(".bin",), chunk=1000, settle=0, reserve=0)
        with open(os.path.join(src, "x.bin"), "wb") as f:
            f.write(os.urandom(500))
        peers, lock, state = [], threading.Lock(), {"now": 0, "max": 0}
        for i in range(2):
            dst = os.path.join(self.tmp, f"dst{i}")
            os.makedirs(dst)
            _, peer = self.make_receiver(dst, policy)
            peer.name, peer.caps, real = f"w{i}", ["sync:m"], peer.request

            def slow(method, path, _real=real, **kw):
                if path.endswith("/chunk"):
                    with lock:
                        state["now"] += 1
                        state["max"] = max(state["max"], state["now"])
                    time.sleep(0.4)
                    with lock:
                        state["now"] -= 1
                return _real(method, path, **kw)
            peer.request = slow
            peers.append(peer)

        class FakeRegistry:
            def online(self):
                return peers
        loop = SyncLoop(Pusher(src, "m", policy, log=lambda *_: None), FakeRegistry(), log=lambda *_: None)
        loop.run_once()
        self.assertEqual(state["max"], 2)                                 # both workers were fed at the same time
        for i in range(2):
            self.assertTrue(os.path.exists(os.path.join(self.tmp, f"dst{i}", "x.bin")))
        loop._busy.add("w0")                                              # still syncing from an earlier pass
        calls = []
        loop._sync_peer = lambda peer: (calls.append(peer.name), loop._busy.discard(peer.name))
        loop.run_once()
        self.assertEqual(calls, ["w1"])


class EndToEndTests(Base):
    def test_worker_joins_and_receives_files(self):
        src, dst = os.path.join(self.tmp, "src"), os.path.join(self.tmp, "dst")
        os.makedirs(src)
        os.makedirs(dst)
        data = os.urandom(70_000)
        with open(os.path.join(src, "model.bin"), "wb") as f:
            f.write(data)
        policy = Policy(extensions=(".bin",), chunk=16_384, settle=0, reserve=0)
        quiet = lambda *_: None  # noqa: E731
        ctl = Controller(tunnel="local", host="127.0.0.1", allow_insecure=True, probe_interval=1, log=quiet)
        join = ctl.start()
        self.cleanups.append(ctl.stop)
        loop = ctl.syncer(src, "models", policy, interval=1)
        w = Worker("worker1", tunnel="local", host="127.0.0.1", sync={"models": dst}, policy=policy, join=join,
                   allow_insecure=True, log=quiet)
        w.start()
        self.cleanups.append(w.stop)
        self.assertTrue(wait_for(lambda: ctl.registry.snapshot() and ctl.registry.snapshot()[0]["online"]),
                        "worker did not register itself")
        target = os.path.join(dst, "model.bin")
        self.assertTrue(wait_for(lambda: os.path.exists(target) and slurp(target) == data, 20),
                        f"file was not synced: {loop.status}")
        peer = ctl.registry.peer("worker1")
        self.assertIn("sync:models", peer.caps)
        self.assertTrue(peer.health())


if __name__ == "__main__":
    unittest.main()
