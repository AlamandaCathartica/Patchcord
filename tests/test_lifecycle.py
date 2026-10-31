"""Worker and Controller lifecycle, reconnection, rollback, LAN wiring, events and resource-aware selection."""
import os
import shutil
import socket
import tempfile
import threading
import time
import unittest

os.environ["MESH_FAST_RETRY"] = "1"

import patchcord
from patchcord import Controller, Policy, Registry, Worker, auth, network, tunnel

quiet = lambda *_: None  # noqa: E731


def wait_for(cond, timeout=10):
    t0 = time.time()
    while time.time() - t0 < timeout:
        if cond():
            return True
        time.sleep(0.05)
    return False


class FakeTunnel:
    """A tunnel provider the tests can break. Every open_tunnel() builds a new one."""
    instances, fail_after_first, announce = [], False, True
    count = 0

    def __init__(self, **_):
        FakeTunnel.instances.append(self)
        self.up, self.stopped = True, False
        self.number = FakeTunnel.count = FakeTunnel.count + 1

    def start(self, port, on_url, on_line=None, on_error=print):
        if FakeTunnel.fail_after_first and self.number > 1:
            on_error("Tunnel failed: simulated outage")
        elif FakeTunnel.announce:
            on_url(f"http://127.0.0.1:{port}/".rstrip("/"))

    def stop(self):
        self.up, self.stopped = False, True

    def alive(self):
        return self.up

    @classmethod
    def reset(cls):
        cls.instances, cls.fail_after_first, cls.announce, cls.count = [], False, True, 0


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.cleanups = []
        self.addCleanup(lambda: [fn() for fn in reversed(self.cleanups)])
        FakeTunnel.reset()
        tunnel.PROVIDERS["fake"] = FakeTunnel
        self.addCleanup(tunnel.PROVIDERS.pop, "fake", None)

    def worker(self, name="w1", **kw):
        kw.setdefault("tunnel", "local")
        kw.setdefault("log", quiet)
        kw.setdefault("monitor_interval", 0.1)
        kw.setdefault("reconnect_delay", (0.05, 0.2))
        w = Worker(name, **kw)
        self.cleanups.append(w.stop)
        return w

    def controller(self, **kw):
        kw.setdefault("tunnel", "local")
        kw.setdefault("log", quiet)
        kw.setdefault("probe_interval", 0.2)
        c = Controller(**kw)
        self.cleanups.append(c.stop)
        return c

    @staticmethod
    def threads():
        return {t.name for t in threading.enumerate() if t.name.startswith("mesh-")}


# ------------------------------------------------------------------------------------------------ worker lifecycle
class WorkerLifecycle(Base):
    def test_status_is_running_uptime(self):
        w = self.worker()
        self.assertEqual((w.status, w.is_running, w.uptime), ("stopped", False, 0.0))
        code = w.start()
        self.assertEqual((w.status, w.is_running), ("running", True))
        self.assertTrue(code.startswith("MK1-"))
        time.sleep(0.15)
        self.assertGreater(w.uptime, 0.1)
        info = w.info()
        self.assertEqual((info["status"], info["running"], info["name"]), ("running", True, "w1"))
        self.assertNotIn(w.agent.key, str(info))
        self.assertNotIn(code, str(info))
        w.stop()
        self.assertEqual((w.status, w.is_running, w.uptime), ("stopped", False, 0.0))

    def test_duplicate_start_changes_nothing(self):
        w = self.worker()
        code, port = w.start(), w.agent.port
        before = self.threads()
        self.assertEqual(w.start(), code)
        self.assertEqual((w.agent.port, self.threads()), (port, before))

    def test_stop_is_idempotent_and_cleans_up_threads(self):
        baseline = self.threads()
        w = self.worker(join=patchcord.pairing.make_join_code("http://127.0.0.1:9", auth.new_key()))
        w.start()
        self.assertTrue({"mesh-monitor", "mesh-join"} <= self.threads())
        w.stop()
        w.stop()
        self.assertTrue(wait_for(lambda: not (self.threads() - baseline - {"mesh-agent"})), self.threads())
        self.assertFalse(w.agent.running)
        with self.assertRaises(OSError):                                            # the port really is free again
            socket.create_connection(("127.0.0.1", w.agent.port), timeout=1)

    def test_stop_before_start_is_harmless(self):
        w = self.worker()
        w.stop()
        self.assertEqual(w.status, "stopped")

    def test_restart_keeps_name_key_and_port(self):
        w = self.worker()
        w.start()
        key, port = w.agent.key, w.agent.port
        events = []
        w.on("*", lambda e: events.append(e.name))
        code = w.restart()
        self.assertEqual((w.status, w.agent.key, w.agent.port, w.name), ("running", key, port, "w1"))
        self.assertEqual(patchcord.pairing.parse_code(code, allow_insecure=True)["key"], key)
        self.assertTrue(w.agent.running)
        self.assertEqual([e for e in events if e in ("worker.stopped", "worker.started")], ["worker.stopped", "worker.started"])

    def test_reconnect_opens_new_tunnels_without_stopping_the_agent(self):
        w = self.worker(tunnel="fake")
        w.start()
        first = FakeTunnel.instances[0]
        seen = []
        w.on("worker.reconnecting", lambda e: seen.append("reconnecting"))
        w.reconnect()
        self.assertEqual((w.reconnects, w.status, seen), (1, "running", ["reconnecting"]))
        self.assertTrue(first.stopped)
        self.assertTrue(w.agent.running)
        self.assertEqual(len(FakeTunnel.instances), 2)

    def test_reconnect_needs_a_running_worker(self):
        with self.assertRaises(RuntimeError):
            self.worker().reconnect()

    def test_context_manager(self):
        with self.worker() as w:
            self.assertTrue(w.is_running)
        self.assertEqual(w.status, "stopped")


class WorkerFailure(Base):
    def test_failed_tunnel_rolls_everything_back(self):
        FakeTunnel.announce = False
        FakeTunnel.fail_after_first = True
        FakeTunnel.count = 0
        errors, w = [], self.worker(tunnel="fake")
        w.on("worker.error", lambda e: errors.append(e.phase))
        baseline = self.threads()
        # first call succeeds in announcing? no: announce is False, so this one just fails fast through on_error
        FakeTunnel.fail_after_first = False

        class Broken(FakeTunnel):
            def start(self, port, on_url, on_line=None, on_error=print):
                on_error("Tunnel failed: no route to cloudflare")
        tunnel.PROVIDERS["fake"] = Broken
        t0 = time.time()
        with self.assertRaises(RuntimeError):
            w.start()
        self.assertLess(time.time() - t0, 5)                                         # failed fast, not after the timeout
        self.assertEqual((w.status, w.is_running, w.url, w.code), ("failed", False, "", ""))
        self.assertIn("no route", w.last_error)
        self.assertEqual(errors, ["start"])
        self.assertFalse(w.agent.running)
        self.assertEqual(self.threads() - baseline, set())
        tunnel.PROVIDERS["fake"] = FakeTunnel                                         # and it can be started again afterwards
        FakeTunnel.announce = True
        w.start()
        self.assertEqual(w.status, "running")

    def test_second_tunnel_failing_closes_the_first(self):
        calls = []

        class Second(FakeTunnel):
            def start(self, port, on_url, on_line=None, on_error=print):
                calls.append(self)
                if len(calls) == 2:
                    on_error("Tunnel failed: second one broke")
                else:
                    on_url(f"http://127.0.0.1:{port}")
        tunnel.PROVIDERS["fake"] = Second
        w = self.worker(tunnel="fake", expose={"app": 8188})
        with self.assertRaises(RuntimeError):
            w.start()
        self.assertTrue(calls[0].stopped)
        self.assertEqual(w.status, "failed")
        self.assertFalse(w.agent.running)

    def test_stop_cancels_a_start_that_is_waiting_for_a_tunnel(self):
        FakeTunnel.announce = False                                                   # never announces an address
        w = self.worker(tunnel="fake")
        result = []

        def go():
            try:
                w.start(timeout=60)
            except Exception as e:  # noqa: BLE001
                result.append(e)
        t = threading.Thread(target=go)
        t.start()
        self.assertTrue(wait_for(lambda: w.status == "starting"))
        t0 = time.time()
        w.stop()
        t.join(5)
        self.assertFalse(t.is_alive())
        self.assertLess(time.time() - t0, 5)
        self.assertEqual(len(result), 1)
        self.assertEqual((w.status, w.agent.running), ("stopped", False))
        self.assertTrue(FakeTunnel.instances[0].stopped)

    def test_unusable_advertise_host_is_refused_at_construction(self):
        with self.assertRaises(ValueError):
            Worker("w", tunnel="local", host="0.0.0.0", advertise_host="0.0.0.0")
        w = Worker("w", tunnel="local", host="0.0.0.0")
        self.assertFalse(network.is_unspecified(w.advertise_host))

    def test_dead_tunnel_is_replaced_automatically(self):
        w = self.worker(tunnel="fake")
        w.start()
        names, first = [], FakeTunnel.instances[0]
        w.on("*", lambda e: names.append(e.name))
        first.up = False                                                              # the tunnel dies
        self.assertTrue(wait_for(lambda: w.reconnects >= 1), "no automatic reconnect")
        self.assertTrue(wait_for(lambda: w.status == "running"))
        self.assertIn("worker.disconnected", names)
        self.assertIn("worker.reconnecting", names)
        self.assertIn("worker.connected", names)
        self.assertLess(names.index("worker.disconnected"), names.index("worker.connected"))
        self.assertIsNot(w._handles[0], first)

    def test_reconnect_retries_with_backoff_then_recovers(self):
        w = self.worker(tunnel="fake")
        w.start()
        start_count = FakeTunnel.count
        outage = {"on": True}

        class Flaky(FakeTunnel):
            def start(self, port, on_url, on_line=None, on_error=print):
                if outage["on"]:
                    on_error("Tunnel failed: outage")
                else:
                    on_url(f"http://127.0.0.1:{port}")
        tunnel.PROVIDERS["fake"] = Flaky
        FakeTunnel.instances[0].up = False
        self.assertTrue(wait_for(lambda: w.last_error))
        time.sleep(0.5)
        self.assertEqual(w.reconnects, 0)
        self.assertTrue(w.is_running)                                                 # still trying, not given up
        outage["on"] = False
        self.assertTrue(wait_for(lambda: w.reconnects == 1), "did not recover")
        self.assertEqual(w.status, "running")
        self.assertGreater(FakeTunnel.count, start_count)

    def test_gives_up_after_max_attempts(self):
        w = self.worker(tunnel="fake", max_reconnect_attempts=2)
        w.start()

        class Down(FakeTunnel):
            def start(self, port, on_url, on_line=None, on_error=print):
                on_error("Tunnel failed: down")
        tunnel.PROVIDERS["fake"] = Down
        FakeTunnel.instances[0].up = False
        self.assertTrue(wait_for(lambda: w.status == "failed", 15))
        self.assertFalse(w.is_running)
        w.stop()                                                                      # still shuts down cleanly
        self.assertEqual(w.status, "stopped")

    def test_auto_reconnect_can_be_switched_off(self):
        w = self.worker(tunnel="fake", auto_reconnect=False)
        w.start()
        FakeTunnel.instances[0].up = False
        self.assertTrue(wait_for(lambda: w.last_error))
        time.sleep(0.4)
        self.assertEqual(w.reconnects, 0)

    def test_agent_that_stops_is_noticed_and_revived(self):
        w = self.worker()
        w.start()
        port = w.agent.port
        w.agent.stop()
        self.assertTrue(wait_for(lambda: w.reconnects >= 1), "agent was not revived")
        self.assertTrue(w.agent.running)
        self.assertEqual(w.agent.port, port)

    def test_no_event_after_stopped(self):
        events = []
        w = self.worker(join=patchcord.pairing.make_join_code("http://127.0.0.1:9", auth.new_key()))
        w.on("*", lambda e: events.append(e.name))
        w.start()
        time.sleep(0.3)
        w.stop()
        time.sleep(0.3)
        self.assertEqual(events[-1], "worker.stopped")


# ------------------------------------------------------------------------------------------------ controller + worker
class LanTests(Base):
    def test_lan_mode_advertises_a_real_address_never_the_wildcard(self):
        ctl = self.controller(host="0.0.0.0")
        join = ctl.start()
        self.assertNotIn("0.0.0.0", ctl.url)
        self.assertNotIn("0.0.0.0", patchcord.pairing.parse_join_code(join, allow_insecure=True)["url"])
        self.assertEqual(ctl.agent.host, "0.0.0.0")                                   # it still *listens* everywhere
        self.assertEqual(ctl.url, f"http://{network.local_ip()}:{ctl.agent.port}")
        w = self.worker(host="0.0.0.0")
        code = w.start()
        self.assertNotIn("0.0.0.0", patchcord.pairing.parse_code(code, allow_insecure=True)["url"])

    def test_explicit_advertise_host(self):
        ctl = self.controller(host="0.0.0.0", advertise_host="127.0.0.1")
        ctl.start()
        self.assertEqual(ctl.url, f"http://127.0.0.1:{ctl.agent.port}")

    def test_local_mode_accepts_http_without_extra_flags(self):
        self.assertTrue(Controller(tunnel="local", log=quiet).allow_insecure)
        self.assertTrue(Worker("w", tunnel="local", log=quiet).allow_insecure)
        self.assertFalse(Controller(tunnel="cloudflared", log=quiet).allow_insecure)
        self.assertTrue(Controller(tunnel="cloudflared", allow_insecure=True, log=quiet).allow_insecure)

    def test_worker_registers_and_events_fire(self):
        ctl = self.controller(host="0.0.0.0")
        got = []
        ctl.on("*", lambda e: got.append((e.name, e.data.get("worker"))))
        join = ctl.start()
        w = self.worker(host="0.0.0.0", join=join)
        wev = []
        w.on("*", lambda e: wev.append(e.name))
        w.start()
        self.assertTrue(wait_for(lambda: w.registered and ctl.workers and ctl.workers[0].online))
        self.assertIn(("worker.connected", "w1"), got)
        self.assertIn("worker.registered", wev)
        self.assertIn("worker.connected", wev)
        self.assertEqual([x.name for x in ctl.workers], ["w1"])
        self.assertEqual(ctl.worker("w1").url, w.url)
        w.stop()
        self.assertTrue(wait_for(lambda: not ctl.worker("w1").online), "controller did not notice the worker leaving")
        self.assertIn(("worker.disconnected", "w1"), got)
        ctl.registry.remove("w1")
        self.assertIn(("worker.removed", "w1"), got)

    def test_connection_check_works_in_both_directions(self):
        ctl = self.controller(host="0.0.0.0")
        join = ctl.start()
        w = self.worker(host="0.0.0.0", join=join)
        w.start()
        self.assertTrue(wait_for(lambda: ctl.workers and ctl.workers[0].online))
        res = ctl.check("w1")
        self.assertTrue(res["ok"], res)
        self.assertTrue(res["authenticated"])
        self.assertTrue(res["reverse"]["ok"])

    def test_worker_that_restarts_registers_its_new_address(self):
        ctl = self.controller()
        join = ctl.start()
        w = self.worker(join=join, port=0)
        w.start()
        self.assertTrue(wait_for(lambda: w.registered))
        old_url = ctl.worker("w1").url
        w.agent.stop()                                                                # the machine's agent dies and is revived
        self.assertTrue(wait_for(lambda: w.reconnects >= 1))
        self.assertTrue(wait_for(lambda: ctl.workers[0].online and w.registered))
        self.assertEqual(ctl.worker("w1").url, old_url)                               # same port is re-used: still the same

    def test_files_sync_and_transfer_events(self):
        src, dst = os.path.join(self.tmp, "src"), os.path.join(self.tmp, "dst")
        os.makedirs(src)
        os.makedirs(dst)
        with open(os.path.join(src, "model.safetensors"), "wb") as f:
            f.write(os.urandom(300_000))
        policy = Policy(extensions=(".safetensors",), settle=0, reserve=0)
        ctl = self.controller()
        sent, joined = [], []
        ctl.on("transfer.started", lambda e: joined.append(("started", e.worker, e.path)))
        ctl.on("transfer.completed", lambda e: sent.append((e.worker, e.channel, e.path, e.size)))
        join = ctl.start()
        w = self.worker(join=join, sync={"models": dst}, policy=policy)
        got = []
        w.on("transfer.completed", lambda e: got.append((e.channel, e.path, e.size)))
        w.start()
        ctl.syncer(src, "models", policy, interval=0.3)
        self.assertTrue(wait_for(lambda: os.path.exists(os.path.join(dst, "model.safetensors")), 20))
        self.assertTrue(wait_for(lambda: sent and got))
        self.assertEqual(sent[0], ("w1", "models", "model.safetensors", 300_000))
        self.assertEqual(got[0], ("models", "model.safetensors", 300_000))
        self.assertEqual(joined[0], ("started", "w1", "model.safetensors"))

    def test_controller_lifecycle(self):
        ctl = self.controller()
        self.assertEqual((ctl.status, ctl.is_running, ctl.uptime), ("stopped", False, 0.0))
        join = ctl.start()
        self.assertEqual(ctl.start(), join)                                           # duplicate start
        self.assertTrue(ctl.is_running)
        ctl.stop()
        ctl.stop()
        self.assertEqual(ctl.status, "stopped")
        new = ctl.start()                                                             # and it can start again
        self.assertTrue(new.startswith("MJ1-"))
        w = self.worker(join=new)
        w.start()
        self.assertTrue(wait_for(lambda: ctl.workers and ctl.workers[0].online), "probing did not restart after restart")

    def test_controller_start_rolls_back_when_the_tunnel_fails(self):
        class Broken(FakeTunnel):
            def start(self, port, on_url, on_line=None, on_error=print):
                on_error("Tunnel failed: nope")
        tunnel.PROVIDERS["fake"] = Broken
        ctl = self.controller(tunnel="fake")
        baseline = self.threads()
        with self.assertRaises(RuntimeError):
            ctl.start()
        self.assertEqual((ctl.status, ctl.agent.running, ctl.url), ("stopped", False, ""))
        self.assertEqual(self.threads() - baseline, set())


# ------------------------------------------------------------------------------------------------ resources
class SelectionTests(unittest.TestCase):
    def registry(self):
        reg = Registry(allow_insecure=True, log=quiet)
        gpu = lambda free, total=24000: {"name": "g", "mem_free_mib": free, "mem_total_mib": total, "mem_used_mib": total - free}  # noqa: E731
        spec = {
            "big":    dict(gpus=[gpu(20000), gpu(10000)], ram=64, disk=500),
            "small":  dict(gpus=[gpu(8000, 8000)], ram=16, disk=100),
            "cpu":    dict(gpus=[], ram=128, disk=900),
            "silent": None,
        }
        for i, (name, s) in enumerate(spec.items()):
            reg.add({"name": name, "url": f"http://10.0.0.{i + 1}:80", "key": auth.new_key(), "caps": ["sync:models"] if name != "cpu" else []},
                    verify=False)
            p = reg._peers[name]
            p["online"] = True
            if s:
                p["stats"] = {"gpus": s["gpus"], "ram": {"total": s["ram"] << 30, "used": 0, "available": s["ram"] << 30},
                              "disk": {"total": s["disk"] << 30, "free": s["disk"] << 30}}
        return reg

    def names(self, **kw):
        return [w.name for w in self.registry().select_workers(**kw)]

    def test_gpu_and_vram(self):
        self.assertEqual(self.names(gpu_required=True), ["big", "small"])               # most free VRAM first
        self.assertEqual(self.names(gpu_required=True, min_vram=12000), ["big"])
        self.assertEqual(self.names(min_vram=12000), ["big"])                           # asking for VRAM implies a GPU
        self.assertEqual(self.names(min_vram=30000), [])
        self.assertEqual(self.names(min_gpus=2), ["big"])
        self.assertEqual(self.names(min_gpus=2, min_vram=15000), [])                    # only one GPU has 15 GB free

    def test_ram_disk_caps_exclude(self):
        self.assertEqual(self.names(min_ram=100 * 1024), ["cpu"])
        self.assertEqual(sorted(self.names(min_disk=400 * 1024)), ["big", "cpu"])
        self.assertEqual(sorted(self.names(caps=["sync:models"])), ["big", "silent", "small"])
        self.assertEqual(self.names(gpu_required=True, exclude=["big"]), ["small"])

    def test_unknown_stats_never_satisfy_a_numeric_requirement(self):
        reg = self.registry()
        self.assertIn("silent", [w.name for w in reg.select_workers()])
        for kw in (dict(min_ram=1), dict(min_disk=1), dict(gpu_required=True)):
            self.assertNotIn("silent", [w.name for w in reg.select_workers(**kw)])

    def test_offline_and_disabled_are_skipped(self):
        reg = self.registry()
        reg._peers["big"]["online"] = False
        reg.set_enabled("small", False)
        self.assertIsNone(reg.select_worker(gpu_required=True))
        self.assertNotIn("small", [w.name for w in reg.select_workers()])
        self.assertNotIn("big", [w.name for w in reg.select_workers()])

    def test_worker_info_shape(self):
        reg = self.registry()
        big, silent = reg.worker("big"), reg.worker("silent")
        self.assertEqual((len(big.gpus), big.free_vram, big.free_ram), (2, 20000, 64 * 1024))
        self.assertEqual(silent.stats["gpus"], [])                                      # always present, so w.stats["gpus"] works
        self.assertIsNone(silent.free_ram)
        self.assertNotIn("key", big.to_dict())
        self.assertNotIn("key", reg.snapshot()[0])
        self.assertIsNone([s for s in reg.snapshot() if s["name"] == "silent"][0]["stats"])   # the CLI shows "?" for these
        with self.assertRaises(KeyError):
            reg.worker("nobody")
        self.assertIsNone(reg.select_worker(min_vram=999999))


if __name__ == "__main__":
    unittest.main()
