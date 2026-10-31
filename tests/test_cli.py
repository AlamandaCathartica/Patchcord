"""The `patchcord` command: unit tests of each sub-command, and a real controller + worker as separate processes."""
import contextlib
import io
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest

import patchcord
from patchcord import Agent, auth, cli

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def run(*argv):
    """Run main() in-process: (exit code, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = cli.main(list(argv))
        except SystemExit as e:                                           # argparse errors
            code = e.code
    return code, out.getvalue(), err.getvalue()


def wait_for(cond, timeout=15):
    t0 = time.time()
    while time.time() - t0 < timeout:
        if cond():
            return True
        time.sleep(0.1)
    return False


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        old = os.environ.get("PATCHCORD_HOME")
        os.environ["PATCHCORD_HOME"] = self.tmp
        self.addCleanup(lambda: os.environ.pop("PATCHCORD_HOME") if old is None else os.environ.update(PATCHCORD_HOME=old))


class SimpleCommands(Base):
    def test_version_and_help(self):
        self.assertEqual(run("version"), (0, f"Patchcord {patchcord.__version__}\n", ""))
        self.assertEqual(run("--version")[1].strip(), f"Patchcord {patchcord.__version__}")
        code, out, _ = run()
        self.assertEqual(code, 0)
        for word in ("doctor", "discover", "status", "workers", "controller", "worker", "hosts", "check"):
            self.assertIn(word, out)

    def test_doctor(self):
        code, out, _ = run("doctor", "--no-internet", "--port", "0")
        self.assertEqual(code, 0)
        self.assertIn("PATCHCORD DIAGNOSTICS", out)
        code, out, _ = run("doctor", "--no-internet", "--port", "0", "--json")
        data = json.loads(out)
        self.assertTrue(data["ok"])
        self.assertIn("checks", data)
        code, out, _ = run("doctor", "--no-internet", "--port", "0", "--target", "127.0.0.1:1")
        self.assertEqual(code, 1)
        self.assertIn("[FAIL]", out)

    def test_hosts(self):
        self.assertIn("No machines registered", run("hosts")[1])
        self.assertEqual(run("hosts", "add", "192.168.1.20:8080", "--label", "lab")[0], 0)
        code, out, _ = run("hosts", "list")
        self.assertIn("192.168.1.20:8080", out)
        self.assertIn("lab", out)
        self.assertEqual(json.loads(run("hosts", "--json")[1])[0]["port"], 8080)
        self.assertEqual(run("hosts", "add", "0.0.0.0:80")[0], 2)
        self.assertEqual(run("hosts", "add", "10.0.0.1")[0], 2)                       # a port is needed
        self.assertEqual(run("hosts", "remove", "192.168.1.20:8080")[0], 0)
        self.assertEqual(run("hosts", "remove", "192.168.1.20:8080")[0], 1)
        self.assertEqual(run("hosts", "add")[0], 2)                                   # argparse: needs an address

    def test_check(self):
        a = Agent("n1", auth.new_key(), role="worker").start()
        self.addCleanup(a.stop)
        code, out, _ = run("check", f"127.0.0.1:{a.port}")
        self.assertEqual(code, 0)
        self.assertIn("[OK]", out)
        self.assertTrue(json.loads(run("check", f"127.0.0.1:{a.port}", "--json")[1])["ok"])
        code, out, _ = run("check", "127.0.0.1:1")
        self.assertEqual(code, 1)
        self.assertIn("connection refused", out)

    def test_discover(self):
        a = Agent("n1", auth.new_key(), role="worker").start()
        self.addCleanup(a.stop)
        run("hosts", "add", f"127.0.0.1:{a.port}")
        code, out, _ = run("discover", "--no-mdns", "--timeout", "1")
        self.assertEqual(code, 0)
        self.assertIn("reachable (", out)
        found = json.loads(run("discover", "--no-mdns", "--json")[1])
        self.assertTrue(found[0]["reachable"])

    def test_status_with_nothing_running(self):
        self.assertIn("No Patchcord nodes", run("status")[1])
        self.assertEqual(json.loads(run("status", "--json")[1]), [])

    def test_stale_run_records_are_tidied(self):
        if os.name == "nt":
            self.skipTest("pid checks are POSIX only")
        cli._write_record("worker", "ghost", {"url": "http://x", "port": 1, "host": "127.0.0.1"})
        file = os.path.join(cli._run_dir(), "worker-ghost.json")
        with open(file) as f:
            rec = json.load(f)
        rec["pid"] = 2 ** 22 + 12345                                                  # no such process
        with open(file, "w") as f:
            json.dump(rec, f)
        self.assertIn("No Patchcord nodes", run("status")[1])
        self.assertFalse(os.path.exists(file))

    def test_workers_needs_a_source(self):
        code, out, _ = run("workers")
        self.assertEqual(code, 1)
        self.assertIn("No controller found", out)
        self.assertEqual(run("workers", "--registry", os.path.join(self.tmp, "none.json"))[0], 2)

    def test_workers_from_a_saved_registry_hides_keys(self):
        path = os.path.join(self.tmp, "workers.json")
        reg = patchcord.Registry(path, allow_insecure=True, log=lambda *_: None)
        reg.add({"name": "w1", "url": "http://10.0.0.5:8080", "key": auth.new_key(), "caps": ["sync:models"]}, verify=False)
        code, out, _ = run("workers", "--registry", path)
        self.assertEqual(code, 0)
        self.assertIn("w1", out)
        self.assertIn("sync:models", out)
        data = json.loads(run("workers", "--registry", path, "--json")[1])
        self.assertNotIn("key", data[0])

    def test_argument_helpers(self):
        self.assertEqual(cli._pairs(["a=b", "c=d=e"], "--x"), {"a": "b", "c": "d=e"})
        self.assertEqual(cli._pairs(["app=8188"], "--expose", number=True), {"app": 8188})
        with self.assertRaises(SystemExit):
            cli._pairs(["nope"], "--x")
        with self.assertRaises(SystemExit):
            cli._pairs(["a=b"], "--expose", number=True)
        self.assertEqual((cli._duration(5), cli._duration(65), cli._duration(3725)), ("5s", "1m05s", "1h02m"))

    def test_lan_flag_means_local_tunnel_on_every_interface(self):
        args = cli.build_parser().parse_args(["controller", "start", "--lan"])
        kw = cli._net_settings(args)
        self.assertEqual((kw["tunnel"], kw["host"], kw["allow_insecure"], kw["advertise_host"]), ("local", "0.0.0.0", True, None))
        args = cli.build_parser().parse_args(["worker", "start", "w", "--lan", "--advertise-host", "10.1.2.3", "--no-mdns"])
        kw = cli._net_settings(args)
        self.assertEqual((kw["advertise_host"], kw["mdns"]), ("10.1.2.3", False))
        args = cli.build_parser().parse_args(["controller", "start"])
        self.assertEqual(cli._net_settings(args)["tunnel"], "cloudflared")

    def test_bad_advertise_host_is_reported_not_a_traceback(self):
        code, _, err = run("controller", "start", "--lan", "--advertise-host", "0.0.0.0")
        self.assertEqual(code, 2)
        self.assertIn("0.0.0.0", err)


class EndToEnd(Base):
    """A real controller and worker as two processes on this machine, stopped with Ctrl-C."""

    def spawn(self, *argv, env=None, stdin=False):
        e = {**os.environ, "PYTHONPATH": ROOT, "PATCHCORD_HOME": self.tmp, "PYTHONUNBUFFERED": "1", **(env or {})}
        p = subprocess.Popen([sys.executable, "-m", "patchcord", *argv], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             stdin=subprocess.PIPE if stdin else subprocess.DEVNULL, text=True, env=e, cwd=self.tmp)
        lines = []
        threading.Thread(target=lambda: [lines.append(l.rstrip("\n")) for l in p.stdout], daemon=True).start()
        self.addCleanup(lambda: (p.poll() is None and p.kill(), p.wait(), p.stdout.close(), p.stdin and p.stdin.close()))
        return p, lines

    def cli(self, *argv):
        r = subprocess.run([sys.executable, "-m", "patchcord", *argv], capture_output=True, text=True, timeout=30, cwd=self.tmp,
                           env={**os.environ, "PYTHONPATH": ROOT, "PATCHCORD_HOME": self.tmp})
        return r.returncode, r.stdout

    @unittest.skipIf(os.name == "nt", "uses SIGINT")
    def test_controller_and_worker_processes(self):
        ctl, cl = self.spawn("controller", "start", "--lan", "--probe-interval", "0.3", "--no-mdns")
        self.assertTrue(wait_for(lambda: any("MJ1-" in l for l in cl)), "\n".join(cl))
        join = re.search(r"MJ1-\S+", "\n".join(cl)).group(0)
        self.assertNotIn("0.0.0.0", "\n".join(cl))
        wk, wl = self.spawn("worker", "start", "gpu-01", "--lan", "--join", "-", "--no-mdns", stdin=True)
        wk.stdin.write(join + "\n")                                                    # the join code never appears in `ps`
        wk.stdin.flush()
        self.assertTrue(wait_for(lambda: any("registered with the controller" in l for l in wl)), "\n".join(wl))
        self.assertTrue(wait_for(lambda: any("worker connected:    gpu-01" in l for l in cl)), "\n".join(cl))

        code, out = self.cli("status")
        self.assertEqual(code, 0)
        self.assertRegex(out, r"controller\s+controller\s+running")
        self.assertRegex(out, r"worker\s+gpu-01\s+running")
        status = json.loads(self.cli("status", "--json")[1])
        self.assertEqual({r["role"] for r in status}, {"controller", "worker"})
        self.assertNotIn("key", json.dumps(status))                                   # never printed

        self.assertTrue(wait_for(lambda: "gpu-01" in self.cli("workers")[1] and "yes" in self.cli("workers")[1]), self.cli("workers"))
        code, out = self.cli("workers")
        self.assertEqual(code, 0)
        self.assertRegex(out, r"gpu-01\s+yes")
        peers = json.loads(self.cli("workers", "--json")[1])
        self.assertEqual(peers[0]["name"], "gpu-01")
        self.assertNotIn("key", peers[0])
        worker_url = peers[0]["url"]
        self.assertTrue(self.cli("check", worker_url)[0] == 0)

        for p in (wk, ctl):                                                            # Ctrl-C: both shut down cleanly
            p.send_signal(signal.SIGINT)
        self.assertEqual(wk.wait(20), 0, "\n".join(wl))
        self.assertEqual(ctl.wait(20), 0, "\n".join(cl))
        self.assertTrue(any("Stopping" in l for l in wl + cl))
        self.assertEqual(os.listdir(os.path.join(self.tmp, "run")), [])               # records removed
        self.assertIn("No Patchcord nodes", self.cli("status")[1])

    @unittest.skipIf(os.name == "nt", "uses SIGTERM")
    def test_sigterm_also_stops_cleanly(self):
        wk, wl = self.spawn("worker", "start", "w1", "--tunnel", "local")
        self.assertTrue(wait_for(lambda: any("is running" in l for l in wl)), "\n".join(wl))
        wk.send_signal(signal.SIGTERM)
        self.assertEqual(wk.wait(20), 0)

    def test_bad_join_code_is_reported(self):
        wk, wl = self.spawn("worker", "start", "w1", "--tunnel", "local", "--join", "MJ1-garbage")
        self.assertTrue(wait_for(lambda: any("join code cannot be used" in l for l in wl)), "\n".join(wl))
        wk.send_signal(signal.SIGINT)
        wk.wait(20)

    def test_unknown_command_and_missing_name(self):
        self.assertNotEqual(self.cli("worker", "start")[0], 0)
        self.assertNotEqual(self.cli("bogus")[0], 0)


if __name__ == "__main__":
    unittest.main()
