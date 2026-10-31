"""Run a whole cluster on this machine: python examples/local_demo.py"""
import os
import tempfile
import time

from patchcord import Controller, Policy, Worker

tmp = tempfile.mkdtemp()
src, dst = os.path.join(tmp, "src"), os.path.join(tmp, "dst")
os.makedirs(src), os.makedirs(dst)
open(os.path.join(src, "hello.bin"), "wb").write(os.urandom(200_000))

policy = Policy(extensions=(".bin",), chunk=64_000, settle=0, reserve=0)
ctl = Controller(tunnel="local", host="127.0.0.1", allow_insecure=True, probe_interval=1)
join = ctl.start()
ctl.syncer(src, "demo", policy, interval=1)
w = Worker("worker1", tunnel="local", host="127.0.0.1", sync={"demo": dst}, policy=policy, join=join, allow_insecure=True)
w.start()

for _ in range(30):
    if os.path.exists(os.path.join(dst, "hello.bin")):
        break
    time.sleep(0.5)
print("workers:", ctl.registry.snapshot())
print("synced :", os.listdir(dst))
print("stats  :", ctl.registry.peer("worker1").stats())
w.stop(), ctl.stop()
