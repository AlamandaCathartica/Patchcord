"""What a Colab worker cell looks like with patchcord (compare ~60 lines of boilerplate in ComfyCluster's Worker.ipynb).

    !pip install -q git+https://github.com/YOU/patchcord
    JOIN = "MJ1-..."                      # printed by the controller cell
"""
import subprocess

from patchcord import Policy, Worker, colab

colab.kill_stale("cloudflared", "main.py")
app = subprocess.Popen(["python", "main.py", "--port", "8188"], cwd="/content/ComfyUI")      # your app, any app

worker = Worker(
    "worker1",
    sync={"models": "/content/ComfyUI/models"},          # the controller pushes files here
    policy=Policy(extensions=(".safetensors", ".ckpt")),
    expose={"comfy": 8188},                              # also tunnel the app's own port; its URL rides in the code
    logs={"engine": "/content/engine.log"},
    join="MJ1-...",                                      # registers itself; nothing to paste
)
code = worker.start()
colab.keepalive(lambda: f"worker1 ready\n\n{code}", running=lambda: app.poll() is None)
