"""Controller cell."""
from patchcord import Controller, Policy, colab

ctl = Controller(registry_path="/content/workers.json")      # tunnel="cloudflared" by default
join = ctl.start()
ctl.syncer("/content/ComfyUI/models", channel="models", policy=Policy(extensions=(".safetensors", ".ckpt")))
colab.keepalive(lambda: f"Join code for workers:\n{join}\n\nWorkers: {ctl.registry.snapshot()}")
