"""Small helpers for notebook launchers (Colab or any Jupyter). Nothing here is required to use the rest of patchcord."""
import os
import subprocess
import sys
import time


def is_colab():
    return "google.colab" in sys.modules or bool(os.environ.get("COLAB_RELEASE_TAG"))


def kill_stale(*patterns):
    """pkill leftovers of a previous run of the cell (e.g. 'cloudflared', 'my_app.py')."""
    for p in patterns:
        try:
            subprocess.run(["pkill", "-f", p], check=False)
        except FileNotFoundError:                    # no pkill (Windows): nothing to clean up
            return


def ensure_repo(url, directory, branch="main"):
    """Clone, or update to the latest commit if already cloned. Returns True if the code is now current; on a failed
    update the copy that is already there is kept (returns False)."""
    if os.path.isdir(os.path.join(directory, ".git")):
        r = subprocess.run(f"git -C {directory} fetch --depth 1 origin {branch} && "
                           f"git -C {directory} reset --hard FETCH_HEAD", shell=True, capture_output=True, text=True)
    else:
        subprocess.run(["rm", "-rf", directory], check=False)
        r = subprocess.run(["git", "clone", "--depth", "1", "-b", branch, url, directory], capture_output=True, text=True)
    if r.returncode != 0 and not os.path.isdir(directory):
        raise SystemExit(f"Could not download {url} (branch {branch}):\n{r.stderr}")
    return r.returncode == 0


def pip_install(*args):
    r = subprocess.run([sys.executable, "-m", "pip", "install", "-q", *args], capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit("pip install failed:\n" + (r.stdout + r.stderr)[-2000:])


def keepalive(render, interval=20, running=lambda: True):
    """Keep the cell alive and redraw `render()` (a string) every `interval` seconds, until Ctrl-C or running() is False."""
    try:
        from IPython.display import clear_output
    except ImportError:
        clear_output = lambda **kw: None  # noqa: E731
    try:
        while running():
            clear_output(wait=True)
            print(render())
            time.sleep(interval)
    except KeyboardInterrupt:
        print("Cell stopped. Background threads keep running.")
