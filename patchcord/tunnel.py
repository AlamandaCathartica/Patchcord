"""Make a local port reachable from other machines.

Providers: "cloudflared" (free quick tunnel, no account; the default for Colab) and "local" (no tunnel: plain
http://host:port, for LAN or tests). Anything with start(port, on_url, on_line, on_error) and stop() also works;
an optional alive() lets a worker notice that a tunnel died.

"local" separates where a node *listens* (`host`, e.g. 0.0.0.0) from what it *advertises* (`advertise_host`, e.g.
192.168.1.10). The advertised address is never 0.0.0.0.
"""
import os
import platform
import re
import shutil
import stat
import subprocess
import threading
import time
import urllib.request

from . import network

URL_RE = re.compile(r"https://[a-z0-9-]+\.trycloudflare\.com")
NOT_A_TUNNEL = {"https://api.trycloudflare.com"}      # cloudflared mentions its API host in log lines


class Local:
    def __init__(self, host="127.0.0.1", advertise_host=None, **_):
        self.host, self.advertise_host = host, advertise_host

    @property
    def address(self):
        """What other machines are told. Raises ValueError if there is nothing usable to tell them."""
        return network.resolve_advertise_host(self.host, self.advertise_host, log=lambda *_: None)

    def start(self, port, on_url, on_line=None, on_error=print):
        try:
            on_url(f"http://{network.format_host(self.address)}:{port}")
        except ValueError as e:
            on_error(f"Tunnel failed: {e}")

    def stop(self):
        pass

    def alive(self):
        return True


class Cloudflared:
    def __init__(self, cache_dir=None, binary=None, host="127.0.0.1", **_):
        self.cache_dir = cache_dir or os.path.join(os.path.expanduser("~"), ".cache", "patchcord")
        self.binary, self.proc = binary, None
        # cloudflared runs on this machine, so it connects to the agent locally (any address of this machine works)
        self.target = "127.0.0.1" if network.is_unspecified(host) or network.is_loopback(host) else host

    def ensure_binary(self, log=print):
        found = self.binary or shutil.which("cloudflared")
        if found:
            return found
        system = platform.system().lower()
        if system not in ("linux", "windows"):
            raise RuntimeError("cloudflared is not installed. Install it (e.g. `brew install cloudflared`) and make sure "
                               "it is on PATH.")
        path = os.path.join(self.cache_dir, "cloudflared.exe" if system == "windows" else "cloudflared")
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
        arch = "arm64" if platform.machine().lower() in ("aarch64", "arm64") and system == "linux" else "amd64"
        name = f"cloudflared-windows-{arch}.exe" if system == "windows" else f"cloudflared-linux-{arch}"
        url = f"https://github.com/cloudflare/cloudflared/releases/latest/download/{name}"
        os.makedirs(self.cache_dir, exist_ok=True)
        log(f"Downloading cloudflared ({system} {arch}) once; cached in {self.cache_dir}")
        tmp = path + ".part"
        urllib.request.urlretrieve(url, tmp)
        os.chmod(tmp, os.stat(tmp).st_mode | stat.S_IEXEC)
        os.replace(tmp, path)
        return path

    def start(self, port, on_url, on_line=None, on_error=print):
        def run():
            try:
                exe = self.ensure_binary(on_error)
                self.proc = subprocess.Popen(
                    [exe, "tunnel", "--url", f"http://{network.format_host(self.target)}:{port}", "--no-autoupdate"],
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, start_new_session=True)
                announced = False
                for line in self.proc.stdout:
                    if on_line:
                        on_line(line.rstrip("\n"))
                    if not announced:
                        for url in URL_RE.findall(line):
                            if url not in NOT_A_TUNNEL:
                                announced = True
                                on_url(url)
                                break
                on_error("cloudflared exited.")
            except Exception as e:  # noqa: BLE001
                on_error(f"Tunnel failed: {e}")

        threading.Thread(target=run, daemon=True, name="mesh-tunnel").start()

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(5)
            except subprocess.TimeoutExpired:
                self.proc.kill()

    def alive(self):
        """False once cloudflared has exited (quick tunnels do that now and then)."""
        return self.proc is not None and self.proc.poll() is None


PROVIDERS = {"cloudflared": Cloudflared, "local": Local}


def open_tunnel(port, provider="cloudflared", *, cache_dir=None, timeout=120, log=print, host="127.0.0.1",
                advertise_host=None, cancel=None):
    """Make `port` reachable and wait for its address. Returns (url, handle); handle.stop() closes it.

    host / advertise_host   where the node listens / what to tell other machines ("local" provider)
    cancel                  a threading.Event: set it to abandon the wait (raises RuntimeError)
    Raises TimeoutError, RuntimeError (the provider reported a failure, or cancelled) or ValueError (unknown
    provider). Nothing is left running when it raises."""
    if isinstance(provider, str):
        if provider not in PROVIDERS:
            raise ValueError(f"unknown tunnel provider {provider!r} (use one of {sorted(PROVIDERS)})")
        provider = PROVIDERS[provider](cache_dir=cache_dir, host=host, advertise_host=advertise_host)
    got, box, failed = threading.Event(), [], []

    def on_error(msg):
        log(msg)
        failed.append(str(msg))

    provider.start(port, lambda u: (box.append(u), got.set()), on_line=None, on_error=on_error)
    deadline = time.monotonic() + timeout
    while not got.wait(0.2):
        problem = None
        if failed:
            problem = RuntimeError(failed[0])
        elif cancel is not None and cancel.is_set():
            problem = RuntimeError("cancelled")
        elif time.monotonic() >= deadline:
            problem = TimeoutError("the tunnel did not start in time")
        if problem:
            provider.stop()
            raise problem
    return box[0], provider
