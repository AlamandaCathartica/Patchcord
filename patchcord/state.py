"""Where Patchcord keeps its small local files, and a safe way to write them.

    $PATCHCORD_HOME            if set, everything lives there
    ~/.patchcord               otherwise (on Windows: %LOCALAPPDATA%\\patchcord)

    hosts.json                 machines you registered by hand (see patchcord.discovery.add_host)
    run/<name>.json            one file per node started by the `patchcord` command, so `patchcord status` can find it
"""
import json
import os
import tempfile


def home():
    base = os.environ.get("PATCHCORD_HOME")
    if not base:
        if os.name == "nt" and os.environ.get("LOCALAPPDATA"):
            base = os.path.join(os.environ["LOCALAPPDATA"], "patchcord")
        else:
            base = os.path.join(os.path.expanduser("~"), ".patchcord")
    return base


def path(*parts):
    return os.path.join(home(), *parts)


def read_json(file, default=None):
    try:
        with open(file, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def write_json(file, data, private=True):
    """Atomic write; private=True makes the file readable by this user only (it may hold node keys)."""
    folder = os.path.dirname(os.path.abspath(file))
    os.makedirs(folder, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=folder, suffix=".part")        # mkstemp creates the file with mode 0600
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        if not private and os.name != "nt":
            os.chmod(tmp, 0o644)
        os.replace(tmp, file)
    except BaseException:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise
