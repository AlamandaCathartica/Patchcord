"""Push a folder of big files from one node to others: chunked, resumable, hash-verified, atomic.

Receiver side (workers):   Receiver("/content/models", channel="models", policy=Policy(extensions=(".safetensors",)))
                           .attach(agent)          # adds GET .../inventory and POST .../chunk to the agent
Sender side (controller):  Pusher("/content/models", channel="models", policy=...).sync(peer)

How it works
  * The sender hashes each file once (remembered by size + mtime) and asks the receiver what it has.
  * It sends what is missing or different, smallest first, in `policy.chunk` slices (so a dropped connection resumes).
  * The receiver hashes as slices arrive. The file only becomes visible, in one atomic rename, if the SHA-256
    matches what the sender announced. A half-written or damaged file is never visible.
  * Nothing is ever deleted on the receiver. A file with the same path but different content is replaced.
  * Every path from the network is validated by the Policy before it touches the disk.
Empty files are not synced.
"""
import hashlib
import json
import os
import re
import threading
import time
from dataclasses import dataclass

from .peer import PeerError

PROTOCOL = "mesh-sync1"
STAGE_DIR = ".mesh-sync"                 # inside the root: partial files wait here (same disk, so the final move is atomic)
NAME_RE = re.compile(r"[\w][\w .,+()\[\]'&@#=~\-]{0,200}")
SHA_RE = re.compile(r"[0-9a-f]{64}")


@dataclass
class Policy:
    """Configure file types, paths, chunk sizes, and disk-space rules for sync."""
    extensions: tuple = None             # e.g. (".safetensors", ".ckpt"); None = any file name
    max_depth: int = 8                   # folders + file name
    skip_dirs: frozenset = frozenset()   # folder names that are never synced
    reserve: int = 1 << 30               # the receiver keeps this much disk free
    chunk: int = 32 << 20                # bytes per request (Cloudflare tunnels allow 100 MB)
    settle: float = 3.0                  # a file modified in the last seconds may still be growing: do not send yet

    def check_path(self, rel):
        """Validate 'sub/dir/file.ext'. Returns it normalised or raises ValueError."""
        parts = str(rel or "").replace("\\", "/").split("/")
        if not 1 <= len(parts) <= self.max_depth or "" in parts:
            raise ValueError("bad path")
        for p in parts:
            if not NAME_RE.fullmatch(p) or ".." in p or p in self.skip_dirs:
                raise ValueError("bad path component")
        if self.extensions and not parts[-1].lower().endswith(tuple(e.lower() for e in self.extensions)):
            raise ValueError("this file type is not allowed")
        return "/".join(parts)


def abs_path(root, rel, policy):
    return os.path.join(root, *policy.check_path(rel).split("/"))


def sha256_file(path, stop=None):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            blk = f.read(4 << 20)
            if not blk:
                return h.hexdigest()
            if stop and stop():
                raise InterruptedError
            h.update(blk)


class HashIndex:
    """SHA-256 of files remembered by path, checked against size and mtime, so a big file is hashed once."""

    def __init__(self, path=None):
        self.path, self._d, self._lock, self._dirty = path, {}, threading.Lock(), False
        if path and os.path.isfile(path):
            try:
                with open(path, encoding="utf-8") as f:
                    self._d = {k: v for k, v in json.load(f).items() if isinstance(v, list) and len(v) == 3}
            except (OSError, ValueError, AttributeError):
                self._d = {}

    def get(self, rel, size, mtime_ns):
        with self._lock:
            e = self._d.get(rel)
        return e[2] if e and e[0] == size and e[1] == mtime_ns else None

    def put(self, rel, size, mtime_ns, sha):
        with self._lock:
            self._d[rel], self._dirty = [size, mtime_ns, sha], True

    def forget_missing(self, present):
        with self._lock:
            for k in [k for k in self._d if k not in present]:
                del self._d[k]
                self._dirty = True

    def save(self):
        if not self.path:
            return
        with self._lock:
            if not self._dirty:
                return
            data, self._dirty = json.dumps(self._d), False
        try:
            os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
            tmp = self.path + ".part"
            with open(tmp, "w", encoding="utf-8") as f:
                f.write(data)
            os.replace(tmp, self.path)
        except OSError:
            pass


def scan(root, policy):
    """-> ([{path, size, mtime_ns}], [rejected paths]). Skips hidden names, symlinks, empty files and the staging folder."""
    out, skipped = [], []
    for d, dirs, names in os.walk(root):
        dirs[:] = sorted(x for x in dirs if not x.startswith(".") and x not in policy.skip_dirs)
        for n in sorted(names):
            if n.startswith("."):
                continue
            full = os.path.join(d, n)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            if policy.extensions and not n.lower().endswith(tuple(e.lower() for e in policy.extensions)):
                continue
            if os.path.islink(full):
                continue
            try:
                policy.check_path(rel)
                st = os.stat(full)
            except ValueError:
                skipped.append(rel)
                continue
            except OSError:
                continue
            if st.st_size > 0:
                out.append({"path": rel, "size": st.st_size, "mtime_ns": st.st_mtime_ns})
    return out, skipped


def inventory(root, index, policy):
    files, skipped = scan(root, policy)
    for f in files:
        f["sha256"] = index.get(f["path"], f["size"], f["mtime_ns"])
    return files, skipped


def hash_missing(root, index, policy, stop=None):
    """Hash every file without a valid cached hash. Returns how many files still have none (too fresh or changing)."""
    files, _ = scan(root, policy)
    index.forget_missing({f["path"] for f in files})
    waiting = 0
    for f in files:
        if index.get(f["path"], f["size"], f["mtime_ns"]):
            continue
        if policy.settle and time.time() - f["mtime_ns"] / 1e9 < policy.settle:
            waiting += 1
            continue
        full = abs_path(root, f["path"], policy)
        try:
            sha = sha256_file(full, stop)
            st = os.stat(full)
        except InterruptedError:                      # asked to stop (it is an OSError, so it must be caught first)
            return waiting + 1
        except OSError:
            continue
        if (st.st_size, st.st_mtime_ns) != (f["size"], f["mtime_ns"]):
            waiting += 1
            continue
        index.put(f["path"], f["size"], f["mtime_ns"], sha)
        index.save()
    return waiting


# ------------------------------------------------------------------------------------------------ receiving
class Receiver:
    """Receive chunked files, verify their SHA-256 hashes, and install them safely."""
    def __init__(self, root, channel="files", policy=None, log=print, on_complete=None):
        """on_complete(path, size) is called after each file has been verified and installed."""
        self.root, self.channel, self.policy, self.log = root, channel, policy or Policy(), log
        self.on_complete = on_complete
        self.stage = os.path.join(root, STAGE_DIR)
        self.index = HashIndex(os.path.join(self.stage, "hashes.json"))
        self._lock, self._wake, self._st = threading.Lock(), threading.Event(), {}
        self._halt, self._hasher = threading.Event(), None
        os.makedirs(self.stage, exist_ok=True)
        self._cleanup_stage()

    @property
    def cap(self):
        return f"sync:{self.channel}"

    def _cleanup_stage(self):
        """Keep a partial file only if both halves exist: p-<id>.part (the bytes) and p-<id>.json (what it is)."""
        names = set(os.listdir(self.stage))
        for n in names:
            stem, ext = os.path.splitext(n)
            if n.startswith("p-") and ((ext == ".part" and stem + ".json" not in names)
                                       or (ext == ".json" and stem + ".part" not in names)):
                try:
                    os.remove(os.path.join(self.stage, n))
                except OSError:
                    pass

    def attach(self, agent, start=True):
        """Add the sync endpoints to `agent`. start=False leaves the background hasher off until start() (a Worker
        starts and stops it together with itself)."""
        from .agent import ApiError
        base = f"/_mesh/sync/{self.channel}"

        @agent.route("GET", base + "/inventory")
        def _inventory(req):
            return self.inventory()

        @agent.route("POST", base + "/chunk")
        def _chunk(req):
            q = req.query
            try:
                return self.receive(q.get("path", ""), req.int("offset"), req.int("total"), q.get("sha256", ""),
                                    req.read())
            except ValueError as e:
                raise ApiError(400, str(e)) from None

        if start:
            self.start()
        return self

    def start(self):
        """Start the background hasher (it hashes what is already in the folder so the sender can compare). Idempotent."""
        if self._hasher and self._hasher.is_alive():
            return self
        self._halt = threading.Event()
        self._hasher = threading.Thread(target=self._hash_loop, args=(self._halt,), daemon=True, name="mesh-hasher")
        self._hasher.start()
        return self

    def stop(self):
        """Stop the background hasher. The endpoints stay in place; start() brings it back."""
        self._halt.set()
        self._wake.set()
        if self._hasher and self._hasher is not threading.current_thread():
            self._hasher.join(5)
        self._hasher = None

    def _hash_loop(self, halt):
        while not halt.is_set():
            try:
                waiting = hash_missing(self.root, self.index, self.policy, stop=halt.is_set)
            except InterruptedError:
                return
            except Exception as e:  # noqa: BLE001
                self.log(f"[mesh] hashing: {e}")
                waiting = 0
            self._wake.wait(2 if waiting else 20)
            self._wake.clear()

    def inventory(self):
        files, skipped = inventory(self.root, self.index, self.policy)
        try:
            import shutil
            free = shutil.disk_usage(self.root).free
        except OSError:
            free = 0
        return {"protocol": PROTOCOL, "files": files, "skipped": skipped, "free": free, "partial": self.partials()}

    def _part(self, rel):
        return os.path.join(self.stage, "p-" + hashlib.sha1(rel.encode()).hexdigest()[:24] + ".part")

    def _meta_path(self, rel):
        return self._part(rel)[:-5] + ".json"

    def _read_meta(self, path):
        try:
            with open(path, encoding="utf-8") as f:
                m = json.load(f)
            return m if isinstance(m, dict) and SHA_RE.fullmatch(str(m.get("sha"))) and m.get("path") else None
        except (OSError, ValueError):
            return None

    def partials(self):
        """Half-received files the sender can continue: [{path, sha256, total, have}]."""
        out = []
        with self._lock:
            for n in os.listdir(self.stage):
                if not (n.startswith("p-") and n.endswith(".json")):
                    continue
                m = self._read_meta(os.path.join(self.stage, n))
                if not m:
                    continue
                st = self._st.get(m["path"])
                try:
                    have = st["have"] if st else os.path.getsize(os.path.join(self.stage, n[:-5] + ".part"))
                except OSError:
                    continue
                out.append({"path": m["path"], "sha256": m["sha"], "total": m.get("total"), "have": have})
        return out

    def _drop(self, rel):
        self._st.pop(rel, None)
        for p in (self._part(rel), self._meta_path(rel)):
            try:
                os.remove(p)
            except OSError:
                pass

    def _recover(self, rel, sha, total):
        """After a restart: pick up a partial file from disk by hashing the bytes already there. None if there is none."""
        m = self._read_meta(self._meta_path(rel))
        if not m or m["path"] != rel or m["sha"] != sha or m.get("total") != total:
            return None
        h = hashlib.sha256()
        try:
            size = os.path.getsize(self._part(rel))
            if not 0 < size < total:
                return None
            with open(self._part(rel), "rb") as f:
                for blk in iter(lambda: f.read(4 << 20), b""):
                    h.update(blk)
        except OSError:
            return None
        st = self._st[rel] = {"h": h, "have": size, "sha": sha, "total": total}
        return st

    def receive(self, rel, offset, total, sha, data):
        """One slice. Returns {"done": bool, "have": bytes_so_far}. Raises ApiError (409 = out of order, 422 = bad hash)."""
        from .agent import ApiError
        rel = self.policy.check_path(rel)                 # ValueError -> 400 in the route
        if not SHA_RE.fullmatch(sha or ""):
            raise ApiError(400, "bad sha256")
        if total <= 0 or offset < 0 or offset >= total or not data:
            raise ApiError(400, "bad slice")
        if offset + len(data) > total:
            raise ApiError(400, "slice goes past the end of the file")
        with self._lock:
            st = self._st.get(rel)
            if offset == 0:
                import shutil
                if total + self.policy.reserve > shutil.disk_usage(self.root).free:
                    raise ApiError(507, "not enough disk space")
                self._drop(rel)
                st = self._st[rel] = {"h": hashlib.sha256(), "have": 0, "sha": sha, "total": total}
                with open(self._meta_path(rel), "w", encoding="utf-8") as f:
                    json.dump({"path": rel, "sha": sha, "total": total}, f)
            else:
                st = st or self._recover(rel, sha, total)
            if not st or st["have"] != offset or st["sha"] != sha or st["total"] != total:
                raise ApiError(409, "out of order", have=st["have"] if st and st["sha"] == sha else 0)
            with open(self._part(rel), "ab") as f:
                f.write(data)
            st["h"].update(data)
            st["have"] += len(data)
            if st["have"] < total:
                return {"done": False, "have": st["have"]}
            digest = st["h"].hexdigest()
            if digest != sha:
                self._drop(rel)
                raise ApiError(422, "sha256 does not match; the file was discarded")
            dst = os.path.join(self.root, *rel.split("/"))
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            os.replace(self._part(rel), dst)
            self._st.pop(rel, None)
            try:
                os.remove(self._meta_path(rel))
            except OSError:
                pass
            stt = os.stat(dst)
            self.index.put(rel, stt.st_size, stt.st_mtime_ns, sha)
            self.index.save()
        self.log(f"[mesh] received {rel}")
        if self.on_complete:
            try:
                self.on_complete(rel, total)
            except Exception as e:  # noqa: BLE001  (the application's callback must not fail the transfer)
                self.log(f"[mesh] on_complete for {rel} raised {type(e).__name__}: {e}")
        return {"done": True, "have": total}


# ------------------------------------------------------------------------------------------------ sending
class Pusher:
    """Synchronize files from a local folder to a remote receiver."""
    def __init__(self, root, channel="files", policy=None, log=print, on_progress=None, retries=5, emit=None):
        """emit(event, **data) receives transfer.started / transfer.completed / transfer.failed (worker, channel, path,
        size, error); a Controller passes its own emit."""
        self.root, self.channel, self.policy, self.log = root, channel, policy or Policy(), log
        self.on_progress, self.retries, self.emit = on_progress, retries, emit
        self.index = HashIndex(os.path.join(root, STAGE_DIR, "hashes-sender.json"))
        self.stop_event, self._hash_lock = threading.Event(), threading.Lock()

    @property
    def cap(self):
        return f"sync:{self.channel}"

    def _event(self, name, peer, f, **extra):
        if self.emit:
            try:
                self.emit(name, worker=peer.name, channel=self.channel, path=f["path"], size=f["size"], **extra)
            except Exception as e:  # noqa: BLE001
                self.log(f"[mesh] event {name}: {e}")

    def _progress(self, peer, **kw):
        if self.on_progress:
            self.on_progress(peer.name, kw)

    @staticmethod
    def diff(ready, remote_files):
        """-> (files to send smallest first, how many are identical, how many wait for the receiver's hash)"""
        have = {f["path"]: f for f in remote_files}
        todo, same, waiting = [], 0, 0
        for f in ready:
            rf = have.get(f["path"])
            if rf and rf.get("size") == f["size"]:
                if not rf.get("sha256"):
                    waiting += 1                   # same size, hash unknown yet: wait, do not guess
                    continue
                if rf["sha256"] == f["sha256"]:
                    same += 1
                    continue
            todo.append(f)
        todo.sort(key=lambda f: f["size"])
        return todo, same, waiting

    def sync(self, peer):
        """Bring `peer` up to date. Returns {"sent", "same", "waiting", "errors": [..]}. Raises PeerError if the peer is unreachable
        or does not speak this protocol."""
        os.makedirs(os.path.join(self.root, STAGE_DIR), exist_ok=True)
        with self._hash_lock:                               # peers sync in parallel; hash each file only once
            fresh = hash_missing(self.root, self.index, self.policy, stop=self.stop_event.is_set)
        files, _ = inventory(self.root, self.index, self.policy)
        ready = [f for f in files if f["sha256"]]
        base = f"/_mesh/sync/{self.channel}"
        try:
            remote = peer.get(base + "/inventory", timeout=45)
        except PeerError as e:
            if e.status == 404:
                raise PeerError(f"{peer.name} has no '{self.channel}' sync channel", 404) from None
            raise
        if remote.get("protocol") != PROTOCOL:
            raise PeerError(f"{peer.name} speaks a different sync version")
        todo, same, waiting = self.diff(ready, remote.get("files", []))
        partial = {p.get("path"): p for p in remote.get("partial") or [] if isinstance(p, dict)}
        free, errors, sent = remote.get("free") or 0, [], 0
        for i, f in enumerate(todo):
            if self.stop_event.is_set():
                break
            if f["size"] + self.policy.reserve > free:
                errors.append(f"no space on {peer.name} for {f['path']}")
                continue
            self._progress(peer, state="syncing", file=f["path"], done=0, total=f["size"], queue=len(todo) - i)
            self._event("transfer.started", peer, f)
            try:
                finished = self._push_file(peer, f, partial.get(f["path"]))
            except FileNotFoundError:
                continue                           # deleted while queued
            except PeerError as e:
                errors.append(f"{f['path']}: {e}")
                self._event("transfer.failed", peer, f, error=str(e))
                continue
            if not finished:                       # stopped part-way: not sent, not an error
                break
            self._event("transfer.completed", peer, f)
            free -= f["size"]
            sent += 1
            self.log(f"[mesh] {f['path']} -> {peer.name}")
        self._progress(peer, state="error" if errors else "synced", file="", done=0, total=0, queue=0,
                       error=errors[0] if errors else "")
        return {"sent": sent, "same": same, "waiting": waiting + fresh, "errors": errors}

    def _push_file(self, peer, f, partial=None):
        rel, size = f["path"], f["size"]
        full = abs_path(self.root, rel, self.policy)
        st = os.stat(full)
        if (st.st_size, st.st_mtime_ns) != (size, f["mtime_ns"]):
            raise PeerError("it changed while waiting to be sent; it will be sent again")
        path = f"/_mesh/sync/{self.channel}/chunk"
        offset, fails, resyncs = 0, 0, 0
        if partial and partial.get("sha256") == f["sha256"] and partial.get("total") == size:
            have = partial.get("have")
            if isinstance(have, int) and 0 < have < size:
                offset = have                              # the receiver kept part of this file: continue, do not restart
        with open(full, "rb") as fh:
            while offset < size:
                if self.stop_event.is_set():
                    return False
                fh.seek(offset)
                data = fh.read(min(self.policy.chunk, size - offset))
                if not data:
                    raise PeerError("the file got shorter while it was being sent")
                try:
                    peer.request("POST", path, params={"path": rel, "offset": offset, "total": size,
                                                       "sha256": f["sha256"]},
                                 data=data, headers={"Content-Type": "application/octet-stream"}, timeout=300)
                except PeerError as e:
                    if e.status == 409:            # the receiver is somewhere else (a slice landed but the reply was lost)
                        resyncs += 1
                        if resyncs > 10:
                            raise PeerError("the receiver keeps losing its place") from None
                        offset = max(0, min(size - 1, int(e.body.get("have", 0))))
                        continue
                    if e.status != 0:              # a real refusal (bad hash, no space, auth): do not retry
                        raise
                    fails += 1
                    if fails > self.retries:
                        raise
                    time.sleep(min(30, 2 ** fails) if not os.environ.get("MESH_FAST_RETRY") else 0.01)
                    continue
                fails = 0
                offset += len(data)
                self._progress(peer, state="syncing", file=rel, done=offset, total=size)
        return True


class SyncLoop:
    """Keeps every online peer that advertises the channel up to date: a pass every `interval` seconds, or at once on wake()."""

    def __init__(self, pusher, registry, interval=20, log=print, emit=None):
        """emit(event, **data): a failed pass raises worker.error (worker, error)."""
        self.pusher, self.registry, self.interval, self.log, self.emit = pusher, registry, interval, log, emit
        self.status, self._wake, self._stop = {}, threading.Event(), threading.Event()
        self._lock, self._busy = threading.Lock(), set()
        pusher.on_progress = self._on_progress

    def _on_progress(self, name, kw):
        self.status.setdefault(name, {}).update(kw)

    def start(self):
        threading.Thread(target=self._run, daemon=True, name="mesh-sync").start()
        return self

    def stop(self):
        self._stop.set()
        self.pusher.stop_event.set()
        self._wake.set()

    def wake(self):
        self._wake.set()

    def run_once(self, wait=True):
        """One pass: every eligible peer syncs in its own thread, so a slow worker never holds up the others. A peer that is
        still busy from the previous pass is skipped. wait=True returns when this pass's threads are done."""
        threads = []
        for peer in self.registry.online():
            if self.pusher.cap not in peer.caps:
                continue
            with self._lock:
                if peer.name in self._busy:
                    continue
                self._busy.add(peer.name)
            t = threading.Thread(target=self._sync_peer, args=(peer,), daemon=True, name=f"mesh-sync-{peer.name}")
            t.start()
            threads.append(t)
        if wait:
            for t in threads:
                t.join()

    def _error(self, peer, exc):
        if self.emit:
            try:
                self.emit("worker.error", worker=peer.name, error=str(exc))
            except Exception:  # noqa: BLE001
                pass

    def _sync_peer(self, peer):
        try:
            res = self.pusher.sync(peer)
            self.status.setdefault(peer.name, {}).update(last=res, error=res["errors"][0] if res["errors"] else "")
        except PeerError as e:
            self.status.setdefault(peer.name, {}).update(state="error", error=str(e))
            self._error(peer, e)
        except Exception as e:  # noqa: BLE001  (one bad peer must not stop the others)
            self.log(f"[mesh] sync {peer.name}: {e}")
            self.status.setdefault(peer.name, {}).update(state="error", error=str(e))
            self._error(peer, e)
        finally:
            with self._lock:
                self._busy.discard(peer.name)

    def _run(self):
        while not self._stop.is_set():
            try:
                self.run_once(wait=False)
            except Exception as e:  # noqa: BLE001  (never let the thread die)
                self.log(f"[mesh] sync loop: {e}")
            self._wake.wait(self.interval)
            self._wake.clear()
