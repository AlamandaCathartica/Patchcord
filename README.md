# patchcord


```text

 ____          __           __                              __     
/\  _`\       /\ \__       /\ \                            /\ \    
\ \ \L\ \ __  \ \ ,_\   ___\ \ \___     ___    ___   _ __  \_\ \   
 \ \ ,__/'__`\ \ \ \/  /'___\ \  _ `\  /'___\ / __`\/\`'__\/'_` \  
  \ \ \/\ \L\.\_\ \ \_/\ \__/\ \ \ \ \/\ \__//\ \L\ \ \ \//\ \L\ \ 
   \ \_\ \__/.\_\\ \__\ \____\\ \_\ \_\ \____\ \____/\ \_\\ \___,_\
    \/_/\/__/\/_/ \/__/\/____/ \/_/\/_/\/____/\/___/  \/_/ \/__,_ /

        
```

Connect several machines (Colab notebooks, LAN boxes, servers) into one cluster. Extracted from ComfyCluster;
standard library only, Python 3.9+.

| Module | Job |
|---|---|
| `tunnel` | Make a local port reachable (`"cloudflared"` quick tunnel, or `"local"` for LAN/tests; plug in your own) |
| `pairing` | Versioned codes: worker code (`MK1-`: name, url, key, capabilities, extra urls) and controller join code (`MJ1-`) |
| `Agent` | Small worker-side server: auth, `/_mesh/health`, `stats`, `log`, your own `@route` and `@rpc` |
| `Peer` | Client for another node (`health`, `stats`, `log`, `call`, or raw `request`) |
| `Receiver` / `Pusher` / `SyncLoop` | Resumable, hash-verified, atomic one-way folder sync with a path `Policy` |
| `Registry` | Controller's worker list: add by code, probe, persist (0600), self-registration endpoint |
| `Worker` / `Controller` | All of the above wired together (lifecycle, auto-reconnect, events, resource-aware `select_worker`) |
| `network` | Interfaces, `local_ip()`, the address to advertise, `check()` a connection (both directions) |
| `discovery` / `mdns` | `patchcord.discover()`: mDNS plus machines registered by hand |
| `doctor` | `patchcord.doctor()`: why can't this machine connect? |
| `events` | `controller.on("worker.connected", ...)` |
| `cli` | the `patchcord` command |
| `colab` | Notebook helpers: `ensure_repo`, `kill_stale`, `pip_install`, `keepalive` |

```python
from patchcord import Controller, Worker, Policy

ctl = Controller()                    # cloudflared tunnel by default
join = ctl.start()                    # give this code to workers
ctl.syncer("/data/models", "models", Policy(extensions=(".safetensors",)))

Worker("w1", sync={"models": "/data/models"}, expose={"app": 8188}, join=join).start()
```

Try it without any network: `python examples/local_demo.py`. Tests: `python -m unittest discover -s tests` (about 40 s; the multicast test skips itself where multicast is blocked).

## On a LAN

`host` is where a node *listens*, `advertise_host` is what it *tells other machines*. 0.0.0.0 is never advertised:

```python
ctl = patchcord.Controller(tunnel="local", host="0.0.0.0")                           # address detected
ctl = patchcord.Controller(tunnel="local", host="0.0.0.0", advertise_host="192.168.1.10")   # or say it yourself
join = ctl.start()

patchcord.discover()                      # finds nodes by mDNS and the ones you registered; shows who is reachable
patchcord.discovery.add_host("192.168.1.20", 8080)    # multicast blocked (guest Wi-Fi, VLANs, VPN)? register by hand
patchcord.network.interfaces(); patchcord.network.local_ip()
ctl.check("gpu-01")                       # reachable? key accepted? can it connect back to the controller?
patchcord.doctor()                        # checks Python, ports, interfaces, mDNS, cloudflared, internet; hints per problem
```

`tunnel="local"` accepts plain `http://` addresses by default (it is a LAN mode). Finding a machine authorises nothing:
you still need its pairing code or the controller's join code.

## Worker lifecycle, events, resources

```python
w = patchcord.Worker("gpu-01", join=join, tunnel="local", host="0.0.0.0")
w.start()                                 # a second start() changes nothing; a failed start() rolls everything back
w.status, w.is_running, w.uptime          # "running", True, 93.4
w.reconnect()                             # fresh tunnels + register again, agent keeps running
w.restart(); w.stop()                     # restart keeps name, key and port

ctl.on("worker.connected", lambda e: print(e.worker, "is online"))     # also: worker.disconnected / removed / error,
ctl.on("transfer.completed", lambda e: print(e.worker, e.path))        #       transfer.started / failed, controller.started

for w in ctl.workers:
    print(w.name, w.online, w.stats["gpus"])
best = ctl.select_worker(gpu_required=True, min_vram=12000)           # None if no online worker has 12 GB free
```

A worker watches its own agent, tunnel and LAN address (`monitor_interval`) and reconnects with a growing delay
(`reconnect_delay`, `max_reconnect_attempts`, `auto_reconnect=False` to turn it off). Events: see `patchcord.help("events")`.

## Command line

```
patchcord doctor [--target JOIN_CODE_OR_URL] [--json]       why can't my worker connect?
patchcord discover                                          machines on this network
patchcord hosts add 192.168.1.20:8080                       register one by hand
patchcord check 192.168.1.20:8080                           can this machine reach that one?
patchcord status | workers                                  what is running here / what the controller knows
patchcord controller start --lan                            prints the join code
patchcord worker start gpu-01 --lan --join MJ1-...          (or --join - to read it from stdin, or PATCHCORD_JOIN)
patchcord version
```

`controller start` and `worker start` run until Ctrl-C or SIGTERM and then shut down cleanly.

## Built-in help

You can explore Patchcord directly from Python without opening the README:

```python
import patchcord

patchcord.help()                 # overview and quick start
patchcord.help("Controller")   # details for one class
patchcord.help("transfer")     # details for a module
patchcord.about()                # Python and platform information
patchcord.version()              # installed version
patchcord.examples()             # copyable examples
patchcord.list_transports()      # available tunnel providers
```

The standard Python documentation tools work too: `help(patchcord)` and
`help(patchcord.Controller)`. Use `dir(patchcord)` to inspect the public names.

## Sync behaviour
- Workers are synced in parallel, one thread each; a slow worker never holds up the others.
- A half-received file survives a worker restart: the receiver re-hashes the bytes it kept, and the sender continues from there.
  If those bytes were damaged, the final SHA-256 check fails, the partial is discarded, and the next pass starts that file clean.

## Security model
- Nodes listen on 127.0.0.1 by default (tunnels connect locally). For LAN use pass `host="0.0.0.0"` (or `--lan`): then anyone
  on that network can reach the node, so every endpoint except `/_mesh/health` needs the key, and codes must stay private.
  LAN mode is plain HTTP: use it on networks you trust. `POST /_mesh/reach` (connect-back test) only ever connects to the caller.
- mDNS announcements carry name, role, port and address, never a key.
- Every node has a random key (`X-Mesh-Key`, constant-time compare). `/_mesh/health` is the only open endpoint.
- Workers register with a separate **join token**, which only allows `POST /_mesh/register`; it is not a node key.
- Pairing addresses must be bare `https://` origins (`http://` only with `allow_insecure=True`); `allow_hosts` can pin hosts.
- Every path from the network goes through `Policy.check_path` before touching disk; files install only after the SHA-256 matches.
- On Windows, file permission bits do not apply, so the saved worker list (it holds keys) is only as private as your user folder.
- A worker's code contains its key. Anyone holding it can use that worker. Keep codes and join codes private.
- Quick tunnels have no SLA and a new URL each session; that is why `join=` re-registers automatically.

## Not in v1
App-level job orchestration (ComfyCluster's `pipeline.py`), a reverse proxy mode for non-HTTP-aware apps, and
adapters that mount the agent inside another framework (aiohttp/Flask). `Worker(expose=...)` covers the main case
by tunnelling the app's own port next to the agent.
