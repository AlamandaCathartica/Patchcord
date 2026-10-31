"""Built-in help and project information for Patchcord.

These helpers are intentionally dependency-free and safe to call from a
Python REPL, notebook, or script.
"""
from __future__ import annotations

import importlib
import inspect
import platform
import shutil
import sys
import textwrap

from . import __version__


BANNER = r""" ____          __           __                              __     
/\  _`\       /\ \__       /\ \                            /\ \    
\ \ \L\ \ __  \ \ ,_\   ___\ \ \___     ___    ___   _ __  \_\ \   
 \ \ ,__/'__`\ \ \ \/  /'___\ \  _ `\  /'___\ / __`\/\`'__\/'_` \  
  \ \ \/\ \L\.\_\ \ \_/\ \__/\ \ \ \ \/\ \__//\ \L\ \ \ \//\ \L\ \ 
   \ \_\ \__/.\_\\ \__\ \____\\ \_\ \_\ \____\ \____/\ \_\\ \___,_\
    \/_/\/__/\/_/ \/__/\/____/ \/_/\/_/\/____/\/___/  \/_/ \/__,_"""


_TOPICS = {
    "controller": ("class", "patchcord.node", "Controller",
                   "Manage workers, pairing, and file synchronization."),
    "worker": ("class", "patchcord.node", "Worker",
               "Run a machine as a worker and connect it to a controller."),
    "agent": ("class", "patchcord.agent", "Agent",
              "HTTP server that exposes health, stats, logs, routes, and RPC."),
    "peer": ("class", "patchcord.peer", "Peer",
             "Client for sending requests to another Patchcord node."),
    "registry": ("class", "patchcord.registry", "Registry",
                 "Store, inspect, and monitor paired workers."),
    "policy": ("class", "patchcord.transfer", "Policy",
               "Rules for which files may be synchronized."),
    "pusher": ("class", "patchcord.transfer", "Pusher",
               "Send files from a local folder to a remote worker."),
    "receiver": ("class", "patchcord.transfer", "Receiver",
                 "Receive and verify files from a remote controller."),
    "syncloop": ("class", "patchcord.transfer", "SyncLoop",
                 "Run file synchronization repeatedly in the background."),
    "transfer": ("module", "patchcord.transfer", None,
                 "Resumable, chunked, SHA-256-verified file synchronization."),
    "pairing": ("module", "patchcord.pairing", None,
                "Create, parse, and validate worker and controller join codes."),
    "tunnel": ("module", "patchcord.tunnel", None,
               "Expose a local service through a tunnel or LAN address."),
    "auth": ("module", "patchcord.auth", None,
             "Authentication key helpers used by Patchcord nodes."),
    "colab": ("module", "patchcord.colab", None,
              "Helpers for launching and managing Patchcord in Colab/Jupyter."),
    "network": ("module", "patchcord.network", None,
                "Network interfaces, the address to advertise, and connection checks."),
    "discovery": ("module", "patchcord.discovery", None,
                  "Find other Patchcord machines (mDNS plus machines registered by hand)."),
    "mdns": ("module", "patchcord.mdns", None,
             "Small standard-library mDNS / DNS-SD announcer and browser."),
    "events": ("module", "patchcord.events", None,
               "React to worker.connected, transfer.completed and other events."),
    "doctor": ("module", "patchcord.doctor", None,
               "patchcord.doctor(): find out why a machine cannot connect."),
    "cli": ("module", "patchcord.cli", None,
            "The `patchcord` command."),
    "agent.request": ("class", "patchcord.agent", "Request",
                      "Read request bodies, JSON, query parameters, and route parameters."),
    "apierror": ("class", "patchcord.agent", "ApiError",
                 "Return a controlled HTTP error from a custom route or RPC."),
    "peererror": ("class", "patchcord.peer", "PeerError",
                  "Exception raised when a remote request fails."),
}

_ALIASES = {
    "controller": "controller", "controllers": "controller",
    "worker": "worker", "workers": "worker",
    "node": "worker",
    "agent": "agent", "server": "agent",
    "peer": "peer", "client": "peer",
    "registry": "registry", "workers list": "registry",
    "policy": "policy", "sync policy": "policy",
    "pusher": "pusher", "sender": "pusher",
    "receiver": "receiver",
    "syncloop": "syncloop", "sync loop": "syncloop",
    "transfer": "transfer", "file transfer": "transfer", "sync": "transfer",
    "pairing": "pairing", "pair": "pairing",
    "tunnel": "tunnel", "tunneling": "tunnel",
    "auth": "auth", "authentication": "auth",
    "colab": "colab", "jupyter": "colab",
    "network": "network", "lan": "network", "discover": "discovery", "discovery": "discovery",
    "mdns": "mdns", "events": "events", "event": "events", "doctor": "doctor", "diagnostics": "doctor",
    "cli": "cli", "command": "cli",
    "request": "agent.request",
    "apierror": "apierror", "peererror": "peererror",
}


def _resolve(topic):
    key = str(topic).strip().lower()
    key = _ALIASES.get(key, key)
    if key not in _TOPICS:
        choices = ", ".join(sorted(_TOPICS))
        raise ValueError("Unknown Patchcord help topic {!r}. Available topics: {}".format(topic, choices))
    kind, module_name, object_name, description = _TOPICS[key]
    module = importlib.import_module(module_name)
    obj = getattr(module, object_name) if kind == "class" else module
    return key, obj, description


def help(topic=None, *, file=None):
    """Show the Patchcord guide or detailed help for one class/module.

    Examples:
        patchcord.help()
        patchcord.help("Controller")
        patchcord.help("transfer")
        patchcord.help("Worker")
    """
    if topic is None:
        output = """
        PATCHCORD {version}
        Lightweight distributed networking for Python

        GET STARTED
          Controller   Manage connected workers
          Worker       Run a machine and connect it to a controller

        CORE CLASSES
          Agent        HTTP server, custom routes, and RPC
          Peer         Send requests to another node
          Registry     Keep track of paired workers

        FILE TRANSFER
          Policy       Configure allowed files and transfer behavior
          Pusher       Send files to workers
          Receiver     Receive and verify files
          SyncLoop     Repeat synchronization in the background

        MODULES
          pairing      Pairing codes and controller join codes
          tunnel       Tunnel providers (cloudflared and local)
          auth         Authentication helpers
          colab        Colab and Jupyter helpers
          network      Interfaces, advertised address, connection checks
          discovery    Find machines on your network (also: patchcord.discover())
          events       controller.on("worker.connected", ...)
          doctor       Why can't my machine connect? (also: patchcord.doctor())

        EXAMPLES
          patchcord.help("Controller")
          patchcord.help("Worker")
          patchcord.help("transfer")
          patchcord.help("pairing")

        QUICK START
          import patchcord

          controller = patchcord.Controller(tunnel="local")
          join_code = controller.start()
          print(join_code)

        MORE
          patchcord.about()
          patchcord.version()
          patchcord.examples()
          patchcord.list_transports()
          help(patchcord.Controller)
        """.format(version=__version__)
        print(BANNER, file=file)
        print(textwrap.dedent(output).strip(), file=file)
        return

    try:
        key, obj, description = _resolve(topic)
    except ValueError as exc:
        print(str(exc), file=file)
        return

    print(BANNER, file=file)
    title = key.upper()
    doc = inspect.getdoc(obj) or description
    try:
        signature = str(inspect.signature(obj))
    except (TypeError, ValueError):
        signature = ""

    print("{}\n{}\n{}".format(title, "=" * len(title), description), file=file)
    if signature:
        print("\nSignature: {}{}".format(getattr(obj, "__name__", title), signature), file=file)
    print("\n{}".format(doc), file=file)

    if key == "controller":
        print("""
COMMON USAGE
  controller = patchcord.Controller(tunnel="local")
  join_code = controller.start()
  worker_info = controller.registry.snapshot()
  controller.stop()

TIP
  Use tunnel="local" for machines that can reach each other over your LAN.
  Use the default cloudflared tunnel when a public tunnel is needed.
""".rstrip(), file=file)
    elif key == "worker":
        print("""
COMMON USAGE
  worker = patchcord.Worker("gpu-01", join=join_code, tunnel="local")
  worker.start()
  worker.stop()

TIP
  A worker can receive synchronized folders with the sync argument.
""".rstrip(), file=file)
    elif key == "transfer":
        print("""
QUICK EXAMPLE
  # On the worker:
  receiver = patchcord.Receiver("/data/models", channel="models")
  receiver.attach(agent)

  # On the controller:
  pusher = patchcord.Pusher("/local/models", channel="models")
  result = pusher.sync(peer)

NOTE
  Transfer is one-way: files are pushed to the receiver. The receiver does
  not automatically delete files that are absent from the source.
""".rstrip(), file=file)


def version():
    """Print and return the installed Patchcord version."""
    value = "Patchcord {}".format(__version__)
    print(value)
    return __version__


def about():
    """Print basic project and runtime information."""
    info = {
        "name": "Patchcord",
        "version": __version__,
        "python": platform.python_version(),
        "implementation": platform.python_implementation(),
        "platform": platform.platform(),
        "runtime_dependencies": "None (Python standard library)",
    }
    print(BANNER)
    print("PATCHCORD")
    print("---------")
    for key, value in info.items():
        print("{:<22} {}".format(key.replace("_", " ").title() + ":", value))
    return info


def examples():
    """Print small, copyable examples for common Patchcord tasks."""
    content = """
    PATCHCORD EXAMPLES

    1. Start a controller
       import patchcord
       controller = patchcord.Controller(tunnel="local")
       join_code = controller.start()
       print(join_code)

    2. Start a worker
       import patchcord
       worker = patchcord.Worker("worker-01", join=join_code, tunnel="local")
       worker.start()

    3. Talk to a worker
       peer = patchcord.Peer("http://192.168.1.20:8000", key="NODE_KEY")
       print(peer.health())
       print(peer.stats())

    4. Register a custom RPC
       agent = patchcord.Agent("worker-01", key="NODE_KEY")

       @agent.rpc("add")
       def add(a, b):
           return a + b

       agent.start()
       # From a connected peer: peer.call("add", a=2, b=3)

    5. Configure file synchronization
       policy = patchcord.Policy(
           extensions=(".safetensors", ".ckpt"),
           chunk=8 * 1024 * 1024,
       )
       worker = patchcord.Worker(
           "worker-01",
           sync={"models": "/data/models"},
           policy=policy,
       )
    """
    print(textwrap.dedent(content).strip())


def list_transports():
    """Print and return the tunnel providers currently built into Patchcord.

    The returned names are tunnel providers, not general HTTP transports.
    """
    providers = ("cloudflared", "local")
    print("Available tunnel providers:")
    for name in providers:
        if name == "cloudflared":
            detail = "Public HTTPS tunnel (requires cloudflared; Patchcord can download it)"
        else:
            detail = "Direct local/LAN address; no external tunnel"
        print("  {:<14} {}".format(name, detail))
    return list(providers)
