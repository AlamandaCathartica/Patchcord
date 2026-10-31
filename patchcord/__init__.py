"""Patchcord: connect machines into a small distributed network.

Patchcord provides node pairing, machine-to-machine communication, tunnels,
and resumable file synchronization.

Start here:
    import patchcord
    patchcord.help()

Something will not connect?
    patchcord.doctor()          # in a terminal: patchcord doctor
    patchcord.discover()        # machines on your network (mDNS + ones you registered by hand)

For detailed topics:
    patchcord.help("Controller")
    patchcord.help("Worker")
    patchcord.help("transfer")

The normal Python help system also works:
    help(patchcord)
    help(patchcord.Controller)
"""
__version__ = "0.2.0"

from . import auth, discovery, events, mdns, network, pairing, state, tunnel
from .agent import Agent, ApiError
from .discovery import discover
from .doctor import doctor
from .events import Emitter, Event
from .node import Controller, Worker
from .peer import Peer, PeerError
from .registry import Registry, WorkerInfo
from .transfer import Policy, Pusher, Receiver, SyncLoop
from .help import about, examples, help, list_transports, version

__author__ = "Patchcord contributors"
__license__ = "MIT"

__all__ = [
    "Agent", "ApiError", "Controller", "Emitter", "Event", "Peer", "PeerError", "Policy", "Pusher", "Receiver",
    "Registry", "SyncLoop", "Worker", "WorkerInfo",
    "about", "auth", "discover", "discovery", "doctor", "events", "examples", "help", "list_transports", "mdns",
    "network", "pairing", "state", "tunnel", "version",
]
