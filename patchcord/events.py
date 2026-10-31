"""A tiny event system, so applications react to changes instead of polling for them.

    controller.on("worker.connected", lambda e: print(e.worker, "is online"))

    @controller.on("transfer.completed")             # decorator form
    def done(event):
        print(event.worker, event.path)

Handlers receive one `Event`: `event.name`, `event.time`, `event.data` (a dict), and every key of the data is also
an attribute (`event.worker`). Handlers run in the thread that raised the event, one after another, so keep them
quick; an exception in a handler is logged and never stops Patchcord. `"*"` subscribes to every event.

Controller events
    controller.started / controller.stopped
    worker.connected / worker.disconnected / worker.removed     worker=name (+ url)
    worker.error                                                 worker=name, error=text
    transfer.started / transfer.completed / transfer.failed     worker, channel, path, size (+ error)

Worker events
    worker.started / worker.stopped
    worker.connected / worker.disconnected                       reason=...
    worker.reconnecting / worker.registered / worker.error
    transfer.completed                                           channel, path, size
"""
import threading
import time


class Event:
    def __init__(self, name, data=None):
        self.name, self.data, self.time = name, dict(data or {}), time.time()

    def __getattr__(self, item):
        try:
            return self.__dict__["data"][item]
        except KeyError:
            raise AttributeError(item) from None

    def __repr__(self):
        return f"Event({self.name!r}, {self.data!r})"


class Emitter:
    """Mixin that gives an object on() / once() / off() / emit()."""

    def _events_init(self):
        if "_handlers" not in self.__dict__:
            self._handlers, self._handlers_lock = {}, threading.Lock()

    def on(self, event, handler=None):
        """Subscribe `handler` to `event`. Without a handler this returns a decorator. Returns the handler."""
        self._events_init()
        if handler is None:
            return lambda fn: self.on(event, fn)
        if not callable(handler):
            raise TypeError("handler must be callable")
        with self._handlers_lock:
            self._handlers.setdefault(event, []).append((handler, False))
        return handler

    def once(self, event, handler=None):
        """Like on(), but the handler is removed after it has run once."""
        self._events_init()
        if handler is None:
            return lambda fn: self.once(event, fn)
        with self._handlers_lock:
            self._handlers.setdefault(event, []).append((handler, True))
        return handler

    def off(self, event, handler=None):
        """Remove one handler, or every handler of `event` when none is given."""
        self._events_init()
        with self._handlers_lock:
            if handler is None:
                self._handlers.pop(event, None)
            else:
                self._handlers[event] = [h for h in self._handlers.get(event, []) if h[0] is not handler]

    def emit(self, event, **data):
        """Raise an event. Returns the number of handlers that ran."""
        self._events_init()
        ev = Event(event, data)
        with self._handlers_lock:
            todo = list(self._handlers.get(event, [])) + list(self._handlers.get("*", []))
            for key in (event, "*"):
                if key in self._handlers:
                    self._handlers[key] = [h for h in self._handlers[key] if not h[1]]
        for fn, _ in todo:
            try:
                fn(ev)
            except Exception as e:  # noqa: BLE001  (an application's handler must never break the network code)
                log = getattr(self, "log", print)
                log(f"[mesh] event handler for {event!r} raised {type(e).__name__}: {e}")
        return len(todo)
