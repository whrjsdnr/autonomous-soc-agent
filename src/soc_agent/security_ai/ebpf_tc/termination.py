"""Signal-only cleanup boundary: no model, network, collector or privilege imports."""

import signal
import threading
from contextlib import contextmanager


class SupervisorTermination(KeyboardInterrupt):
    """A real terminal/process signal, never successful collector completion."""

    def __init__(self, signum: int):
        self.signum = signum
        super().__init__("SUPERVISOR_SIGNAL_" + signal.Signals(signum).name)


@contextmanager
def termination_boundary():
    """Unwind through the existing cleanup once; a second signal cannot skip it."""
    if threading.current_thread() is not threading.main_thread():
        raise ValueError("SUPERVISOR_MAIN_THREAD_REQUIRED")
    requested = False

    def stop(signum, _frame):
        nonlocal requested
        if not requested:
            requested = True
            raise SupervisorTermination(signum)

    previous = {sig: signal.getsignal(sig) for sig in (signal.SIGTERM, signal.SIGINT)}
    try:
        for sig in previous:
            signal.signal(sig, stop)
        yield
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)
