"""Actual show-demo unified shell entry: mapped window, SIGINT and process exit twice."""

import ctypes as c
import json
import signal
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RELEASE = ROOT / "releases/evidence-demo-20261104"
OUTPUT = RELEASE / "docs/unified-validation"
x = c.CDLL("libX11.so.6")
x.XOpenDisplay.argtypes = [c.c_char_p]
x.XOpenDisplay.restype = c.c_void_p
x.XDefaultRootWindow.argtypes = [c.c_void_p]
x.XDefaultRootWindow.restype = c.c_ulong
x.XQueryTree.argtypes = [
    c.c_void_p,
    c.c_ulong,
    c.POINTER(c.c_ulong),
    c.POINTER(c.c_ulong),
    c.POINTER(c.POINTER(c.c_ulong)),
    c.POINTER(c.c_uint),
]
x.XFetchName.argtypes = [c.c_void_p, c.c_ulong, c.POINTER(c.c_char_p)]
x.XFree.argtypes = [c.c_void_p]
x.XCloseDisplay.argtypes = [c.c_void_p]
d = x.XOpenDisplay(None)
assert d
root = x.XDefaultRootWindow(d)


def find(window, depth=0):
    name = c.c_char_p()
    x.XFetchName(d, window, c.byref(name))
    match = name.value and name.value.decode(errors="replace") == "E2E Scenario Replay"
    if name:
        x.XFree(name)
    if match:
        return window
    if depth > 5:
        return None
    r = c.c_ulong()
    p = c.c_ulong()
    children = c.POINTER(c.c_ulong)()
    n = c.c_uint()
    if not x.XQueryTree(d, window, c.byref(r), c.byref(p), c.byref(children), c.byref(n)):
        return None
    try:
        for i in range(n.value):
            found = find(children[i], depth + 1)
            if found:
                return found
    finally:
        if children:
            x.XFree(children)


checks = []
for round in (1, 2):
    assert not find(root), "PREEXISTING_DEMO_WINDOW"
    started = time.monotonic()
    with (OUTPUT / f"terminal-{round}.log").open("w") as log:
        p = subprocess.Popen(
            [str(RELEASE / "show-demo"), "unified"],
            cwd=ROOT,
            stdout=log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        deadline = time.monotonic() + 30
        while not find(root):
            assert p.poll() is None, "CLI_EXIT_BEFORE_WINDOW"
            if time.monotonic() > deadline:
                raise RuntimeError("GUI_NOT_MAPPED")
            time.sleep(0.1)
        mapped = time.monotonic()
        time.sleep(1)  # Let initial Tk callbacks and signal-handler installation complete.
        p.send_signal(signal.SIGINT)
        rc = p.wait(timeout=15)
    assert rc == 0 and not find(root)
    checks.append(
        dict(
            round=round,
            command="./releases/evidence-demo-20261104/show-demo unified",
            gui_window_observed=True,
            stop="SIGINT equivalent Ctrl+C",
            returncode=rc,
            pid_absent=not Path(f"/proc/{p.pid}").exists(),
            mapped_seconds=mapped - started,
            total_seconds=time.monotonic() - started,
        )
    )
x.XCloseDisplay(d)
(OUTPUT / "terminal-checks.json").write_text(json.dumps(checks, indent=2) + "\n")
print(checks)
