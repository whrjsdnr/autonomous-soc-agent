"""Explicit WSLg idle profiling. No authentication, capture, model inference or traffic.

Run the same file/interpreter against two PYTHONPATH exports. Startup includes
imports and the first completed backend projection; idle callbacks are measured
in Tk mainloop rather than by a synthetic busy update loop.
"""

import argparse
import asyncio
import json
import os
import socket
import sys
import tempfile
import threading
import time
from pathlib import Path


def no_capture(event, args):
    if event == "socket.__new__" and args[1] in (socket.AF_PACKET, socket.AF_INET, socket.AF_INET6):
        raise PermissionError("PROFILE_NETWORK_DISABLED")


def memory():
    values = {}
    for line in Path("/proc/self/status").read_text().splitlines():
        if line.startswith(("VmRSS:", "VmHWM:")):
            key, value, _ = line.split()
            values[key.rstrip(":")] = int(value) * 1024
    return values


def children():
    ids = set()
    for task in Path("/proc/self/task").iterdir():
        try:
            ids.update(map(int, (task / "children").read_text().split()))
        except FileNotFoundError:
            continue
    return sorted(ids)


def run(mode, seconds, active=False):
    started, cpu = time.monotonic(), time.process_time()
    import tkinter as tk

    from soc_agent.gui.backend import GUIConfig

    if mode == "operator":
        from soc_agent.gui.production import Desktop
    else:
        from soc_agent.gui.app import Desktop

    with tempfile.TemporaryDirectory(prefix="soc-profile-") as temp:
        root = tk.Tk()
        config = GUIConfig(
            data_directory=Path(temp) / "gui",
            native_python=Path(os.environ["SOC_PROFILE_NATIVE_PYTHON"])
            if os.getenv("SOC_PROFILE_NATIVE_PYTHON")
            else None,
            artifacts=Path(os.environ["SOC_PROFILE_ARTIFACTS"])
            if os.getenv("SOC_PROFILE_ARTIFACTS")
            else None,
        )
        app = Desktop(root, config)
        deadline = time.monotonic() + 90
        try:
            while time.monotonic() < deadline:
                root.update()
                if app.startup_complete and not app.busy:
                    break
                time.sleep(0.01)
            if not app.startup_complete or app.busy:
                raise RuntimeError("PROFILE_STARTUP_TIMEOUT")
            ready, startup_cpu = time.monotonic(), time.process_time() - cpu
            before = memory()
            responses = []
            for _ in range(20):
                at = time.monotonic_ns()
                root.after(0, lambda t=at: responses.append((time.monotonic_ns() - t) / 1e6))
                root.update()

            def widget_count(w):
                return 1 + sum(widget_count(c) for c in w.winfo_children())

            count = widget_count(root)
            callbacks = []
            original = app._drain

            def drain():
                callbacks.append(time.monotonic())
                return original()

            app._drain = drain

            async def tasks():
                return max(0, len(asyncio.all_tasks()) - 1)

            active_tasks = asyncio.run_coroutine_threadsafe(tasks(), app.worker.loop).result(2)
            idle_start, idle_cpu = time.monotonic(), time.process_time()
            root.after(int(seconds * 1000), root.quit)
            root.mainloop()
            elapsed, consumed = time.monotonic() - idle_start, time.process_time() - idle_cpu
            result = {
                "scope": "ACTUAL_WSLG_IDLE_NO_CAPTURE_NO_INFERENCE",
                "mode": mode,
                "startup_seconds": ready - started,
                "startup_cpu_seconds": startup_cpu,
                "idle_rss_bytes": before["VmRSS"],
                "process_image_peak_rss_bytes": before["VmHWM"],
                "idle_seconds": elapsed,
                "idle_cpu_seconds": consumed,
                "idle_cpu_one_core_percent": consumed / elapsed * 100,
                "response_p50_ms": sorted(responses)[10],
                "response_p95_ms": sorted(responses)[18],
                "widgets": count,
                "threads": len(threading.enumerate()),
                "background_async_tasks": active_tasks,
                "idle_child_processes": len(children()),
                "backend_completion_polls_per_second": len(callbacks) / elapsed,
                "model_service_created": app.worker.backend.model_service is not None,
                "model_deserializations": "UNKNOWN_NOT_INSTRUMENTED",
                "created_runtime_owners": len(getattr(app.worker.backend, "_owners", {}))
                if hasattr(app.worker.backend, "_owners")
                else 6,
            }
            if active:
                available = (
                    int(Path("/proc/meminfo").read_text().split("MemAvailable:")[1].split()[0])
                    * 1024
                )
                if available < 2 * 1024**3:
                    raise RuntimeError("PROFILE_MODEL_MEMORY_HEADROOM_REQUIRED")
                from soc_agent.security_ai.operational.network_capture.calibrated_policy import (
                    policy,
                )
                from tests.research_adapter_support import research_paths
                from tests.streaming_network_support import idle_source

                async def fixture():
                    owner = app.worker.backend.total_monitoring
                    owner.paths = research_paths()
                    await owner.start_fixture(idle_source(owner), policy=policy("balanced-v2"))
                    await asyncio.wait_for(owner.task, 40)
                    return owner.snapshot()

                active_start = time.monotonic()
                future = asyncio.run_coroutine_threadsafe(fixture(), app.worker.loop)
                peak_gui = peak_tree = maximum_children = 0
                while not future.done() and time.monotonic() - active_start < 45:
                    rss = memory()["VmRSS"]
                    owned = children()
                    tree_rss = rss
                    for pid in owned:
                        try:
                            tree_rss += (
                                int(
                                    Path(f"/proc/{pid}/status")
                                    .read_text()
                                    .split("VmRSS:")[1]
                                    .split()[0]
                                )
                                * 1024
                            )
                        except (OSError, IndexError, ValueError):
                            continue
                    peak_gui, peak_tree = max(peak_gui, rss), max(peak_tree, tree_rss)
                    maximum_children = max(maximum_children, len(owned))
                    root.update()
                    time.sleep(0.02)
                snapshot = future.result(1)
                assert snapshot["network"]["finalization"] == "VERIFIED"
                assert snapshot["network"]["inference_count"] == 2
                assert snapshot["network"]["queue_backlog"] == 0
                result["active_fixture"] = {
                    "scope": "ACTUAL_RF_LR_SAME_FOUR_SYNTHETIC_PACKETS_NOT_NATIVE",
                    "elapsed_seconds": time.monotonic() - active_start,
                    "sampled_peak_gui_rss_bytes": peak_gui,
                    "sampled_peak_subtree_rss_bytes": peak_tree,
                    "maximum_owned_child_processes": maximum_children,
                    "final_queue_backlog": snapshot["network"]["queue_backlog"],
                    "inference_queue": snapshot["network"]["inference_queue"],
                    "finalization": snapshot["network"]["finalization"],
                    "audit_integrity": snapshot["runtime_audit_integrity"],
                    "models": [
                        {
                            key: r["receipt"][key]
                            for key in (
                                "profile",
                                "artifact_digest",
                                "feature_values",
                                "prediction",
                                "score",
                                "inference_latency_ms",
                            )
                        }
                        for r in snapshot["research"]["records"]
                    ],
                }
        finally:
            app.close()
            while app.worker.thread.is_alive() and time.monotonic() < deadline:
                root.update()
                time.sleep(0.01)
        result["gui_worker_stopped"] = not app.worker.thread.is_alive()
        result["remaining_child_processes"] = len(children())
        return result


if __name__ == "__main__":
    sys.addaudithook(no_capture)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("operator", "developer"), required=True)
    parser.add_argument("--idle-seconds", type=float, default=3)
    parser.add_argument("--active-fixture", action="store_true")
    args = parser.parse_args()
    if os.geteuid() == 0 or not 1 <= args.idle_seconds <= 30:
        raise SystemExit("PROFILE_UNPRIVILEGED_BOUNDED_RUN_REQUIRED")
    print(json.dumps(run(args.mode, args.idle_seconds, args.active_fixture), sort_keys=True))
