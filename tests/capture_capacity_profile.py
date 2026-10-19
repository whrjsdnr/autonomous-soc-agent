"""Fresh-process, non-privileged calibration stages. No Native capacity claim."""

import argparse
import asyncio
import json
import math
import os
import platform
import resource
import socket
import sys
import tempfile
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

from tests import native_capture_verification_guard as guard
from tests.research_adapter_support import research_paths
from tests.streaming_network_support import packet
from tests.unit.live_network.test_parity import request
from tests.unit.network_capture.test_packets import dns, frame
from tests.unit.network_capture.test_packets import packet as parsed


def measure(action, repeats, warmup):
    for _ in range(warmup):
        action()
    samples = []

    def rss():
        return int(Path("/proc/self/statm").read_text().split()[1]) * os.sysconf("SC_PAGE_SIZE")

    peak = [rss()]
    stopped = threading.Event()

    def sample():
        while not stopped.wait(0.01):
            peak[0] = max(peak[0], rss())

    sampler = threading.Thread(target=sample)
    sampler.start()
    cpu, start = time.process_time(), time.monotonic()
    try:
        for _ in range(repeats):
            before = time.perf_counter()
            action()
            samples.append(time.perf_counter() - before)
        elapsed, cpu = time.monotonic() - start, time.process_time() - cpu
    finally:
        stopped.set()
        sampler.join()
    peak[0] = max(peak[0], rss())
    ordered = sorted(samples)
    return dict(
        repetitions=repeats,
        warmup=warmup,
        latency_seconds={str(q): ordered[math.ceil(q * repeats) - 1] for q in (0.5, 0.95, 0.99)},
        throughput_per_second=repeats / elapsed,
        elapsed_seconds=elapsed,
        controller_cpu_seconds=cpu,
        controller_cpu_fraction=cpu / elapsed,
        peak_rss_bytes=peak[0],
        process_lifetime_peak_rss_bytes=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024,
        queue_depth=None,
        errors=0,
    )


def stage(name, directory):
    from soc_agent.security_ai.operational.network_capture.isolated_flow import IsolatedFlows
    from soc_agent.security_ai.operational.network_capture.parsing import dns_message
    from soc_agent.security_ai.research.adapter import ResearchAdapter
    from soc_agent.security_ai.research.live_input import produce

    paths = research_paths()
    sys.path.insert(0, str((paths.producer_source or paths.ml) / "src"))
    body, metadata = frame(), parsed(frame())
    fake = SimpleNamespace(session=SimpleNamespace(interface_id="a" * 64))
    if name == "raw_parsing":
        return measure(lambda: parsed(body), 2000, 100)
    if name == "dns_extraction":
        return measure(lambda: dns_message(dns(), retain_name=False), 2000, 100)
    message = dict(
        kind="PACKET",
        session_id="00000000-0000-0000-0000-000000000001",
        sequence=1,
        counter_sequence=2,
        dns_queries=1,
        dns_responses=0,
        dns_parse_failures=0,
    )

    def serialize():
        return json.dumps({**message, "packet": metadata.model_dump(mode="json")}).encode()

    if name == "serialization":
        return measure(serialize, 2000, 100)
    if name == "transport_validation":
        from soc_agent.security_ai.operational.network_capture.stream_transport import StreamMessage

        payload = serialize()
        return measure(lambda: StreamMessage.model_validate_json(payload), 2000, 100)
    if name == "unix_transfer":
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        try:
            payload = serialize()

            def transfer():
                left.sendall(payload)
                assert right.recv(8192) == payload

            return measure(transfer, 2000, 100)
        finally:
            left.close()
            right.close()
    if name == "aggregation":
        inputs = iter([packet(fake, i / 100, flags=16) for i in range(2100)])
        flows = IsolatedFlows()
        return measure(lambda: flows.add(next(inputs), uuid4()), 2000, 100)
    if name == "network14":
        q = request(native=False)
        return measure(lambda: produce(q), 500, 10)
    if name == "sqlite":
        from soc_agent.security_ai.operational.network_capture.stream_session import StreamPolicy
        from soc_agent.security_ai.operational.network_capture.total_session import prepare
        from soc_agent.security_ai.research.stream_store import StreamStore

        session_dir = directory / "session"
        session = prepare(session_dir, StreamPolicy())
        store = StreamStore(session_dir, session, fixture=True, create=True)
        owner = SimpleNamespace(session=session)
        flows = IsolatedFlows()
        completed = []
        for port in range(1000, 1033):
            for t in (0, 0.5, 31):
                completed.extend(flows.add(packet(owner, t, port=port), uuid4()))
        items = iter(completed)

        def commit():
            store.commit(next(items), (1, 4))
            store.finish(store.queue.claim(), "PROFILE_NO_MODEL")

        return measure(commit, 30, 3)
    if name in ("quality", "edge", "investigation"):
        adapter = ResearchAdapter(directory, paths=paths, live_metadata=True, transient_inputs=True)
        receipts = []

        def infer():
            q = request(native=False).model_copy(
                update={"profile": "edge" if name == "edge" else "quality"}
            )
            result = asyncio.run(adapter.infer(q))
            assert result["status"] == "SUCCESS", result
            receipts.append(result["receipt"])

        if name != "investigation":
            result = measure(infer, 3, 1)
            result["worker_resources"] = [
                {
                    k: r[k]
                    for k in (
                        "worker_peak_rss_bytes",
                        "worker_cpu_seconds",
                        "inference_latency_ms",
                        "artifact_digest",
                        "feature_digest",
                    )
                }
                for r in receipts
            ]
            return result
        infer()  # Actual trusted RF receipt, excluded from investigation timing.
        from soc_agent.security_ai.external.runtime_store import RuntimeGovernanceStore
        from soc_agent.security_ai.research.investigation import investigate
        from soc_agent.security_ai.research.models import parse_receipt

        store = RuntimeGovernanceStore.create_isolated(directory / "soc")
        receipt = parse_receipt(receipts[-1])

        def investigate_once():
            result = asyncio.run(
                investigate(
                    RuntimeGovernanceStore(directory / "soc/external-validation.sqlite"),
                    receipt,
                    uuid4(),
                )
            )
            assert result["status"] == "ASSESSED_READ_ONLY"

        return measure(investigate_once, 3, 1)
    if name == "gui":
        import tkinter as tk

        from soc_agent.gui.app import Desktop
        from soc_agent.gui.backend import GUIConfig
        from tests.gui_wslg_checks import close, idle

        root = tk.Tk()
        app = Desktop(root, GUIConfig(data_directory=directory))

        async def run():
            try:
                await idle(root, app)
                app.navigate("Total Monitoring")
                snapshot = app.worker.backend.total_monitoring.snapshot()

                def render():
                    app.live_view.render(snapshot)
                    root.update_idletasks()

                result = measure(render, 50, 10)
                result["input"] = "ACTUAL_WSLG_EMPTY_STOPPED_STATE_NO_FAKE_LIVE_DATA"
                return result
            finally:
                await close(root, app)

        return asyncio.run(run())
    raise ValueError("UNKNOWN_STAGE")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--stage", required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    with tempfile.TemporaryDirectory(prefix="soc-capacity-stage-") as directory:
        result = stage(args.stage, Path(directory))
    assert guard.blocked == 0
    args.output.write_text(
        json.dumps(
            dict(
                stage=args.stage,
                scope="FIXTURE_NOT_NATIVE",
                python=platform.python_version(),
                kernel=platform.release(),
                result=result,
            ),
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
