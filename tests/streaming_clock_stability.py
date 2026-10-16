"""Bounded real-time synthetic stream; actual RF/LR workers, no native capture.

Run explicitly, outside pytest. Never adjusts clocks or fabricates model receipts.
"""

import argparse
import asyncio
import json
import resource
import time
from datetime import UTC, datetime
from pathlib import Path

import tests.native_capture_verification_guard as guard
from soc_agent.security_ai.operational.network_capture.stream_session import StreamPolicy
from soc_agent.security_ai.research.stream_service import StreamingMonitoring
from tests.research_adapter_support import research_paths
from tests.streaming_network_support import real_time_source


async def run(output: Path, seconds: int) -> None:
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    owner = StreamingMonitoring(output, paths=research_paths())
    started, cpu = time.monotonic(), time.process_time()
    last_utc = datetime.now(UTC)
    adjustments = []
    samples = []
    await owner.start_fixture(
        real_time_source(owner, seconds), policy=StreamPolicy(seconds=seconds)
    )
    while not owner.task.done():
        now = datetime.now(UTC)
        if now < last_utc:
            adjustments.append((now - last_utc).total_seconds())
        last_utc = now
        samples.append(
            {
                "elapsed_monotonic": time.monotonic() - started,
                "utc": now.isoformat(),
                "queue": owner.store.queue.counts(),
                "metrics": dict(owner.metrics),
            }
        )
        try:
            await asyncio.wait_for(asyncio.shield(owner.task), 1)
        except TimeoutError:
            continue
    await owner.task
    snapshot = owner.snapshot()
    records = snapshot["research"]["records"]
    result = {
        "contract": "soc-streaming-clock-fixture-probe:v1",
        "source": "FIXTURE",
        "elapsed_monotonic": time.monotonic() - started,
        "cpu_seconds": time.process_time() - cpu,
        "peak_rss_bytes": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024,
        "utc_backward_samples": adjustments,
        "utc_sample_interval_seconds": 1,
        "state": snapshot["state"],
        "metrics": owner.metrics,
        "queue": owner.store.queue.counts(),
        "actual_inferences": len([r for r in records if r.get("receipt")]),
        "read_only_investigations": len([r for r in records if r.get("investigation")]),
        "worker_failures": len([r for r in records if r["status"] != "COMPLETE"]),
        "audit_digest": owner.store.runtime.verify_audit(),
        "operational_gate": snapshot["operational_gate"],
        "new_capture": False,
        "blocked_network_socket_attempts": guard.blocked,
    }
    (output / "samples.json").write_text(json.dumps(samples, indent=2) + "\n")
    (output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2), flush=True)
    assert result["elapsed_monotonic"] >= seconds
    assert result["state"] == "STOPPED", result
    assert result["actual_inferences"] == result["read_only_investigations"] == 2, result
    assert result["worker_failures"] == 0, result
    assert result["queue"] == {"DONE": 1}, result
    assert guard.blocked == 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--seconds", type=int, choices=range(40, 91), default=60)
    args = parser.parse_args()
    asyncio.run(run(args.output, args.seconds))
