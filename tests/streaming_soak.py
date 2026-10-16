"""Explicit wall-clock fixture soak. No native capture or synthetic model receipt."""

import argparse
import asyncio
import hashlib
import json
import time
from pathlib import Path

import tests.native_capture_verification_guard as guard
from soc_agent.security_ai.operational.network_capture.stream_session import StreamPolicy
from soc_agent.security_ai.research.stream_service import StreamingMonitoring
from tests.research_adapter_support import research_paths
from tests.streaming_network_support import UnknownMockAdapter, real_time_source


async def run(output: Path, seconds: int):
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    owner = StreamingMonitoring(output, paths=research_paths())
    adapter = UnknownMockAdapter()
    hashes = {
        str(p): hashlib.sha256(p.read_bytes()).hexdigest()
        for folder in (
            "src/soc_agent/security_ai/research",
            "src/soc_agent/security_ai/operational/network_capture",
        )
        for p in Path(folder).glob("*.py")
    }
    started = time.monotonic()
    await owner.start_fixture(
        real_time_source(owner, seconds),
        policy=StreamPolicy(seconds=seconds, max_inferences=256),
        model_adapter=adapter,
    )
    with (output / "samples.jsonl").open("x") as stream:
        while not owner.task.done():
            sample = dict(
                elapsed_seconds=time.monotonic() - started, state=owner.state, **owner.metrics
            )
            stream.write(json.dumps(sample, allow_nan=False) + "\n")
            stream.flush()
            try:
                await asyncio.wait_for(asyncio.shield(owner.task), 30)
            except TimeoutError:
                continue
    await owner.task
    snapshot = owner.snapshot()
    result = dict(
        contract="soc-streaming-fixture-soak:v1",
        elapsed_seconds=time.monotonic() - started,
        requested_seconds=seconds,
        source_sha256=hashes,
        state=snapshot["state"],
        metrics=owner.metrics,
        queue=owner.store.queue.counts(),
        audit_digest=owner.store.runtime.verify_audit(),
        actual_model_inferences=0,
        mock_unknown_calls=adapter.calls,
        retained_input_files=len(list((owner.directory / "inputs").glob("*"))),
        active_metadata_bytes=owner.aggregator.bytes,
        operational_gate=snapshot["operational_gate"],
        no_capture=True,
        network_socket_attempts=guard.blocked,
    )
    (output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2), flush=True)
    assert result["state"] == "STOPPED", result
    assert result["elapsed_seconds"] >= seconds
    assert result["queue"].get("PENDING", 0) == 0
    assert result["active_metadata_bytes"] == result["retained_input_files"] == 0
    assert guard.blocked == 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--seconds", type=int, default=1800, choices=range(1, 1801))
    args = parser.parse_args()
    asyncio.run(run(args.output, args.seconds))
