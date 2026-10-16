"""Five-minute paced synthetic fixture with actual RF/LR; no network socket/capture."""

import asyncio
import json
import sys
import tempfile
import time
from pathlib import Path

from soc_agent.security_ai.research.stream_service import StreamingMonitoring
from tests import native_capture_verification_guard as guard
from tests.research_adapter_support import research_paths
from tests.streaming_network_support import packet
from tests.total_monitoring_support import dns_packet


async def main(output):
    with tempfile.TemporaryDirectory(prefix="soc-total-soak-") as directory:
        owner = StreamingMonitoring(Path(directory), total=True, paths=research_paths())
        samples = []

        async def source():
            started = time.monotonic()
            tick = 0
            while time.monotonic() - started < 300:
                t = time.monotonic() - started
                cycle, phase = divmod(tick, 45)
                yield packet(owner, t, port=3000, flags=16)
                if phase in (0, 1, 2):
                    yield packet(
                        owner,
                        t,
                        port=10000 + cycle,
                        reverse=phase == 1,
                        length=40 + phase * 20,
                        flags=(2, 16, 1)[phase],
                    )
                if tick % 10 == 0:
                    yield dns_packet(owner, t)
                    yield dns_packet(owner, t + 0.001, response=True)
                samples.append(dict(elapsed=t, network=dict(owner.metrics)))
                tick += 1
                await asyncio.sleep(1)

        started = time.monotonic()
        await owner.start_fixture(source())
        await owner.task
        snapshot = owner.snapshot()
        result = dict(
            elapsed_monotonic=time.monotonic() - started,
            origin="FIXTURE_NO_CAPTURE",
            samples=samples,
            final=snapshot,
            audit_digest=owner.store.runtime.verify_audit(),
            network_socket_attempts_blocked=guard.blocked,
        )
        # No paths, raw packets, addresses or receipts are needed in resource evidence.
        result["final"].pop("research", None)
        output.write_text(json.dumps(result, indent=2))
        assert snapshot["network"]["finalization"] == "VERIFIED", owner.last_error
        assert snapshot["network"]["inference_count"] > 0
        assert snapshot["network"]["retained_metadata_bytes"] == 0
        assert snapshot["network"]["queue_backlog"] == 0


if __name__ == "__main__":
    asyncio.run(main(Path(sys.argv[1])))
