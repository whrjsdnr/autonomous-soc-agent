"""Bounded adapter stage benchmark, same three-packet Golden flow, no live traffic.

One existing-parser operation decodes three packet records. One Zeek operation
maps their single precomputed conn summary. Zeek capture/analysis is excluded;
these are different stage costs, not equivalent end-to-end collector throughput.
"""

import json
import resource
import sys
import time
from datetime import UTC, datetime
from uuid import UUID

from soc_agent.security_ai.collectors.adapter import parse_line
from soc_agent.security_ai.collectors.models import Source
from soc_agent.security_ai.operational.network_capture.parsing import parse_packet
from tests.production_slimming_profile import no_capture
from tests.unit.live_network.test_parity import wire
from tests.zeek_collector_support import row


def benchmark():
    source = Source(
        session_id=UUID(int=1),
        source_digest="a" * 64,
        origin="SYNTHETIC_ZEEK_JSON",
        version="9.0.0",
    )
    frames = [wire(reverse=i == 1, length=40 + 20 * i, tcp=False) for i in range(3)]
    log = row()

    def existing():
        return [
            parse_packet(
                frame,
                interface_id="a" * 64,
                timestamp=datetime(2026, 1, 1, tzinfo=UTC),
                direction="OUTBOUND",
                native=False,
            )
            for frame in frames
        ]

    def zeek():
        return parse_line(log, "network", source)

    results = {}
    for name, method in (
        ("existing_three_packet_parser", existing),
        ("zeek_one_summary_adapter", zeek),
    ):
        for _ in range(100):
            method()
        samples, rounds = [], []
        cpu = time.process_time()
        for _ in range(5):
            start = time.monotonic()
            for _ in range(1000):
                at = time.monotonic_ns()
                method()
                samples.append((time.monotonic_ns() - at) / 1e6)
            rounds.append(time.monotonic() - start)
        samples.sort()
        results[name] = dict(
            completed_flow_operations=5000,
            rounds=5,
            operations_per_round=1000,
            warmup_operations=100,
            elapsed_seconds=sum(rounds),
            flow_operations_per_second=5000 / sum(rounds),
            latency_p50_ms=samples[2500],
            latency_p95_ms=samples[4750],
            latency_p99_ms=samples[4950],
            cpu_seconds=time.process_time() - cpu,
            process_peak_rss_bytes=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024,
            queue_depth="NOT_APPLICABLE_SYNCHRONOUS_STAGE_ONLY",
            errors=0,
        )
    return dict(
        scope="SYNTHETIC_STAGE_COSTS_NOT_NATIVE_NOT_EQUIVALENT_FULL_PIPELINES",
        includes_zeek_engine=False,
        feature_parity="BLOCKED",
        results=results,
    )


if __name__ == "__main__":
    sys.addaudithook(no_capture)
    print(json.dumps(benchmark(), indent=2))
