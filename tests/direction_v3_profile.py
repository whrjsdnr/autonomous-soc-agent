"""v2 versus v3 admission/parsing of identical synthetic frames, never Native capacity."""

import json
import os
import platform
import resource
import statistics
import sys
import time
from datetime import UTC, datetime

from soc_agent.security_ai.operational.network_capture.direction_policy import (
    Accounting,
    DirectionPolicy,
)
from soc_agent.security_ai.operational.network_capture.parsing import parse_packet
from soc_agent.security_ai.operational.network_capture.stream_session import RateBudget
from tests.production_slimming_profile import no_capture
from tests.unit.live_network.test_parity import wire


def run(v3):
    frame = wire()
    a = Accounting(DirectionPolicy(), 0) if v3 else RateBudget(256, 512, 0)
    count = 0

    def call(i):
        nonlocal count
        direction = "OUTBOUND" if i % 2 == 0 else "INBOUND"
        if v3:
            accepted = a.admit(direction, i / 128)
        else:
            a.consume(i / 128)
            accepted = direction == "OUTBOUND"
        if accepted:
            parse_packet(
                frame,
                interface_id="a" * 64,
                timestamp=datetime.fromtimestamp(1800000000 + i / 128, UTC),
                capture_timestamp_ns=1800000000 * 10**9 + i * 7812500,
                direction=direction,
                native=True,
                retain_name=False,
            )
            count += 1
            if v3:
                a.normalized += 1

    for i in range(128):
        call(i)
    times = []
    started, cpu = time.perf_counter(), time.process_time()
    for i in range(128, 4128):
        before = time.perf_counter_ns()
        call(i)
        times.append((time.perf_counter_ns() - before) / 1000)
    elapsed = time.perf_counter() - started
    times.sort()
    return dict(
        raw_frames=4000,
        normalized_packets=count - 64,
        throughput=4000 / elapsed,
        normalized_throughput=2000 / elapsed,
        p50_us=times[1999],
        p95_us=times[3799],
        p99_us=times[3959],
        cpu_seconds=time.process_time() - cpu,
        peak_rss_bytes=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024,
        queue_depth="NOT_APPLICABLE_TO_MICROSTAGE",
        errors=0,
    )


def main():
    sys.addaudithook(no_capture)
    result = dict(
        scope="SYNTHETIC_ADMISSION_PARSING_ONLY_NOT_NATIVE_CAPACITY",
        kernel=platform.release(),
        python=platform.python_version(),
        cpu_affinity=len(os.sched_getaffinity(0)),
        warmup_frames=128,
        iterations=4000,
        repeats=5,
        simulated_raw_fps=128,
        native_throughput="UNKNOWN",
        deduplication=False,
    )
    for key, v3 in [("balanced_v2", False), ("direction_v3", True)]:
        rows = [run(v3) for _ in range(5)]
        result[key] = dict(
            runs=rows, median_raw_throughput=statistics.median(r["throughput"] for r in rows)
        )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
