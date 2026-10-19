"""Identical capture-free fixtures. Timings are not Native capture capacity."""

import hashlib
import json
import os
import platform
import socket
import statistics
import sys
import time
from pathlib import Path

from soc_agent.security_ai.operational.network_capture.parsing import parse_packet
from tests.capture_filtering_support import (
    OWNER,
    baseline_project,
    optimized_project,
    seed_dns,
)
from tests.production_slimming_profile import no_capture
from tests.streaming_network_support import packet
from tests.unit.live_network.test_parity import wire


def percentile(rows, p):
    return sorted(rows)[int((len(rows) - 1) * p)]


def measure(factory, iterations=4000, repeats=5):
    results = []
    for _ in range(repeats):
        call, close = factory()
        try:
            for i in range(128):
                call(i)
            latencies = []
            wall, cpu = time.perf_counter(), time.process_time()
            for i in range(iterations):
                before = time.perf_counter_ns()
                call(i + 128)
                latencies.append((time.perf_counter_ns() - before) / 1000)
            elapsed = time.perf_counter() - wall
            results.append(
                dict(
                    throughput_per_second=iterations / elapsed,
                    p50_us=percentile(latencies, 0.5),
                    p95_us=percentile(latencies, 0.95),
                    p99_us=percentile(latencies, 0.99),
                    cpu_seconds=time.process_time() - cpu,
                    wall_seconds=elapsed,
                    error_count=0,
                )
            )
        finally:
            close()
    return dict(
        iterations=iterations,
        warmup=128,
        repeats=repeats,
        runs=results,
        median_throughput=statistics.median(r["throughput_per_second"] for r in results),
    )


def main():
    sys.addaudithook(no_capture)
    value = packet(OWNER, 1)
    body = wire()
    previous = [None]

    def projection(optimized):
        def factory():
            engine = seed_dns()
            previous[0] = None

            def call(i):
                if optimized:
                    output = optimized_project(engine, value, i + 200, previous[0])
                    previous[0] = output[2]
                else:
                    output = baseline_project(engine, value, i + 200)
                assert output[3] == "HEALTHY" and output[2]["pending"] == 128

            return call, lambda: None

        return factory

    def parsing():
        return lambda _: parse_packet(
            body,
            interface_id=value.interface_id,
            timestamp=value.timestamp,
            direction="OUTBOUND",
            native=False,
        ), lambda: None

    def serialization():
        return lambda _: json.dumps(
            dict(kind="PACKET", packet=value.model_dump(mode="json"))
        ).encode(), lambda: None

    payload = json.dumps(dict(kind="PACKET", packet=value.model_dump(mode="json"))).encode()

    def transport():
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        for channel in (left, right):
            channel.settimeout(0.5)
            channel.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 32768)

        def call(_):
            left.sendall(payload)
            assert right.recv(8192) == payload

        def close():
            left.close()
            right.close()

        return call, close

    def identity():
        return lambda _: hashlib.sha256(body).digest(), lambda: None

    stages = {
        name: measure(factory)
        for name, factory in (
            ("raw_parsing_existing", parsing),
            ("transport_serialization_existing", serialization),
            ("unix_seqpacket_roundtrip_existing", transport),
            ("identity_hash_candidate_only", identity),
            ("controller_projection_before", projection(False)),
            ("controller_projection_after", projection(True)),
        )
    }
    status = Path("/proc/self/status").read_text()
    memory = {
        line.split(":")[0]: int(line.split()[1]) * 1024
        for line in status.splitlines()
        if line.startswith(("VmRSS:", "VmHWM:"))
    }
    result = dict(
        scope="SYNTHETIC_FIXTURE_NO_CAPTURE_NO_SUPPRESSION",
        python=platform.python_version(),
        kernel=platform.release(),
        cpu_affinity=len(os.sched_getaffinity(0)),
        stages=stages,
        **memory,
        transport_max_outstanding_messages=1,
        transport_queue_peak="NOT_MEASURED",
        raw_rate_policy_changed=False,
        active_deduplication=False,
        parser_and_transport_unchanged=True,
        controller_seeded_dns_connections=128,
        interpretation=(
            "Projection microbenchmark excludes flow/SQLite/model costs; "
            "do not infer Native FPS capacity"
        ),
    )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
