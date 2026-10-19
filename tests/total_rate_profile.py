"""Offline measurement helpers. No AF_PACKET/IPv4/IPv6 sockets or fabricated receipts."""

import math
import os
import resource
import time
from pathlib import Path


def summary(samples, *, cpu_seconds, elapsed_seconds):
    ordered = sorted(samples)
    return dict(
        samples=len(samples),
        unit="seconds",
        p50=ordered[math.ceil(len(samples) * 0.50) - 1],
        p95=ordered[math.ceil(len(samples) * 0.95) - 1],
        p99=ordered[math.ceil(len(samples) * 0.99) - 1],
        quantile_method="nearest_rank_small_N_not_population_tail",
        elapsed_seconds=elapsed_seconds,
        operations_per_second=len(samples) / elapsed_seconds,
        controller_cpu_seconds=cpu_seconds,
        controller_rss_bytes=int(Path("/proc/self/statm").read_text().split()[1])
        * os.sysconf("SC_PAGE_SIZE"),
        process_peak_rss_bytes=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024,
    )


def measure(action, repeats):
    samples = []
    cpu, start = time.process_time(), time.monotonic()
    for _ in range(repeats):
        before = time.perf_counter()
        action()
        samples.append(time.perf_counter() - before)
    return summary(
        samples, cpu_seconds=time.process_time() - cpu, elapsed_seconds=time.monotonic() - start
    )
