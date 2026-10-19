"""Same PCAP arithmetic comparison and separately timed official engine overhead.

No network or Native throughput claim. Existing ML producer stays unchanged.
"""

import json
import resource
import sys
import tempfile
import time
from pathlib import Path

from soc_agent.security_ai.collectors.offline import OfflineZeek
from soc_agent.security_ai.collectors.packet_input import (
    Packet,
    metadata,
    reference,
    verify_packets,
)
from soc_agent.security_ai.collectors.packet_producer import aggregate
from tests.production_slimming_profile import no_capture
from tests.research_adapter_support import research_paths
from tests.zeek_producer_support import golden


def run():
    paths = research_paths()
    sys.path.insert(0, str((paths.producer_source or paths.ml) / "src"))
    from ml.verified_producers.network import Packet as MLPacket
    from ml.verified_producers.network_v1_1 import network_features

    with tempfile.TemporaryDirectory(prefix="zeek-producer-profile-") as temp:
        root = Path(temp)
        pcap = root / "input.pcap"
        sha = golden(pcap)
        packets = tuple(reference(pcap))
        segmented = aggregate(packets, "profile")
        windows = [
            tuple(Packet.model_validate(p) for p in flow["packets"]) for flow in segmented["flows"]
        ]
        old = [tuple(MLPacket(**p) for p in metadata(w, "profile", sha)) for w in windows]

        def existing():
            return [
                network_features(w, source_origin="OFFLINE_PCAP", source_identity=sha).values
                for w in old
            ]

        def candidate():
            return [f["values"] for f in aggregate(packets, "profile")["flows"]]

        assert existing() == [tuple(v) for v in candidate()]
        result = {}
        for name, method in [
            ("existing_ml_network14_arithmetic", existing),
            ("zeek_incremental_arithmetic_and_windowing", candidate),
        ]:
            for _ in range(100):
                method()
            cpu = time.process_time()
            start = time.monotonic()
            samples = []
            for _ in range(5):
                for _ in range(1000):
                    at = time.monotonic_ns()
                    method()
                    samples.append((time.monotonic_ns() - at) / 1e6)
            elapsed = time.monotonic() - start
            samples.sort()
            result[name] = dict(
                warmup=100,
                rounds=5,
                operations_per_round=1000,
                vectors_per_operation=2,
                vectors_per_second=10000 / elapsed,
                elapsed_seconds=elapsed,
                cpu_seconds=time.process_time() - cpu,
                p50_ms=samples[2500],
                p95_ms=samples[4750],
                p99_ms=samples[4950],
                peak_host_rss_bytes=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024,
            )
        engine = []
        for i in range(4):
            logs = root / f"logs-{i}"
            logs.mkdir()
            runner = OfflineZeek(packet_mode=True)
            cpu = time.process_time()
            start = time.monotonic()
            r = runner.run(pcap, sha, logs)
            p = verify_packets(
                pcap, logs / "network14_packets.log", sha, r["log_sha256"]["network14_packets.log"]
            )
            proof = aggregate(p, "profile")
            if i:
                engine.append(
                    dict(
                        elapsed_seconds=time.monotonic() - start,
                        controller_cpu_seconds=time.process_time() - cpu,
                        official_engine_and_docker_seconds=r["elapsed_seconds"],
                        peak_host_rss_bytes=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
                        * 1024,
                        packet_count=proof["packet_count"],
                        peak_packet_references=proof["peak_packet_references"],
                        flow_count=len(proof["flows"]),
                        queue_final=0,
                    )
                )
        return dict(
            scope="SAME_OFFLINE_SYNTHETIC_PCAP_NOT_NATIVE",
            pcap_sha256=sha,
            arithmetic=result,
            official_engine_pipeline=engine,
            engine_warmup_runs=1,
            zeek_container_cpu_rss="UNKNOWN_NOT_MEASURED_BY_HOST_RUSAGE",
            native_throughput="UNKNOWN",
            capture_to_log_latency="UNKNOWN_NOT_LIVE",
        )


if __name__ == "__main__":
    sys.addaudithook(no_capture)
    print(json.dumps(run(), indent=2))
