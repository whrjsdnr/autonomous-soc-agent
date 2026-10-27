"""One fixed offline replay request; no model/path/module/command from event data."""

import argparse
import ctypes
import os
import resource
import signal
import socket
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

# Limits precede sklearn/numpy/joblib imports; no networking/capture in this worker.


def bind_parent(parent_pid: int) -> None:
    """Linux kills this owned helper if its creating parent thread exits.

    Check both sides of prctl: the parent can exit before the death signal is set.
    This does not affect the independently running Linux SOC Runtime.
    """
    if sys.platform != "linux" or parent_pid <= 1 or os.getppid() != parent_pid:
        raise ValueError("RESEARCH_PARENT_UNAVAILABLE")
    libc = ctypes.CDLL(None, use_errno=True)
    prctl = libc.prctl
    prctl.argtypes = [ctypes.c_int, *([ctypes.c_ulong] * 4)]
    prctl.restype = ctypes.c_int
    if prctl(1, signal.SIGKILL, 0, 0, 0) != 0:  # PR_SET_PDEATHSIG; no privilege change.
        raise OSError(ctypes.get_errno(), "RESEARCH_PARENT_BINDING_FAILED")
    if os.getppid() != parent_pid:
        raise ValueError("RESEARCH_PARENT_UNAVAILABLE")


def limits():
    resource.setrlimit(resource.RLIMIT_AS, (3 * 1024**3, 3 * 1024**3))
    resource.setrlimit(resource.RLIMIT_CPU, (15, 15))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (128 * 1024, 128 * 1024))

    def deny(event, args):
        if event == "socket.__new__" and args[1] in (
            socket.AF_PACKET,
            socket.AF_INET,
            socket.AF_INET6,
        ):
            raise PermissionError("RESEARCH_NETWORK_DENIED")

    sys.addaudithook(deny)


def run(request, paths):
    from soc_agent.security_ai.research.environment import catalogue, verify
    from soc_agent.security_ai.research.models import SPECS, Receipt, digest

    if request.profile == "dns":
        from soc_agent.security_ai.research.dns import run as dns_run

        return dns_run(request, paths)
    verify(paths)
    import ml.verified_producers.network_v1_1 as producer_module
    import numpy as np
    import sklearn
    from ml.ctu13.flows import Flows
    from ml.ctu13.pcap import PcapReader, parse_packet
    from ml.iot23.inspect import _chunks
    from ml.iot23.recovery import recover
    from ml.iot23.wire_reference import read_reference
    from ml.iot23.zeek import load
    from ml.network_research.artifacts import load_research
    from ml.network_research.evaluation import probabilities
    from ml.verified_producers.network_v1_1 import network_features
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import StandardScaler

    if (
        Path(producer_module.__file__).resolve()
        != (paths.producer_source or paths.ml) / "src/ml/verified_producers/network_v1_1.py"
    ):
        raise ValueError("RESEARCH_PRODUCER_IMPORT_ROOT_MISMATCH")
    if sys.version_info[:3] != (3, 12, 14) or sklearn.__version__ != "1.9.1":
        raise ValueError("RESEARCH_BACKEND_VERSION_MISMATCH")
    doc = catalogue()
    expected = doc["samples"][request.flow_index]
    path = paths.ml / doc["raw_relative_path"]
    labels = load(paths.ml / doc["label_relative_path"], doc["label_sha256"], doc["raw_sha256"])
    wires, _ = read_reference(path, doc["raw_sha256"])
    flows, target = Flows(), None
    for record in PcapReader(_chunks(path)):
        try:
            packet = parse_packet(record, doc["raw_sha256"])
        except ValueError:
            continue
        for flow in flows.add(packet):
            if flow.flow_id == expected["flow_id"]:
                target = flow
                break
        if target:
            break
    if target is None:
        raise ValueError("RESEARCH_FLOW_UNAVAILABLE")
    binding = recover(target, labels, wires)
    vector = network_features(
        target.packets, source_origin="OFFLINE_PCAP", source_identity=doc["raw_sha256"]
    )
    if (
        binding.status != "VERIFIED_MATCH"
        or list(binding.references) != expected["label_references"]
        or vector.feature_digest != expected["feature_digest"]
        or vector.source_digest != expected["source_digest"]
        or list(vector.feature_names) != doc["feature_names"]
    ):
        raise ValueError("RESEARCH_FLOW_PROVENANCE_MISMATCH")
    spec = SPECS[request.profile]
    model, manifest = load_research(
        paths.ml / "models/network-research-v1-final" / spec["directory"],
        trusted_manifest_digest=spec["manifest"],
    )
    valid = (
        type(model) is RandomForestClassifier
        if request.profile == "quality"
        else type(model) is Pipeline
        and [type(v) for _, v in model.steps] == [StandardScaler, LogisticRegression]
    )
    if not valid or model.n_features_in_ != 14 or manifest["threshold"] != spec["threshold"]:
        raise ValueError("RESEARCH_MODEL_TYPE_MISMATCH")
    x = np.asarray([vector.values], dtype=np.float32)
    started = time.perf_counter()
    score = float(probabilities(model, x)[0])
    elapsed = (time.perf_counter() - started) * 1000
    return Receipt(
        profile=request.profile,
        request_digest=digest(request.model_dump(mode="json")),
        invocation_id=request.invocation_id,
        model_id=spec["model_id"],
        artifact_digest=spec["sha256"],
        model_manifest_digest=spec["manifest"],
        flow_index=request.flow_index,
        flow_id=expected["flow_id"],
        source_sha256=doc["raw_sha256"],
        source_digest=vector.source_digest,
        feature_digest=vector.feature_digest,
        feature_names=vector.feature_names,
        feature_values=vector.values,
        packet_count=len(target.packets),
        event_time=datetime.fromtimestamp(expected["start_ns"] / 1e9, UTC),
        inferred_at=datetime.now(UTC),
        score=score,
        threshold=spec["threshold"],
        prediction="CLASS_1" if score >= spec["threshold"] else "CLASS_0",
        inference_latency_ms=elapsed,
        worker_limits={
            "address_space_bytes": resource.getrlimit(resource.RLIMIT_AS)[0],
            "cpu_seconds": resource.getrlimit(resource.RLIMIT_CPU)[0],
            "result_file_bytes": resource.getrlimit(resource.RLIMIT_FSIZE)[0],
            "network": "DENIED",
        },
    )


def run_live(request, paths):
    """Same bounded worker and reviewed artifacts; metadata input never grants authority."""
    from soc_agent.security_ai.operational.network_capture.live_session import unprivileged
    from soc_agent.security_ai.research.environment import verify
    from soc_agent.security_ai.research.live_input import parity_check, produce
    from soc_agent.security_ai.research.models import LiveReceipt, digest

    unprivileged()
    verify(paths, offline=False)
    parity_check()
    from soc_agent.security_ai.research.zeek_input import ZeekRequest

    zeek = isinstance(request, ZeekRequest)
    if zeek:
        from soc_agent.security_ai.research.zeek_input import produce as produce_zeek

        vector = produce_zeek(request)
    else:
        vector = produce(request)
    spec, score, elapsed = predict_network(request.profile, vector.values, paths)
    usage = resource.getrusage(resource.RUSAGE_SELF)
    from soc_agent.security_ai.research.models import ZeekReceipt

    return (ZeekReceipt if zeek else LiveReceipt)(
        profile=request.profile,
        **(
            dict(
                pcap_sha256=request.pcap_sha256,
                packet_log_sha256=request.packet_log_sha256,
                script_sha256=request.script_sha256,
            )
            if zeek
            else {}
        ),
        origin=request.origin,
        invocation_id=request.invocation_id,
        request_digest=digest(request.model_dump(mode="json")),
        worker_peak_rss_bytes=usage.ru_maxrss * 1024,
        worker_cpu_seconds=usage.ru_utime + usage.ru_stime,
        capture_session=request.capture_session,
        flow_id=request.flow_id,
        source_digest=vector.source_digest,
        provenance_digest=request.provenance_digest,
        artifact_digest=spec["sha256"],
        model_manifest_digest=spec["manifest"],
        model_id=spec["model_id"],
        feature_names=vector.feature_names,
        feature_values=vector.values,
        feature_digest=vector.feature_digest,
        packet_count=len(request.packets),
        event_time=request.packets[0].timestamp,
        inferred_at=datetime.now(UTC),
        score=score,
        threshold=spec["threshold"],
        prediction="CLASS_1" if score >= spec["threshold"] else "CLASS_0",
        inference_latency_ms=elapsed,
        worker_limits={
            "address_space_bytes": resource.getrlimit(resource.RLIMIT_AS)[0],
            "cpu_seconds": resource.getrlimit(resource.RLIMIT_CPU)[0],
            "result_file_bytes": resource.getrlimit(resource.RLIMIT_FSIZE)[0],
            "network": "DENIED",
        },
    )


def predict_network(profile, values, paths):
    """Shared exact-artifact/type/schema inference for live metadata and TCX vectors."""
    import ml.verified_producers.network_v1_1 as producer
    import numpy as np
    import sklearn
    from ml.network_research.artifacts import load_research
    from ml.network_research.evaluation import probabilities
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import StandardScaler

    from soc_agent.security_ai.research.models import SPECS

    if (
        Path(producer.__file__).resolve()
        != (paths.producer_source or paths.ml) / "src/ml/verified_producers/network_v1_1.py"
        or sys.version_info[:3] != (3, 12, 14)
        or sklearn.__version__ != "1.9.1"
    ):
        raise ValueError("LIVE_PRODUCER_OR_BACKEND_MISMATCH")
    spec = SPECS[profile]
    model, manifest = load_research(
        paths.ml / "models/network-research-v1-final" / spec["directory"],
        trusted_manifest_digest=spec["manifest"],
    )
    valid = (
        type(model) is RandomForestClassifier
        if profile == "quality"
        else type(model) is Pipeline
        and [type(v) for _, v in model.steps] == [StandardScaler, LogisticRegression]
    )
    if not valid or model.n_features_in_ != 14 or manifest["threshold"] != spec["threshold"]:
        raise ValueError("LIVE_MODEL_TYPE_MISMATCH")
    started = time.perf_counter()
    score = float(probabilities(model, np.asarray([values], dtype=np.float32))[0])
    elapsed = (time.perf_counter() - started) * 1000
    return spec, score, elapsed


def run_vector(request, paths):
    from soc_agent.security_ai.research.environment import verify
    from soc_agent.security_ai.research.live_input import parity_check
    from soc_agent.security_ai.research.models import digest
    from soc_agent.security_ai.tcx_input import VectorReceipt, vector

    if os.geteuid() == 0:
        raise ValueError("TCX_MODEL_ORDINARY_UID_REQUIRED")
    verify(paths, offline=False)
    parity_check()
    row, _ = vector(request.job, request.flow_id, request.input_receipt_digest)
    spec, score, elapsed = predict_network(request.profile, row["values"], paths)
    return VectorReceipt(
        origin=request.job.origin,
        profile=request.profile,
        invocation_id=request.invocation_id,
        request_digest=digest(request.model_dump(mode="json")),
        source_digest=digest(request.job.model_dump(mode="json")),
        session=request.job.session,
        namespace=request.job.namespace,
        release_manifest=request.job.release_manifest,
        flow_id=request.flow_id,
        input_receipt_digest=request.input_receipt_digest,
        feature_fingerprint=row["values_digest"],
        feature_names=row["feature_names"],
        feature_values=row["values"],
        model_id=spec["model_id"],
        artifact_digest=spec["sha256"],
        model_manifest_digest=spec["manifest"],
        score=score,
        threshold=spec["threshold"],
        prediction="CLASS_1" if score >= spec["threshold"] else "CLASS_0",
        inferred_at=datetime.now(UTC),
        inference_latency_ms=elapsed,
        worker_limits=dict(
            address_space_bytes=resource.getrlimit(resource.RLIMIT_AS)[0],
            cpu_seconds=resource.getrlimit(resource.RLIMIT_CPU)[0],
            result_file_bytes=resource.getrlimit(resource.RLIMIT_FSIZE)[0],
            network="DENIED",
        ),
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--parent-pid", type=int, required=True)
    parser.add_argument("--request", type=Path, required=True)
    parser.add_argument("--result", type=Path, required=True)
    parser.add_argument("--ml", type=Path, required=True)
    parser.add_argument("--producer-source", type=Path, required=True)
    parser.add_argument("--tcx-vector", action="store_true")
    parser.add_argument("--live-metadata", action="store_true")
    parser.add_argument("--zeek-metadata", action="store_true")
    args = parser.parse_args()
    bind_parent(args.parent_pid)
    limits()
    from soc_agent.security_ai.research.environment import Paths, read_local
    from soc_agent.security_ai.research.models import Request

    if sum((args.tcx_vector, args.live_metadata, args.zeek_metadata)) > 1:
        raise ValueError("RESEARCH_WORKER_MODE_CONFLICT")
    if args.tcx_vector:
        from soc_agent.security_ai.tcx_input import VectorRequest

        request = VectorRequest.model_validate_json(read_local(args.request, 1024 * 1024))
    elif args.zeek_metadata:
        from soc_agent.security_ai.research.zeek_input import ZeekRequest

        request = ZeekRequest.model_validate_json(read_local(args.request, 256 * 1024))
    elif args.live_metadata:
        from soc_agent.security_ai.research.live_input import LiveRequest

        request = LiveRequest.model_validate_json(read_local(args.request, 256 * 1024))
    else:
        request = Request.model_validate_json(read_local(args.request, 4096))
    paths = Paths(
        args.ml, Path(sys.executable), Path(__file__).resolve().parents[3], args.producer_source
    )
    result = (
        run_vector(request, paths)
        if args.tcx_vector
        else run_live(request, paths)
        if args.live_metadata or args.zeek_metadata
        else run(request, paths)
    )
    with args.result.open("x") as stream:
        stream.write(result.model_dump_json())
    args.result.chmod(0o600)


if __name__ == "__main__":
    main()
