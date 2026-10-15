"""Existing DNS9 native fixture only; no raw query extractor or operational admission."""

import hashlib
import importlib.metadata
import json
import resource
from datetime import UTC, datetime
from pathlib import Path

from soc_agent.security_ai.research.environment import Paths, read_local
from soc_agent.security_ai.research.models import DNSReceipt, Request, digest

PIN = "7ad734fb9b101cc5529890cb7c4d2dcdc4d3f5224e5f8bb50741ab5c128d6c24"


def catalogue():
    value = json.loads(read_local(Path(__file__).with_name("dns_replay.json"), 32 * 1024))
    if value.pop("catalogue_digest") != PIN or digest(value) != PIN:
        raise ValueError("DNS_REPLAY_CATALOGUE_TAMPERED")
    return value


def verify(paths: Paths):
    import sys

    if (
        paths.python
        != paths.ml.parent / "autonomous-soc-agent/.security-ai-demo/inference/bin/python"
        or paths.python.resolve() != Path(sys.executable).resolve()
    ):
        raise ValueError("DNS_BACKEND_IDENTITY_MISMATCH")
    doc = catalogue()
    for rel, sha in doc["package_sha256"].items():
        if (
            hashlib.sha256(
                read_local((paths.producer_source or paths.ml) / rel, 128 * 1024)
            ).hexdigest()
            != sha
        ):
            raise ValueError("DNS_PACKAGE_CHANGED")
    # Existing project-local installed artifact bundle; never a request-supplied root.
    root = paths.ml.parent / "autonomous-soc-agent/.security-ai-demo/artifacts/dns"
    for entry in doc["model"]["artifacts"].values():
        body = read_local(root / entry["filename"], entry["size_bytes"])
        if len(body) != entry["size_bytes"] or hashlib.sha256(body).hexdigest() != entry["sha256"]:
            raise ValueError("DNS_ARTIFACT_DIGEST_MISMATCH")
    # LiteRT lives in the existing isolated environment, not the SOC Python.
    metadata = (
        paths.python.parent.parent
        / "lib/python3.12/site-packages/ai_edge_litert-2.3.0.dist-info/METADATA"
    )
    body = read_local(metadata, 128 * 1024).decode()
    if "Version: 2.3.0\n" not in body or "Name: ai-edge-litert\n" not in body:
        raise ValueError("DNS_BACKEND_VERSION_MISMATCH")
    for name, version in {"scikit-learn": "1.9.1", "joblib": "1.6.0"}.items():
        if importlib.metadata.version(name) != version:
            raise ValueError("DNS_BACKEND_VERSION_MISMATCH")
    return {
        "status": "READY",
        "meaning": "PREFLIGHT_ONLY_NO_INFERENCE",
        "profile": "dns",
        "model_id": doc["model"]["model_id"],
        "artifact": "VERIFIED",
        "threshold": 0.5,
        "source_origin": "FIXTURE",
        "validation_level": "FIXTURE_NATIVE_ONLY",
        "producer_parity": "UNVERIFIED",
        "operational_inference": "BLOCKED",
        "write_policy": "WRITE_DENIED",
    }


def run(request: Request, paths: Paths):
    verify(paths)
    import dns_security_ai
    from dns_security_ai import DNSConfig, DNSPredictor

    if (
        Path(dns_security_ai.__file__).resolve().parent
        != (paths.producer_source or paths.ml) / "packages/dns-security-ai/src/dns_security_ai"
    ):
        raise ValueError("DNS_PACKAGE_IMPORT_ROOT_MISMATCH")
    doc = catalogue()
    item = doc["fixtures"][request.flow_index]
    features = dict(zip(doc["feature_names"], item["values"], strict=True))
    prediction = DNSPredictor(
        DNSConfig(
            artifact_root=paths.ml.parent / "autonomous-soc-agent/.security-ai-demo/artifacts/dns",
            runtime="litert",
        )
    ).predict(features)
    return DNSReceipt(
        profile="dns",
        request_digest=digest(request.model_dump(mode="json")),
        invocation_id=request.invocation_id,
        flow_index=request.flow_index,
        fixture_id=item["id"],
        input_digest=item["input_digest"],
        worker_limits={
            "address_space_bytes": resource.getrlimit(resource.RLIMIT_AS)[0],
            "cpu_seconds": resource.getrlimit(resource.RLIMIT_CPU)[0],
            "result_file_bytes": resource.getrlimit(resource.RLIMIT_FSIZE)[0],
            "network": "DENIED",
        },
        feature_names=doc["feature_names"],
        score=prediction.probability,
        prediction="CLASS_1" if prediction.class_id else "CLASS_0",
        inferred_at=datetime.now(UTC),
        inference_latency_ms=prediction.inference_latency_ms,
        provenance_digest=digest(
            {
                "catalogue": PIN,
                "input_digest": item["input_digest"],
                "model": doc["model"]["artifacts"],
                "source": item["source"],
            }
        ),
    )
