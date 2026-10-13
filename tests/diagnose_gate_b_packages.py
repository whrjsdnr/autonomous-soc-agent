"""Standalone external package smoke; does not integrate or authorize SOC actions.

Run in an existing trusted external-package environment. No dependency installation,
training, source mutation, network request, or SOC store is performed by this tool.
"""

import argparse
import hashlib
import importlib.metadata
import json
import platform
from pathlib import Path


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_new_report(path: Path, report: dict) -> None:
    # Encode/validate before exclusive creation; no partial output on invalid JSON.
    content = json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    with path.open("x", encoding="utf-8") as stream:
        stream.write(content)


def standalone_smoke(root: Path) -> dict:
    # Optional imports must not make the regular SOC test suite depend on ML extras.
    from dns_security_ai import DNSConfig, DNSFeatureContract, DNSPredictor
    from dns_security_ai import prediction_to_evidence as dns_receipt
    from network_security_ai import (
        NetworkSecurityAIConfig,
        Top40Contract,
        create_network_security_ai,
    )
    from network_security_ai import prediction_to_evidence as network_receipt
    from security_ai import EvidenceEnvelope, to_envelope
    from security_ai.artifacts import verify_install

    verification = verify_install(root, model="all")
    configs = [
        NetworkSecurityAIConfig(enabled=True, profile=profile, artifact_root=root)
        for profile in ("detection_quality", "edge")
    ]
    contract = Top40Contract(configs[0])
    cases = []
    for config in configs:
        predictor = create_network_security_ai(config)
        for ordinal, scalar in enumerate((1.0, 100.0)):
            # Contract-valid artificial feature vectors, NOT labelled attack examples.
            features = dict.fromkeys(contract.names, scalar)
            prediction = predictor.predict(features)
            receipt = network_receipt(prediction, flow_reference=f"synthetic-network-{ordinal}")
            envelope = to_envelope(receipt)
            validated = EvidenceEnvelope.model_validate_json(envelope.model_dump_json())
            cases.append(validated.model_dump(mode="json"))
    dns_contract = DNSFeatureContract()
    dns = DNSPredictor(DNSConfig(artifact_root=root / "dns"))
    for ordinal, scalar in enumerate((1.0, 100.0)):
        prediction = dns.predict(dict.fromkeys(dns_contract.names, scalar))
        envelope = to_envelope(dns_receipt(prediction, observation_ref=f"synthetic-dns-{ordinal}"))
        cases.append(
            EvidenceEnvelope.model_validate_json(envelope.model_dump_json()).model_dump(mode="json")
        )
    verification_after = verify_install(root, model="all")
    if verification_after != verification:
        raise ValueError("Artifact verification changed during inference")
    inventory = [
        {
            "path": path.relative_to(root).as_posix(),
            "bytes": path.stat().st_size,
            "sha256": sha256_file(path),
        }
        for path in sorted(root.rglob("*"))
        if path.is_file()
    ]
    return {
        "contract_version": "gate-b-standalone-package-smoke-v1",
        "scope": "standalone synthetic feature vectors; no SOC integration or efficacy claim",
        "status": "PASS",
        "soc_integration": "INCONCLUSIVE",
        "environment": {
            "platform": platform.platform(),
            "python": platform.python_version(),
            "packages": {
                name: importlib.metadata.version(name)
                for name in (
                    "security-ai",
                    "network-security-ai",
                    "dns-security-ai",
                    "numpy",
                    "pydantic",
                    "lightgbm",
                    "torch",
                    "joblib",
                    "scikit-learn",
                    "pandas",
                    "ai-edge-litert",
                )
            },
        },
        "artifact_verification": verification,
        "inventory": inventory,
        "network_feature_names": list(contract.names),
        "dns_feature_names": list(dns_contract.names),
        "envelopes": cases,
        "provider_requests": 0,
        "soc_write_actions": 0,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists() or args.output.is_symlink():
        parser.error("Output exists; refusing overwrite")
    write_new_report(args.output, standalone_smoke(args.artifact_root))


if __name__ == "__main__":
    main()
