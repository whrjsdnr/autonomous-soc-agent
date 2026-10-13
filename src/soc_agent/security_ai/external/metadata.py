"""Small installed package metadata only; never loads model/scaler artifacts."""

import hashlib
import importlib.metadata
from importlib.resources import files
from pathlib import Path

from soc_agent.security_ai.external.models import (
    ArtifactFile,
    ArtifactIdentity,
    FeatureIdentity,
    Profile,
    TrustedExternalModelBinding,
)


def package_code_identity() -> str:
    digest = hashlib.sha256()
    for package, names in (
        (
            "network_security_ai",
            (
                "contracts.py",
                "schema.py",
                "evidence.py",
                "artifact_manifest.json",
                "resources/top40_features.csv",
                "resources/label_mapping.json",
            ),
        ),
        (
            "dns_security_ai",
            (
                "contracts.py",
                "artifacts.py",
                "evidence.py",
                "artifact_manifest.json",
                "feature_contract.json",
            ),
        ),
        ("security_ai", ("common/evidence.py", "artifacts.py", "artifact_catalog.json")),
    ):
        for name in names:
            digest.update((package + "/" + name + "\0").encode("utf-8"))
            digest.update(files(package).joinpath(name).read_bytes())
    return digest.hexdigest()


def reviewed_binding(
    profile: Profile, *, expected_code_identity: str, runtime_contract_digest: str
) -> TrustedExternalModelBinding:
    """Setup supplies its reviewed code pin; no authority or artifact verification minted."""
    for name in ("security-ai", "network-security-ai", "dns-security-ai"):
        if importlib.metadata.version(name) != "0.1.0":
            raise ValueError("Unsupported external package version")
    if package_code_identity() != expected_code_identity:
        raise ValueError("External contract code differs from trusted setup")
    from dns_security_ai import DNSFeatureContract
    from network_security_ai import NetworkSecurityAIConfig, Top40Contract
    from security_ai.artifacts import catalog

    value = catalog()
    group = {"detection_quality": "network-quality", "edge": "network-edge", "litert": "dns"}[
        profile
    ]
    spec = value["bundles"][group]
    network = profile != "litert"
    package = "network_security_ai" if network else "dns_security_ai"
    manifest = files(package).joinpath("artifact_manifest.json").read_bytes()
    if network:
        contract = Top40Contract(NetworkSecurityAIConfig(artifact_root=Path(".")))
        names, schema, labels = contract.names, contract.feature_set_version, contract.classes
        names_digest, label_digest = contract.digest, contract.label_mapping_digest
        metadata_digest = spec["files"]["metadata/network/top40_features.csv"]["sha256"]
        model_id = (
            "network_cse2018_lightgbm_v4b2"
            if profile == "detection_quality"
            else "network_cse2018_dnn_fp32"
        )
    else:
        contract = DNSFeatureContract()
        names, schema, labels = contract.names, contract.schema_version, ("NORMAL", "MALICIOUS")
        names_digest = contract.digest
        label_digest = hashlib.sha256(b'{"MALICIOUS":1,"NORMAL":0}').hexdigest()
        metadata_digest = spec["files"]["metadata/dns/feature_contract.json"]["sha256"]
        model_id = "dns_cicbell_dnn_int8"
    return TrustedExternalModelBinding(
        binding_id=group,
        source_package="network-security-ai" if network else "dns-security-ai",
        package_version="0.1.0",
        package_code_identity=expected_code_identity,
        model_id=model_id,
        model_version=spec["model_version"],
        profile=profile,
        artifact_identity=ArtifactIdentity(
            release_version=value["version"],
            catalog_digest=hashlib.sha256(
                files("security_ai").joinpath("artifact_catalog.json").read_bytes()
            ).hexdigest(),
            loader_manifest_digest=hashlib.sha256(manifest).hexdigest(),
            files=tuple(
                ArtifactFile(path=name, **item) for name, item in sorted(spec["files"].items())
            ),
        ),
        feature_identity=FeatureIdentity(
            schema_version=schema,
            ordered_names=names,
            ordered_names_digest=names_digest,
            metadata_digest=metadata_digest,
            label_mapping_digest=label_digest,
            ordered_labels=labels,
        ),
        runtime_contract_digest=runtime_contract_digest,
        limitations=(
            "Class probabilities are uncalibrated and never authorize actions.",
            "DNS training/scaler pairing and efficacy remain UNVERIFIED.",
        ),
    )
