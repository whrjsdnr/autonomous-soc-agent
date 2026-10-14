"""Read-only GUI inventory and explicit synthetic demo probe; never an authority API.

Inventory never predicts, opens a runtime database, installs dependencies or downloads
artifacts. Probe success describes this execution only, not producer parity or efficacy.
"""

import argparse
import importlib
import importlib.metadata
from pathlib import Path
from typing import Literal

from soc_agent.review.models import StoredIncident
from soc_agent.security_ai.external.assembly import assemble
from soc_agent.security_ai.external.inference import InferenceUnavailable, _inventory, infer
from soc_agent.security_ai.external.metadata import reviewed_binding
from soc_agent.security_ai.external.models import (
    Hash,
    Profile,
    Snapshot,
    TrustedExternalModelBinding,
)
from soc_agent.security_ai.external.projection import project, projection_digest
from soc_agent.security_ai.external.service import ModelInput

# Existing Gate B reviewed package contract pin, not a pin discovered from current files.
REVIEWED_CODE = "56293972d069dffaf564a390ab7a4c4554c2a2a5b2ab6be6f6f758b5ea3cce44"
STATUS_CONTRACT = "soc-security-ai-package-status:v1"
PROFILES: tuple[Profile, ...] = ("detection_quality", "edge", "litert")
Check = Literal["VERIFIED", "UNKNOWN", "BLOCKED", "UNAVAILABLE"]


class PackageStatus(Snapshot):
    binding_id: Literal["network-quality", "network-edge", "dns"]
    package: Literal["network-security-ai", "dns-security-ai"]
    version: str | None = None
    installed: Check
    package_import: Check
    contract: Check
    artifact: Check
    backend_dependencies: Check
    demo_inference: Check = "UNKNOWN"
    advisory_projection: Check = "UNKNOWN"
    agent_investigation: Literal["NOT_TESTED"] = "NOT_TESTED"
    operational_input: Literal["NOT_INFERABLE"] = "NOT_INFERABLE"
    overall: Literal[
        "READY_FOR_VERIFIED_DEMO", "ADVISORY_ONLY", "NOT_INFERABLE", "BLOCKED", "UNAVAILABLE"
    ]
    model_id: str | None = None
    model_version: str | None = None
    feature_schema: str | None = None
    feature_names: tuple[str, ...] = ()
    feature_names_digest: Hash | None = None
    artifact_catalog_digest: Hash | None = None
    blocking_reasons: tuple[str, ...]
    evidence_references: tuple[str, ...]


class AuthenticationStatus(Snapshot):
    route: Literal["NATIVE_AUTHENTICATION_SOURCE_CHAIN"] = "NATIVE_AUTHENTICATION_SOURCE_CHAIN"
    evidence_reference: Literal[
        "soc_agent.security_ai.operational.authentication_investigation:read_authentication_view"
    ] = "soc_agent.security_ai.operational.authentication_investigation:read_authentication_view"
    current_runtime_validation: Literal["NOT_QUERIED"] = "NOT_QUERIED"
    external_model_inference: Literal["NOT_INFERABLE"] = "NOT_INFERABLE"


class IntegrationStatus(Snapshot):
    contract_version: Literal["soc-security-ai-package-status:v1"] = STATUS_CONTRACT
    packages: tuple[PackageStatus, ...]
    environment_scope: Literal["CURRENT_INTERPRETER"] = "CURRENT_INTERPRETER"
    authentication: AuthenticationStatus = AuthenticationStatus()
    input_origin: Literal["NOT_SUPPLIED", "SYNTHETIC_PRECOMPUTED_FEATURE_FIXTURE"] = "NOT_SUPPLIED"
    context_digest: Hash | None = None
    projection_digest: Hash | None = None
    write_disposition: Literal["WRITE_DENIED"] = "WRITE_DENIED"
    cross_domain_correlation: Literal["UNVERIFIED"] = "UNVERIFIED"
    # Results are display data, never a capability or proof of source authenticity.
    execution_authority: Literal[False] = False


def inspect_packages(*, artifact_root: Path | None = None) -> IntegrationStatus:
    """Inspect the current interpreter only. No inference, persistence or runtime mutation.

    An artifact root must be explicitly supplied by trusted application composition.
    Dependency checks inspect distribution metadata, not native backend load success.
    Heavy verification should run off the GUI rendering thread; do not poll file hashes.
    """
    from soc_agent.security_ai.external.models import content_digest_payload

    statuses = []
    for profile in PROFILES:
        dns = profile == "litert"
        package = "dns-security-ai" if dns else "network-security-ai"
        name = "dns_security_ai" if dns else "network_security_ai"
        installed: Check = "VERIFIED"
        imported: Check = "UNKNOWN"
        contract: Check = "UNKNOWN"
        artifact: Check = "UNKNOWN"
        backend: Check = "UNKNOWN"
        reasons = ["TRAINING_PRODUCER_PARITY_UNVERIFIED"]
        version = None
        binding = None
        try:
            version = importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError:
            installed = "UNAVAILABLE"
            reasons.append("PACKAGE_NOT_INSTALLED")
        try:
            for module in (name, "security_ai"):
                importlib.import_module(module)
            imported = "VERIFIED"
        except (ImportError, OSError):
            imported = "UNAVAILABLE"
            reasons.append("PACKAGE_IMPORT_FAILED")
        try:
            binding = reviewed_binding(
                profile,
                expected_code_identity=REVIEWED_CODE,
                runtime_contract_digest=content_digest_payload({"contract": STATUS_CONTRACT}),
            )
            contract = "VERIFIED"
        except (ValueError, ImportError, OSError):
            contract = "BLOCKED"
            reasons.append("REVIEWED_CONTRACT_UNAVAILABLE")
        dependencies = {
            "detection_quality": ("lightgbm",),
            "edge": ("torch", "joblib", "scikit-learn"),
            "litert": ("ai-edge-litert", "joblib", "scikit-learn", "pandas"),
        }[profile]
        try:
            for dependency in dependencies:
                importlib.metadata.version(dependency)
            backend = "VERIFIED"
        except importlib.metadata.PackageNotFoundError:
            backend = "UNAVAILABLE"
            reasons.append("BACKEND_DEPENDENCY_MISSING")
        if artifact_root is not None and binding is not None:
            artifact = _verify_artifact(artifact_root, binding)
            if artifact == "BLOCKED":
                reasons.append("ARTIFACT_VERIFICATION_FAILED")
        elif artifact_root is None:
            reasons.append("ARTIFACT_ROOT_NOT_CONFIGURED")
        overall = (
            "UNAVAILABLE"
            if installed == "UNAVAILABLE" or imported == "UNAVAILABLE"
            else "BLOCKED"
            if "BLOCKED" in (contract, artifact) or backend == "UNAVAILABLE"
            else "NOT_INFERABLE"
        )
        statuses.append(
            PackageStatus(
                binding_id="dns"
                if dns
                else "network-quality"
                if profile == "detection_quality"
                else "network-edge",
                package=package,
                version=version,
                installed=installed,
                package_import=imported,
                contract=contract,
                artifact=artifact,
                backend_dependencies=backend,
                overall=overall,
                model_id=binding.model_id if binding else None,
                model_version=binding.model_version if binding else None,
                feature_schema=binding.feature_identity.schema_version if binding else None,
                feature_names=binding.feature_identity.ordered_names if binding else (),
                feature_names_digest=binding.feature_identity.ordered_names_digest
                if binding
                else None,
                artifact_catalog_digest=binding.artifact_identity.catalog_digest
                if binding
                else None,
                blocking_reasons=tuple(reasons),
                evidence_references=(
                    "soc_agent.security_ai.external.metadata:reviewed_binding",
                    "soc_agent.security_ai.external.inference:infer",
                ),
            )
        )
    return IntegrationStatus(packages=tuple(statuses))


def _verify_artifact(root: Path, binding: TrustedExternalModelBinding) -> Check:
    try:
        from security_ai.artifacts import ArtifactDistributionError, verify_install
    except ImportError:
        return "BLOCKED"
    try:
        root = Path(root).absolute()
        before = _inventory(root, binding)
        verify_install(root, model=binding.binding_id)
        if before != _inventory(root, binding):
            return "BLOCKED"
        return "VERIFIED"
    except (ValueError, OSError, ArtifactDistributionError):
        return "BLOCKED"


def verify_fixture_demo(
    *, artifact_root: Path, inputs: tuple[ModelInput, ...], incident: StoredIncident
) -> IntegrationStatus:
    """Explicit opt-in native inference using existing v2 synthetic inputs only.

    Uses the same official inference, adapter, source revalidation and projection as
    the application. Does not create a DB, run an Agent/LLM or grant tool authority.
    Failures propagate sanitized inference/validation codes, never fallback outputs.
    """
    if not inputs or len(inputs) > 3:
        raise ValueError("EXPLICIT_UNIQUE_DEMO_INPUTS_REQUIRED")
    inputs = tuple(ModelInput.model_validate_json(item.model_dump_json()) for item in inputs)
    if len({i.binding.binding_id for i in inputs}) != len(inputs):
        raise ValueError("EXPLICIT_UNIQUE_DEMO_INPUTS_REQUIRED")
    inventory = inspect_packages(artifact_root=artifact_root)
    selected = {i.binding.binding_id for i in inputs}
    if any(
        p.contract != "VERIFIED" or p.artifact != "VERIFIED" or p.backend_dependencies != "VERIFIED"
        for p in inventory.packages
        if p.binding_id in selected
    ) or any(i.binding.package_code_identity != REVIEWED_CODE for i in inputs):
        raise InferenceUnavailable("DEMO_ENVIRONMENT_NOT_VERIFIED")
    runs = tuple(
        infer(artifact_root, item.binding, item.observation, incident=incident) for item in inputs
    )
    context = assemble(runs, incident=incident)
    if context.unlinked_results or len(context.results) != len(inputs):
        raise InferenceUnavailable("INCIDENT_LINKED_DEMO_RESULTS_REQUIRED")
    projection = project(context)
    tested = {r.binding.binding_id for r in context.results}
    return IntegrationStatus(
        packages=tuple(
            p.model_copy(
                update={
                    "demo_inference": "VERIFIED",
                    "advisory_projection": "VERIFIED",
                    "overall": "ADVISORY_ONLY",
                }
            )
            if p.binding_id in tested
            else p
            for p in inventory.packages
        ),
        input_origin="SYNTHETIC_PRECOMPUTED_FEATURE_FIXTURE",
        context_digest=context.context_digest,
        projection_digest=projection_digest(projection),
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact-root", type=Path)
    args = parser.parse_args()
    print(inspect_packages(artifact_root=args.artifact_root).model_dump_json(indent=2))


if __name__ == "__main__":
    main()
