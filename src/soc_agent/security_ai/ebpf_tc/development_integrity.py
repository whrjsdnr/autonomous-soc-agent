"""Automatic byte verification inside an explicitly approved development boundary.

No grant issuer, activation, privilege, network or ledger writer. Identical SHA
is not authorization; existing exact R1/R2/Root/Native admission still runs.
"""

import hashlib
import json
import os
import tempfile
from pathlib import Path

from pydantic import Field, model_validator

from soc_agent.security_ai.ebpf_tc.dependencies import read_held
from soc_agent.security_ai.ebpf_tc.execution_request import ExecutionRequest
from soc_agent.security_ai.ebpf_tc.reassessment import Artifact, Contract, Hash, digest, held_json
from soc_agent.security_ai.ebpf_tc.source_guard import SourceGuard, snapshot


class ArtifactAutomation(Contract):
    """Human-approved finite source/path/authority boundary, not a wildcard grant."""

    request_file: Path
    project: Path
    source_export: Path
    first_build: Path
    second_build: Path
    source_pins: dict[str, Hash] = Field(min_length=1, max_length=4096)
    allowed_source_changes: list[str] = Field(max_length=128)
    reference_artifact: Artifact
    boundary_sha: Hash

    @model_validator(mode="after")
    def paths(self):
        paths = (
            self.request_file,
            self.project,
            self.source_export,
            self.first_build,
            self.second_build,
        )
        if any(not p.is_absolute() for p in paths) or len(set(paths)) != len(paths):
            raise ValueError("AUTOMATION_DISTINCT_ABSOLUTE_PATHS")
        for name in self.source_pins:
            if Path(name).is_absolute() or ".." in Path(name).parts:
                raise ValueError("AUTOMATION_SOURCE_PATH")
        if not set(self.allowed_source_changes) <= self.source_pins.keys():
            raise ValueError("AUTOMATION_UNREVIEWED_SOURCE_PATH")
        return self


def boundary(directory: Path) -> dict:
    """Everything in the Phase D authority descriptor except content identities.

    In particular capabilities, Root Manifest, namespace policy, traffic, clock,
    resource, collector and DNS contracts remain exact. No semantic LLM decision.
    """
    phase = json.loads(read_held(directory / "phase-d.json", owner=os.getuid(), limit=1048576))
    image = json.loads(
        read_held(directory / "supervisor-image.json", owner=os.getuid(), limit=1048576)
    )
    return dict(
        phase={k: v for k, v in phase.items() if k not in {"sources", "bundle", "image"}},
        image={k: v for k, v in image.items() if k not in {"path", "sha256", "files"}},
    )


def _verify_sources(config: ArtifactAutomation) -> dict[str, str]:
    exported = snapshot(config.source_export)
    if exported.keys() != config.source_pins.keys():
        raise ValueError("AUTOMATION_SOURCE_INVENTORY_CHANGED")
    current = {}
    for name, old in config.source_pins.items():
        path = config.project / name
        if path.resolve(strict=True) != path:
            raise ValueError("AUTOMATION_SOURCE_SYMLINK")
        pin = hashlib.sha256(
            read_held(path, owner=os.getuid(), limit=64 * 1024**2, allow_empty=True)
        ).hexdigest()
        if pin != exported[name] or pin != old and name not in config.allowed_source_changes:
            raise ValueError("AUTOMATION_SOURCE_CHANGE_REQUIRES_REVIEW")
        current[name] = pin
    # Unlisted executable Python modules cannot sneak in through new source files.
    code = snapshot(config.project / "src")
    if {"src/" + k for k in code} != {k for k in current if k.startswith("src/")}:
        raise ValueError("AUTOMATION_SOURCE_INVENTORY_CHANGED")
    return current


def verify_generated_image(policy, artifact: Artifact) -> None:
    """Reconstruct privileged image bytes with the pinned, unchanged builder.

    Two matching caller files alone are not trusted build provenance. Never
    execute either candidate. Reuse the existing ordinary-user image builder.
    """
    from soc_agent.security_ai.ebpf_tc.namespace_runtime import NamespaceBuild
    from soc_agent.security_ai.ebpf_tc.root_operations import RootBinding
    from soc_agent.security_ai.ebpf_tc.supervisor import prepare_supervisor_image

    directory = policy.artifact_automation.first_build
    descriptor = json.loads(
        read_held(directory / "supervisor-image.json", owner=os.getuid(), limit=1048576)
    )
    runtime = descriptor["namespace_runtime"]
    if runtime is None or runtime["policy"] is None or descriptor["namespace_preview"]:
        raise ValueError("AUTOMATION_ACTIVATED_BUILD_POLICY_REQUIRED")
    with tempfile.TemporaryDirectory(prefix="soc-integrity-rebuild-") as temporary:
        root = Path(temporary)
        receipt = root / "namespace-policy.json"
        receipt.write_bytes(runtime["policy_body"].encode())
        build = NamespaceBuild(
            lease_file=policy.lease_file,
            lease_sha=policy.lease_sha,
            origin=RootBinding.model_validate(policy.namespace_origin),
            policy_file=receipt,
            policy_sha=runtime["policy_sha"],
        )
        generated = prepare_supervisor_image(
            directory / "release",
            artifact.root_manifest,
            root / "supervisor.py",
            dns_sidecar=True,
            namespace_build=build,
        )
        if generated.sha256 != artifact.image:
            raise ValueError("AUTOMATION_IMAGE_BUILD_PROVENANCE")


def verified_artifact(policy, rows: list[dict]) -> Artifact:
    """Revalidate actual independent outputs, never trust a PASS flag in a packet."""
    from soc_agent.security_ai.ebpf_tc.phase_d import validate_preparation

    config = policy.artifact_automation
    if config is None:
        raise ValueError("AUTOMATION_POLICY_REQUIRED")
    if config.reference_artifact not in policy.artifacts:
        raise ValueError("AUTOMATION_REFERENCE_NOT_APPROVED")
    body = read_held(config.request_file, owner=os.getuid(), limit=65536)
    request = ExecutionRequest.model_validate_json(body)
    if Path(request.directory) != config.first_build:
        raise ValueError("AUTOMATION_BUILD_DIRECTORY")
    amendment = held_json(Path(request.amendment_file), request.amendment_sha)
    artifact = Artifact.model_validate(amendment["binding"]["next_artifact"])
    reference = config.reference_artifact
    if (artifact.release, artifact.root_manifest) != (reference.release, reference.root_manifest):
        raise ValueError("AUTOMATION_ROOT_OR_RELEASE_CHANGE_REQUIRES_REVIEW")
    if (request.manifest, request.image_sha) != (artifact.manifest, artifact.image):
        raise ValueError("AUTOMATION_REQUEST_SHA")
    # No execution receipt is accepted here. The ordinary operational check must
    # independently validate ALL exact receipts, R1 tip, Replay and fresh Scope.
    with (
        SourceGuard(config.project / "src"),
        SourceGuard(config.source_export),
        SourceGuard(config.first_build),
        SourceGuard(config.second_build),
    ):
        sources = _verify_sources(config)
        first, second = snapshot(config.first_build), snapshot(config.second_build)
        if first != second or config.first_build.resolve() == config.second_build.resolve():
            raise ValueError("AUTOMATION_REPRODUCIBLE_BUILD_MISMATCH")
        for name in first:
            left, right = (config.first_build / name).stat(), (config.second_build / name).stat()
            if (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino):
                raise ValueError("AUTOMATION_BUILD_NOT_INDEPENDENT")
            if (config.first_build / name).stat().st_mode != (
                config.second_build / name
            ).stat().st_mode:
                raise ValueError("AUTOMATION_BUILD_MODE_MISMATCH")
        for directory in (config.first_build, config.second_build):
            actual = validate_preparation(directory, artifact.manifest, artifact.image)
            if (actual["bundle"], actual["tcx_manifest"]) != (
                artifact.bundle,
                artifact.root_manifest,
            ):
                raise ValueError("AUTOMATION_ARTIFACT_IDENTITY")
            scope = boundary(directory)
            if (
                digest(scope) != config.boundary_sha
                or scope["phase"]["scope"]["namespace"] != policy.namespace
            ):
                raise ValueError("AUTOMATION_SCOPE_CHANGE_REQUIRES_REVIEW")
        verify_generated_image(policy, artifact)
        # Git/source provenance must also be checked by the normal CLI. This
        # digest is evidence, never an authorization substitute or a ledger edit.
        if not sources or not rows:
            raise ValueError("AUTOMATION_PROVENANCE_REQUIRED")
    return artifact


def active_policy(config: dict):
    """Resolve a fixed policy pin from the existing validated campaign chain."""
    from soc_agent.security_ai.ebpf_tc.development_session import (
        ACTIVATED,
        DevelopmentPolicy,
        _validate,
    )
    from soc_agent.security_ai.ebpf_tc.dns_diagnostic_engine import dns_held_json_ledger

    campaign = Path(config["target"]["campaign"])
    ledger = campaign / "execution-ledger.jsonl"
    body = read_held(ledger, owner=os.getuid(), limit=1048576)
    rows = dns_held_json_ledger(str(ledger), hashlib.sha256(body).hexdigest(), os.getuid())
    matches = [
        r
        for r in rows
        if r.get("event") == ACTIVATED
        and r.get("policy_sha") == config["automatic_request_policy_sha"]
    ]
    if len(matches) != 1 or digest(matches[0]["policy"]) != config["automatic_request_policy_sha"]:
        raise ValueError("AUTOMATION_POLICY_NOT_ACTIVATED")
    policy = DevelopmentPolicy.model_validate_json(json.dumps(matches[0]["policy"]))
    budget_body = read_held(campaign / "budget.json", owner=os.getuid(), limit=65536)
    baseline_body = read_held(campaign / "baseline.json", owner=os.getuid(), limit=1048576)
    if (
        rows[0]["budget_sha256"] != hashlib.sha256(budget_body).hexdigest()
        or rows[0]["baseline_sha256"] != hashlib.sha256(baseline_body).hexdigest()
    ):
        raise ValueError("AUTOMATION_LEDGER_ANCHOR")
    _validate(policy, json.loads(budget_body), hashlib.sha256(baseline_body).hexdigest())
    automation = policy.artifact_automation
    if automation is None or automation.request_file != Path(config["request_file"]):
        raise ValueError("AUTOMATION_REQUEST_PATH")
    if automation.project != Path(config["project"]):
        raise ValueError("AUTOMATION_SOURCE_PROJECT")
    return policy, rows


def approved_source_pins(config: dict, original: dict) -> dict:
    """Allow only reviewed source-file deltas, even before a request is published."""
    policy, _ = active_policy(config)
    if original != policy.artifact_automation.source_pins:
        raise ValueError("AUTOMATION_SOURCE_BASELINE")
    return _verify_sources(policy.artifact_automation)


def automatic_request_pin(config: dict) -> str:
    """Calculate the fixed request SHA only after current policy/byte verification."""
    policy, rows = active_policy(config)
    if os.readlink("/proc/self/ns/net") != policy.namespace:
        raise ValueError("AUTOMATION_EXECUTION_NAMESPACE")
    automation = policy.artifact_automation
    before = read_held(automation.request_file, owner=os.getuid(), limit=65536)
    verified_artifact(policy, rows)
    after = read_held(automation.request_file, owner=os.getuid(), limit=65536)
    if before != after:
        raise ValueError("AUTOMATION_REQUEST_CHANGED_DURING_CHECK")
    return hashlib.sha256(after).hexdigest()
