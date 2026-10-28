"""Pinned Namespace build policy, not permission to enter, install or capture.

Same explicit-file trust-anchor model as recovery_policy. No discovery, issuance,
ledger writes, privilege changes or namespace creation happen here.
"""

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Literal

from pydantic import model_validator

from soc_agent.security_ai.ebpf_tc.reassessment import Contract, Hash, Identity, digest, held_json
from soc_agent.security_ai.ebpf_tc.root_operations import RootBinding


class NamespaceBuild(Contract):
    lease_file: Path
    lease_sha: Hash
    origin: RootBinding
    policy_file: Path | None = None
    policy_sha: Hash | None = None

    @model_validator(mode="after")
    def paired_policy(self):
        if (self.policy_file is None) != (self.policy_sha is None):
            raise ValueError("NAMESPACE_POLICY_PIN_REQUIRED")
        return self


class NamespacePolicy(Contract):
    contract: Literal["SOC_NAMESPACE_SUPERVISOR_BUILD_POLICY_V1"] = (
        "SOC_NAMESPACE_SUPERVISOR_BUILD_POLICY_V1"
    )
    decision: Literal["APPROVED"]
    approver: Identity
    human_reference_sha: Hash
    binding: dict
    issued_at: int
    expires_at: int
    activate_namespace_supervisor: Literal[True]
    authorize_root: Literal[False] = False
    authorize_native: Literal[False] = False
    authorize_traffic: Literal[False] = False


def binding(build: NamespaceBuild, release) -> tuple[dict, dict]:
    from soc_agent.security_ai.ebpf_tc.isolated_dns_launcher import inspect_lease
    from soc_agent.security_ai.ebpf_tc.phase_d import runtime_bundle

    lease = inspect_lease(build.lease_file, build.lease_sha, build.origin)
    value = dict(
        namespace=lease["namespace"],
        lease_sha=build.lease_sha,
        namespace_device=lease["dev"],
        namespace_inode=lease["inode"],
        boot_id=lease["boot_id"],
        root_manifest=release.identity,
        sources_sha=digest(runtime_bundle()),
        dependencies_sha=digest([d.model_dump(mode="json") for d in release.dependencies]),
        uid=os.getuid(),
        gid=os.getgid(),
        controller="ORDINARY_UID_INSIDE_APPROVED_NAMESPACE",
        root_docker="NOT_USED_BY_PHASE_D",
        analysis_container_network="none",
    )
    return value, lease


def check_policy(data: dict, expected: dict) -> NamespacePolicy:
    result = NamespacePolicy.model_validate(data)
    if (
        result.binding != expected
        or not result.issued_at <= time.time() < result.expires_at
        or not 0 < result.expires_at - result.issued_at <= 86400
        or any(v in result.approver.upper() for v in ("MOCK", "FIXTURE", "SCRIPTED"))
    ):
        raise ValueError("NAMESPACE_POLICY_BINDING_OR_EXPIRY")
    return result


def prepare_binding(build: NamespaceBuild, release) -> dict:
    expected, lease = binding(build, release)
    policy = policy_body = None
    if build.policy_file is not None:
        policy = held_json(build.policy_file, build.policy_sha)
        policy_body = build.policy_file.read_text()
        if hashlib.sha256(policy_body.encode()).hexdigest() != build.policy_sha:
            raise ValueError("NAMESPACE_POLICY_CHANGED_DURING_BUILD")
        check_policy(policy, expected)
    return dict(
        binding=expected,
        lease=lease,
        policy=policy,
        policy_body=policy_body,
        policy_sha=build.policy_sha,
    )


def build_review(image, identity: dict) -> dict:
    """Separate policy inputs from receipt-dependent outputs; grant nothing.

    The build-policy binding is known before approval. The receipt changes image
    and Phase D manifest bytes, not that binding. Execution/metering approvals
    must use the subsequent exact outputs, never the preview's image hash.
    """
    packet = image.namespace_runtime
    if packet is None:
        raise ValueError("NAMESPACE_REVIEW_REQUIRED")
    verify_descriptor(image)
    if (
        identity["image"] != image.sha256
        or identity["tcx_manifest"] != packet["binding"]["root_manifest"]
    ):
        raise ValueError("NAMESPACE_REVIEW_OUTPUT_BINDING")
    return dict(
        policy_input=packet["binding"],
        policy_input_sha=digest(packet["binding"]),
        policy_receipt_sha=packet["policy_sha"],
        built_outputs={k: identity[k] for k in ("manifest", "bundle", "image", "tcx_manifest")},
        artifact_stage="GUARDED" if image.namespace_preview else "POLICY_EMBEDDED",
        next_step="NAMESPACE_BUILD_POLICY_APPROVAL"
        if image.namespace_preview
        else "EXACT_ARTIFACT_METERING_AND_EXECUTION_REVIEW",
        outputs_requiring_rebuild_after_policy=["manifest", "image"]
        if image.namespace_preview
        else [],
        authorizes_execution=False,
    )


def verify_descriptor(image) -> None:
    """Literal descriptor consistency; never enables an unapproved preview."""
    # Inspect literals, never evaluate a generated image to validate it.
    import ast

    found = []
    for node in ast.parse(image.path.read_bytes()).body:
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == "NAMESPACE_RUNTIME" for t in node.targets
        ):
            found.append(ast.literal_eval(node.value))
    if len(found) != 1 or found[0] != image.namespace_runtime:
        raise ValueError("NAMESPACE_IMAGE_BINDING")
    packet = found[0]
    if packet["binding"]["namespace"] != image.scope_namespace:
        raise ValueError("NAMESPACE_IMAGE_SCOPE")
    if packet["policy"] is None:
        if not image.namespace_preview or packet["policy_sha"] is not None:
            raise ValueError("NAMESPACE_POLICY_REQUIRED")
        return
    body = packet["policy_body"].encode()
    if json.loads(body) != packet["policy"]:
        raise ValueError("NAMESPACE_POLICY_BODY")
    if hashlib.sha256(body).hexdigest() != packet["policy_sha"]:
        raise ValueError("NAMESPACE_POLICY_SHA")
    check_policy(packet["policy"], packet["binding"])
    if image.namespace_preview:
        raise ValueError("NAMESPACE_APPROVED_DESCRIPTOR_STILL_PREVIEW")
