"""Explicitly pinned human recovery policy; absence never enables replacement.

Build permission is not activation. A supplied SHA is an operator trust anchor,
as with R1; this module neither discovers a reviewer nor issues an approval.
"""

import ast
import hashlib
import time
from pathlib import Path
from typing import Literal

from soc_agent.security_ai.ebpf_tc.reassessment import Contract, Hash, Identity, digest


class RecoveryBinding(Contract):
    old_root: Hash
    new_root: Hash
    retained_sha: Hash
    dependencies_sha: Hash
    implementation_sha: Hash
    scope_sha: Hash
    abi_sha: Hash
    host_sha: Hash


class RecoveryApproval(Contract):
    contract: Literal["SOC_RETAINED_REPLACEMENT_POLICY_V1"] = "SOC_RETAINED_REPLACEMENT_POLICY_V1"
    decision: Literal["APPROVED"]
    approver: Identity
    human_reference_sha: Hash
    binding: RecoveryBinding
    issued_at: int
    expires_at: int
    activate_retention_replacement: Literal[True]
    authorize_root: Literal[False]
    authorize_native: Literal[False]


class RecoveryBuild(Contract):
    installed_manifest: Hash
    abi_file: Path
    abi_sha: Hash
    policy_file: Path | None = None
    policy_sha: Hash | None = None


def implementation_sha() -> str:
    root = Path(__file__).parent
    files = list(root.glob("*.py")) + [
        root.parent / "collectors/offload_session.py",
        root.parent.parent / "cli.py",
    ]
    return digest(
        {
            str(p.relative_to(root.parent.parent)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(files)
        }
    )


def check_policy(data: dict, binding: RecoveryBinding) -> RecoveryApproval:
    policy = RecoveryApproval.model_validate(data)
    if (
        policy.binding != binding
        or binding.implementation_sha != implementation_sha()
        or not policy.issued_at <= time.time() < policy.expires_at
    ):
        raise ValueError("RECOVERY_POLICY_BINDING_OR_EXPIRY")
    return policy


def image_constants(path: Path) -> dict:
    """Read literal embedded bindings, never execute image bytes to inspect them."""
    result = {}
    names = {"RECOVERY_BINDING", "RECOVERY_POLICY_BODY", "RECOVERY_POLICY_SHA"}
    for node in ast.parse(path.read_bytes()).body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
            if isinstance(target, ast.Name) and target.id in names:
                if target.id in result:
                    raise ValueError("RECOVERY_IMAGE_DUPLICATE_BINDING")
                result[target.id] = ast.literal_eval(node.value)
    if set(result) != names:
        raise ValueError("RECOVERY_IMAGE_BINDING_MISSING")
    return result


def validate_image_recovery(image, release, *, require_policy: bool) -> dict:
    from soc_agent.security_ai.ebpf_tc.phase_d import SCOPE
    from soc_agent.security_ai.ebpf_tc.r2_diagnostic import Scenario
    from soc_agent.security_ai.ebpf_tc.reassessment import held_json
    from soc_agent.security_ai.ebpf_tc.runtime_recovery import (
        host_identity,
        inspect_retained,
        verify_abi,
    )

    binding = image.recovery_binding
    if binding is None:
        raise ValueError("RECOVERY_IMAGE_REQUIRED")
    image.verify()
    constants = image_constants(image.path)
    retained = inspect_retained(binding.old_root)
    verify_abi(image.path.parent / "recovery-abi.json", binding.abi_sha, release)
    if held_json(image.path.parent / "recovery-host.json", binding.host_sha) != host_identity():
        raise ValueError("RECOVERY_HOST_IDENTITY_CHANGED")
    if (
        constants["RECOVERY_BINDING"] != binding.model_dump()
        or constants["RECOVERY_POLICY_SHA"] != image.recovery_policy_sha
        or binding.old_root != image.previous_manifest
        or binding.new_root != release.identity
        or binding.retained_sha != digest(retained.model_dump(mode="json"))
        or binding.dependencies_sha
        != digest([d.model_dump(mode="json") for d in release.dependencies])
        or binding.implementation_sha != implementation_sha()
        or binding.scope_sha != digest(dict(tcx=SCOPE, r2=Scenario().model_dump()))
    ):
        raise ValueError("RECOVERY_IMAGE_OR_PRESERVATION_BINDING")
    body = constants["RECOVERY_POLICY_BODY"]
    if body is None:
        if image.recovery_policy_sha is not None:
            raise ValueError("RECOVERY_POLICY_SHA_WITHOUT_BODY")
        if require_policy:
            raise ValueError("RECOVERY_POLICY_APPROVAL_REQUIRED")
        return dict(status="POLICY_APPROVAL_REQUIRED", native_admission=False)
    import json

    if not isinstance(body, bytes) or hashlib.sha256(body).hexdigest() != image.recovery_policy_sha:
        raise ValueError("RECOVERY_POLICY_SHA")
    check_policy(json.loads(body), binding)
    return dict(status="RUNTIME_APPROVED", native_admission=False)
