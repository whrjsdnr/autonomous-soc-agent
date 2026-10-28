"""Opt-in development metering. No execution grant, refunds, or automatic activation.

The existing writer verifies the chain and serializes admission. Each attempt still
needs the existing exact-artifact/Root/R1/R2 receipts and foreground confirmation.
"""

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Literal
from uuid import UUID

from pydantic import Field, model_validator

from soc_agent.security_ai.ebpf_tc.dependencies import read_held
from soc_agent.security_ai.ebpf_tc.development_integrity import ArtifactAutomation
from soc_agent.security_ai.ebpf_tc.installation import canonical
from soc_agent.security_ai.ebpf_tc.reassessment import (
    Artifact,
    Contract,
    Hash,
    Identity,
    digest,
)

ACTIVATED = "DEVELOPMENT_METERING_ACTIVATED_V1"
MAX_POLICY_BYTES = 512 * 1024


def prepare_artifact_review(
    directory: Path, manifest: str, image_sha: str, *, git_commit: str, git_tree: str
) -> dict:
    """Read-only exact output list, not a policy, activation or execution receipt.

    Git provenance is supplied by the operator; it is not execution authority.
    Existing admission still validates the release and its exact Git binding.
    A guarded artifact is explicitly identified and never treated as final.
    """
    from soc_agent.security_ai.ebpf_tc.phase_d import validate_preparation
    from soc_agent.security_ai.ebpf_tc.supervisor import SupervisorImage

    value = validate_preparation(directory, manifest, image_sha)
    image = SupervisorImage.model_validate_json((directory / "supervisor-image.json").read_bytes())
    if image.namespace_runtime is None:
        raise ValueError("DEVELOPMENT_NAMESPACE_REVIEW_REQUIRED")
    artifact = Artifact(
        git_commit=git_commit,
        git_tree=git_tree,
        release=value["version"],
        manifest=manifest,
        bundle=value["bundle"],
        image=image_sha,
        root_manifest=value["tcx_manifest"],
    )
    return dict(
        artifacts=[artifact.model_dump(mode="json")],
        artifact_stage="GUARDED" if image.namespace_preview else "POLICY_EMBEDDED",
        final_operational_artifacts=[]
        if image.namespace_preview
        else [artifact.model_dump(mode="json")],
        requires_human_activation=True,
        authorizes_execution=False,
    )


def implementation_sha() -> str:
    root = Path(__file__).parents[1]
    names = [root / "operation_budget.py", root / "native_campaign.py", root / "__init__.py"]
    names += sorted(Path(__file__).parent.glob("*.py"))
    for directory in (
        root.parent / "policy",
        root.parent / "approval",
        root.parent / "review",
        root / "ebpf_native",
    ):
        names += sorted(directory.rglob("*.py"))
    return digest(
        {str(p.relative_to(root.parent)): hashlib.sha256(p.read_bytes()).hexdigest() for p in names}
    )


class DevelopmentPolicy(Contract):
    contract: Literal["SOC_ISOLATED_DEVELOPMENT_METERING_V1"] = (
        "SOC_ISOLATED_DEVELOPMENT_METERING_V1"
    )
    decision: Literal["APPROVED"]
    approver: Identity
    human_reference_sha: Hash
    session: Identity
    batch: Literal["BATCH3"] = "BATCH3"
    namespace: str = Field(pattern=r"^net:\[[0-9]+\]$")
    lease_file: Path
    lease_sha: Hash
    namespace_origin: dict
    budget_sha: Hash
    baseline_sha: Hash
    security_implementation_sha: Hash
    artifacts: list[Artifact] = Field(min_length=1, max_length=16)
    issued_at: int
    expires_at: int
    counter_mode: Literal["OBSERVE_ONLY"] = "OBSERVE_ONLY"
    max_parallel: Literal[1] = 1
    authorize_execution: Literal[False] = False
    refund: Literal[False] = False
    allow_unapproved_artifact: Literal[False] = False
    # Dormant unless a NEW exact human policy includes this reviewed boundary.
    artifact_automation: ArtifactAutomation | None = None

    @model_validator(mode="after")
    def bounded(self):
        if str(UUID(self.session)) != self.session or self.namespace == "net:[4026531833]":
            raise ValueError("DEVELOPMENT_SESSION_OR_HOST_NAMESPACE")
        if not 0 < self.expires_at - self.issued_at <= 86400:
            raise ValueError("DEVELOPMENT_SESSION_VALIDITY")
        return self


def _validate(policy: DevelopmentPolicy, budget: dict, baseline_sha: str | None = None):
    from soc_agent.security_ai.ebpf_tc.isolated_dns_launcher import inspect_lease
    from soc_agent.security_ai.ebpf_tc.root_operations import RootBinding

    if (
        not policy.issued_at <= time.time() < policy.expires_at
        or policy.security_implementation_sha != implementation_sha()
        or digest(budget) != policy.budget_sha
        or baseline_sha is not None
        and policy.baseline_sha != baseline_sha
        or any(x in policy.approver.upper() for x in ("MOCK", "FIXTURE", "SCRIPTED"))
    ):
        raise ValueError("DEVELOPMENT_POLICY_BINDING_OR_EXPIRY")
    origin = RootBinding.model_validate(policy.namespace_origin)
    lease = inspect_lease(policy.lease_file, policy.lease_sha, origin)
    if lease["namespace"] != policy.namespace:
        raise ValueError("DEVELOPMENT_NAMESPACE_CHANGED")


def activate(campaign, packet: dict) -> dict:
    """Existing reassess dispatch; a development instruction never invokes this."""
    from soc_agent.security_ai.native_campaign import NativeCampaign

    # Source allowlists are larger than ordinary 64KiB execution receipts.
    # Keep that default intact; this specific typed policy has its own bound.
    encoded = read_held(Path(packet["policy_file"]), owner=os.getuid(), limit=MAX_POLICY_BYTES)
    if hashlib.sha256(encoded).hexdigest() != packet["policy_sha"]:
        raise ValueError("RECEIPT_SHA_MISMATCH")
    body = json.loads(encoded)
    policy = DevelopmentPolicy.model_validate_json(json.dumps(body))
    _validate(policy, campaign.budget, hashlib.sha256(campaign.baseline_body).hexdigest())
    if policy.batch != campaign.batch or any(
        x in policy.approver.upper() for x in ("MOCK", "FIXTURE", "SCRIPTED")
    ):
        raise ValueError("DEVELOPMENT_POLICY_APPROVER_OR_BATCH")

    def append(rows):
        if any(
            r.get("event") == ACTIVATED and r.get("policy", {}).get("session") == policy.session
            for r in rows
        ):
            raise ValueError("DEVELOPMENT_POLICY_REPLAY")
        if rows[-1].get("record_sha256", digest(rows[-1])) != packet["expected_tip"]:
            raise ValueError("DEVELOPMENT_POLICY_STALE_LEDGER")
        _validate(policy, campaign.budget)
        event = dict(
            event=ACTIVATED,
            policy=body,
            policy_sha=packet["policy_sha"],
            authorizes_execution=False,
        )
        # The existing chain reader is bounded to 1MiB. Do not append a policy
        # that would make the next read fail. Reserve metadata headroom while
        # holding the same campaign lock; do not change the shared ledger limit.
        ledger = campaign.directory / "execution-ledger.jsonl"
        if ledger.stat().st_size + len(canonical(event)) + 4096 > 1048576:
            raise ValueError("DEVELOPMENT_POLICY_LEDGER_CAPACITY")
        return event

    return NativeCampaign._locked(campaign, append)


def metered(rows: list[dict], event: dict, budget: dict, batch: str | None) -> bool:
    """Only this exact, activated, current namespace/artifact may bypass count caps."""
    pin = event.get("development_session_sha")
    if pin is None:
        return False
    matches = [r for r in rows if r.get("event") == ACTIVATED and r.get("policy_sha") == pin]
    if len(matches) != 1 or digest(matches[0]["policy"]) != pin:
        raise ValueError("DEVELOPMENT_POLICY_NOT_ACTIVATED")
    policy = DevelopmentPolicy.model_validate_json(json.dumps(matches[0]["policy"]))
    _validate(policy, budget)
    if rows[0].get("baseline_sha256") != policy.baseline_sha:
        raise ValueError("DEVELOPMENT_BASELINE_CHANGED")
    if batch != policy.batch:
        raise ValueError("DEVELOPMENT_BATCH_CHANGED")
    scope = event["scope"]
    namespace = scope.get("namespace", event.get("development_namespace"))
    if namespace != policy.namespace:
        raise ValueError("DEVELOPMENT_NAMESPACE_SCOPE")
    if event["event"] == "NATIVE_ATTEMPT_RESERVED":
        expected = dict(
            namespace=policy.namespace,
            interface="lo",
            hook="INGRESS",
            duration=300,
            events=4096,
            queue=32,
            address_space_mib=256,
            cpu_seconds=20,
        )
        if scope != expected or event.get("dns_scope", {}).get("namespace") != policy.namespace:
            raise ValueError("DEVELOPMENT_RESOURCE_OR_DNS_SCOPE")
        artifacts = list(policy.artifacts)
        if policy.artifact_automation is not None:
            from soc_agent.security_ai.ebpf_tc.development_integrity import verified_artifact

            candidate = verified_artifact(policy, rows)
            if candidate not in artifacts:
                artifacts.append(candidate)
        if not any(
            event["release"]
            == dict(
                manifest=a.manifest, image=a.image, bundle=a.bundle, tcx_manifest=a.root_manifest
            )
            and event.get("git_commit") == a.git_commit
            for a in artifacts
        ):
            raise ValueError("DEVELOPMENT_ARTIFACT_NOT_REVIEWED")
    else:
        if event.get("operation") not in ("ROOT_INSTALL", "ROOT_DNS_DIAGNOSTIC"):
            raise ValueError("DEVELOPMENT_OPERATION_SCOPE")
        if event.get("binding", {}).get("artifact") not in [
            a.model_dump(mode="json") for a in policy.artifacts
        ]:
            raise ValueError("DEVELOPMENT_ARTIFACT_NOT_REVIEWED")
        # Root operation-specific Scope and limits were checked by reserve_root.
    settled = {
        r.get("attempt_id")
        for r in rows
        if r.get("event")
        in (
            "NATIVE_ATTEMPT_FINISHED",
            "EXECUTION_RESERVATION_SETTLED_V1",
            "ROOT_OPERATION_FINISHED_V1",
        )
    }
    if any(
        r.get("event") in ("NATIVE_ATTEMPT_RESERVED", "ROOT_OPERATION_RESERVED_V1")
        and r.get("attempt_id") not in settled
        for r in rows
    ):
        raise ValueError("DEVELOPMENT_CONCURRENT_EXECUTION")
    return True
