"""Versioned, human-authorized reassessment; never rewrites a failure or safe flag.

This records a separate decision using the existing locked hash-chain writer. It
is intentionally NOT recognized by the pinned legacy admission gate. Activating
admission under this procedure requires a separately reviewed controller update.
A supplied hash is an operator trust anchor, not a signature or reviewer discovery.
"""

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Annotated, Literal, get_args, get_origin

from pydantic import BaseModel, ConfigDict, Field, model_validator

from soc_agent.security_ai.ebpf_tc.dependencies import read_held
from soc_agent.security_ai.ebpf_tc.installation import canonical
from soc_agent.security_ai.native_campaign import NativeCampaign
from soc_agent.security_ai.stabilization_campaign import StabilizationCampaign

Hash = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
Identity = Annotated[str, Field(min_length=1, max_length=128)]


class Contract(BaseModel):
    model_config = ConfigDict(strict=True, frozen=True, extra="forbid")

    @model_validator(mode="before")
    @classmethod
    def literal_types(cls, data: object) -> object:
        if isinstance(data, dict):
            for name, field in cls.model_fields.items():
                if name in data and get_origin(field.annotation) is Literal:
                    if type(data[name]) not in {type(v) for v in get_args(field.annotation)}:
                        raise ValueError("CONTRACT_LITERAL_TYPE")
        return data


def digest(value: object) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


class Artifact(Contract):
    git_commit: Annotated[str, Field(pattern=r"^[0-9a-f]{40}$")]
    git_tree: Annotated[str, Field(pattern=r"^[0-9a-f]{40}$")]
    release: Identity
    manifest: Hash
    bundle: Hash
    image: Hash
    root_manifest: Hash


class Binding(Contract):
    campaign: Literal["SOC_NATIVE_STABILIZATION"] = "SOC_NATIVE_STABILIZATION"
    batch: Literal["BATCH2"] = "BATCH2"
    previous_attempt: Identity
    previous_session: Identity
    previous_artifact: Artifact
    next_session: Identity
    next_artifact: Artifact
    negative_review_sha: Hash
    scope_sha: Hash
    evidence_sha: Hash


class CleanupEvidence(Contract):
    # Reviewer-attested interpretation, with every source pinned separately.
    sources: Annotated[dict[Identity, Hash], Field(min_length=1, max_length=64)]
    owned_fd_closed: bool
    owned_maps_remaining: int = Field(ge=0)
    owned_links_remaining: int = Field(ge=0)
    owned_filters_remaining: int = Field(ge=0)
    container_absent: bool
    drain_verified: bool
    new_unknown_programs: int = Field(ge=0)
    removed_external_program: Literal[1145] = 1145
    external_owner: Literal["wsl-pro.service", "UNKNOWN"]
    external_removal_cause: Literal["UNKNOWN"] = "UNKNOWN"
    global_cleanup: Literal["UNVERIFIED"] = "UNVERIFIED"


class ProcedureApproval(Contract):
    contract: Literal["SOC_REASSESSMENT_PROCEDURE_V1"] = "SOC_REASSESSMENT_PROCEDURE_V1"
    decision: Literal["APPROVED"]
    approver: Identity
    human_reference_sha: Hash
    implementation_sha: Hash
    budget_sha: Hash
    baseline_sha: Hash
    binding_sha: Hash
    issued_at: int = Field(ge=0)
    expires_at: int = Field(gt=0)
    authorize_native: Literal[False] = False
    authorize_root: Literal[False] = False
    replace_legacy_gate: Literal[False] = False


class ReviewReceipt(Contract):
    contract: Literal["SOC_SAFETY_REASSESSMENT_V1"] = "SOC_SAFETY_REASSESSMENT_V1"
    receipt_id: Identity
    reviewer: Identity
    human_reference_sha: Hash
    procedure_sha: Hash
    binding: Binding
    ledger_tip_sha: Hash
    decision: Literal["ALLOW_NEXT_ADMISSION_ONLY", "DENY", "DEFER"]
    accept_unknown_external_removal_cause: bool = False
    issued_at: int = Field(ge=0)
    expires_at: int = Field(gt=0)
    max_next_attempts: Literal[1] = 1
    authorize_native: Literal[False] = False
    authorize_root: Literal[False] = False


def held_json(path: Path, expected_sha: str) -> dict:
    body = read_held(path, owner=os.getuid(), limit=65536)
    if hashlib.sha256(body).hexdigest() != expected_sha:
        raise ValueError("RECEIPT_SHA_MISMATCH")
    return json.loads(body)


def reassess(
    campaign: StabilizationCampaign,
    *,
    procedure_file: Path,
    procedure_sha: str,
    receipt_file: Path,
    receipt_sha: str,
    evidence: CleanupEvidence,
    source_paths: dict[str, Path],
    expected_binding: Binding,
) -> dict:
    """Consume separately pinned procedure/review approvals atomically; no execution."""
    procedure = ProcedureApproval.model_validate(held_json(procedure_file, procedure_sha))
    receipt = ReviewReceipt.model_validate(held_json(receipt_file, receipt_sha))
    now = int(time.time())
    if not (
        procedure.issued_at <= now < procedure.expires_at
        and receipt.issued_at <= now < receipt.expires_at
    ):
        raise ValueError("REASSESSMENT_EXPIRED_OR_FUTURE")
    if (
        procedure.implementation_sha != hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        or procedure.budget_sha != hashlib.sha256(campaign.budget_body).hexdigest()
        or procedure.baseline_sha != hashlib.sha256(campaign.baseline_body).hexdigest()
        or procedure.binding_sha != digest(expected_binding.model_dump())
        or receipt.procedure_sha != procedure_sha
        or receipt.binding != expected_binding
        or receipt.binding.evidence_sha != digest(evidence.model_dump())
        or campaign.batch != expected_binding.batch
    ):
        raise ValueError("REASSESSMENT_BINDING")
    if set(source_paths) != set(evidence.sources):
        raise ValueError("REASSESSMENT_EVIDENCE_SET")
    for name, path in source_paths.items():
        body = read_held(path, owner=os.getuid(), limit=1048576)
        if hashlib.sha256(body).hexdigest() != evidence.sources[name]:
            raise ValueError("REASSESSMENT_EVIDENCE_SHA")
    if receipt.decision == "ALLOW_NEXT_ADMISSION_ONLY" and (
        not evidence.owned_fd_closed
        or evidence.owned_maps_remaining
        or evidence.owned_links_remaining
        or evidence.owned_filters_remaining
        or not evidence.container_absent
        or not evidence.drain_verified
        or evidence.new_unknown_programs
        or evidence.external_owner == "UNKNOWN"
        or not receipt.accept_unknown_external_removal_cause
    ):
        raise ValueError("REASSESSMENT_CLEANUP_OR_UNCERTAINTY")

    def append(rows: list[dict]) -> dict:
        if time.time() >= min(procedure.expires_at, receipt.expires_at):
            raise ValueError("REASSESSMENT_EXPIRED_UNDER_LOCK")
        if rows[-1].get("record_sha256") != receipt.ledger_tip_sha:
            raise ValueError("REASSESSMENT_STALE_LEDGER")
        negatives = [
            r for r in rows if r.get("record_sha256") == expected_binding.negative_review_sha
        ]
        if len(negatives) != 1:
            raise ValueError("REASSESSMENT_ORIGINAL_REVIEW_MISSING")
        old = negatives[0]
        latest = [
            r
            for r in rows
            if r.get("event") == "DIAGNOSTIC_E2E_EVIDENCE_REVIEW_COMPLETED"
            and r.get("attempt_id") == expected_binding.previous_attempt
        ]
        if latest[-1] != old:
            raise ValueError("REASSESSMENT_SUPERSEDED_NEGATIVE_REVIEW")
        if (
            old.get("event") != "DIAGNOSTIC_E2E_EVIDENCE_REVIEW_COMPLETED"
            or old.get("safe_for_next_attempt") is not False
            or old.get("attempt_id") != expected_binding.previous_attempt
        ):
            raise ValueError("REASSESSMENT_ORIGINAL_REVIEW_BINDING")
        reservations = [
            r
            for r in rows
            if r.get("event") == "NATIVE_ATTEMPT_RESERVED"
            and r.get("attempt_id") == expected_binding.previous_attempt
        ]
        finished = [
            r
            for r in rows
            if r.get("event") == "NATIVE_ATTEMPT_FINISHED"
            and r.get("attempt_id") == expected_binding.previous_attempt
        ]
        prior = expected_binding.previous_artifact
        if (
            len(reservations) != 1
            or len(finished) != 1
            or reservations[0].get("git_commit") != prior.git_commit
            or reservations[0].get("release")
            != dict(
                manifest=prior.manifest,
                bundle=prior.bundle,
                image=prior.image,
                tcx_manifest=prior.root_manifest,
            )
            or finished[0].get("evidence", {}).get("application_session")
            != expected_binding.previous_session
            or finished[0].get("outcome") != "FAILED"
        ):
            raise ValueError("REASSESSMENT_PRIOR_SESSION_OR_RELEASE")
        for row in rows:
            if row.get("event") == "SAFETY_REASSESSMENT_RECORDED_V1" and (
                row.get("receipt_id") == receipt.receipt_id
                or row.get("receipt_sha256") == receipt_sha
                or row.get("human_reference_sha") == receipt.human_reference_sha
            ):
                raise ValueError("REASSESSMENT_REPLAY")
        return dict(
            event="SAFETY_REASSESSMENT_RECORDED_V1",
            receipt_id=receipt.receipt_id,
            receipt_sha256=receipt_sha,
            procedure_sha256=procedure_sha,
            reviewer=receipt.reviewer,
            approver=procedure.approver,
            human_reference_sha=receipt.human_reference_sha,
            binding=expected_binding.model_dump(),
            evidence=evidence.model_dump(),
            decision=receipt.decision,
            expires_at=receipt.expires_at,
            legacy_admission_unchanged=True,
            authorizes_execution=False,
        )

    # Use existing chain validation/flock/fsync. No synthesized legacy safe=True event.
    return NativeCampaign._locked(campaign, append)
