"""Opt-in versioned admission amendment; inert without separately pinned human approval.

The old controller/budget and negative review are immutable. This adapter uses
its hash-chain writer and the same global/batch counters. It authorizes no Root
command and performs no authentication, installation, capture or network I/O.
"""

import hashlib
import time
from pathlib import Path
from typing import Literal

from soc_agent.security_ai.ebpf_tc.reassessment import (
    Binding,
    Contract,
    Hash,
    Identity,
    digest,
    held_json,
)
from soc_agent.security_ai.native_campaign import NativeCampaign
from soc_agent.security_ai.stabilization_campaign import StabilizationCampaign


class AdmissionAmendment(Contract):
    contract: Literal["SOC_REASSESSMENT_ADMISSION_AMENDMENT_V1"] = (
        "SOC_REASSESSMENT_ADMISSION_AMENDMENT_V1"
    )
    decision: Literal["APPROVED"]
    approver: Identity
    human_reference_sha: Hash
    implementation_sha: Hash
    base_controller_sha: Hash
    budget_sha: Hash
    baseline_sha: Hash
    binding: Binding
    reassessment_record_sha: Hash
    review_receipt_sha: Hash
    expires_at: int
    # Approval of THIS versioned admission rule is separate from execution approval.
    activate_versioned_admission: Literal[True]
    original_result_unchanged: Literal[True] = True
    root_commands_authorized: Literal[False] = False


class ReassessedCampaign(StabilizationCampaign):
    def __init__(self, directory: Path, *, amendment_file: Path, amendment_sha: str):
        super().__init__(directory, "BATCH2")
        self.amendment = AdmissionAmendment.model_validate(held_json(amendment_file, amendment_sha))
        self.amendment_sha = amendment_sha
        a = self.amendment
        if (
            a.implementation_sha != hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
            or a.base_controller_sha != self.controller_sha
            or a.budget_sha != hashlib.sha256(self.budget_body).hexdigest()
            or a.baseline_sha != hashlib.sha256(self.baseline_body).hexdigest()
            or time.time() >= a.expires_at
        ):
            raise ValueError("REASSESSMENT_AMENDMENT_BINDING")

    def reserve(
        self, identity, scope, dns_scope, approval_file, approval_sha, *, root_cost, git_commit=None
    ):
        receipt = held_json(approval_file, approval_sha)
        a = self.amendment
        if (
            receipt.get("admission_amendment_sha") != self.amendment_sha
            or receipt.get("next_session") != a.binding.next_session
            or receipt.get("reassessment_record_sha") != a.reassessment_record_sha
            or receipt.get("r2_receipt_sha") is None
            or digest(scope) != a.binding.scope_sha
            or git_commit not in (None, a.binding.next_artifact.git_commit)
        ):
            raise ValueError("REASSESSMENT_EXECUTION_APPROVAL_BINDING")
        # One controller instance is bound to a single immutable execution receipt.
        self.execution_receipt = receipt
        self.execution_receipt_sha = approval_sha
        return super().reserve(
            identity,
            scope,
            dns_scope,
            approval_file,
            approval_sha,
            root_cost=root_cost,
            git_commit=a.binding.next_artifact.git_commit,
        )

    def _locked(self, operation):
        def guarded(rows):
            event = operation(rows)
            if event["event"] != "NATIVE_ATTEMPT_RESERVED":
                return event
            a = self.amendment
            if (
                time.time() >= a.expires_at
                or event["approval_sha256"] != self.execution_receipt_sha
            ):
                raise ValueError("REASSESSMENT_ADMISSION_EXPIRED")
            if rows[-1].get("record_sha256") != a.reassessment_record_sha:
                raise ValueError("REASSESSMENT_ADMISSION_STALE_LEDGER")
            reviews = [
                r
                for r in rows
                if r.get("event") == "SAFETY_REASSESSMENT_RECORDED_V1"
                and r.get("binding", {}).get("previous_attempt") == a.binding.previous_attempt
            ]
            if not reviews:
                raise ValueError("REASSESSMENT_ADMISSION_REVIEW_MISSING")
            review = reviews[-1]
            if (
                review.get("record_sha256") != a.reassessment_record_sha
                or review.get("receipt_sha256") != a.review_receipt_sha
                or review.get("binding") != a.binding.model_dump()
                or review.get("decision") != "ALLOW_NEXT_ADMISSION_ONLY"
                or time.time() >= review.get("expires_at", 0)
            ):
                raise ValueError("REASSESSMENT_ADMISSION_REVIEW_INVALID")
            reservations = [r for r in rows if r["event"] == "NATIVE_ATTEMPT_RESERVED"]
            finished = {
                r.get("attempt_id") for r in rows if r["event"] == "NATIVE_ATTEMPT_FINISHED"
            }
            for old in reservations:
                if old.get("attempt_id") not in finished:
                    raise ValueError("REASSESSMENT_PRIOR_ATTEMPT_UNFINISHED")
                legacy = [
                    r
                    for r in rows
                    if r["event"] == "DIAGNOSTIC_E2E_EVIDENCE_REVIEW_COMPLETED"
                    and r.get("attempt_id") == old["attempt_id"]
                ]
                if not legacy:
                    raise ValueError("REASSESSMENT_PRIOR_REVIEW_MISSING")
                if old["attempt_id"] == a.binding.previous_attempt:
                    if legacy[-1].get("record_sha256") != a.binding.negative_review_sha:
                        raise ValueError("REASSESSMENT_STALE_NEGATIVE_REVIEW")
                elif legacy[-1].get("safe_for_next_attempt") is not True:
                    raise ValueError("REASSESSMENT_OTHER_ATTEMPT_BLOCKED")
                if old.get("reassessment_record_sha") == a.reassessment_record_sha:
                    raise ValueError("REASSESSMENT_ADMISSION_REPLAY")
            batch = [r for r in reservations if r.get("batch") == "BATCH2"]
            if len(batch) >= 2 or sum(r["root_cost"] for r in batch) + event["root_cost"] > 2:
                raise ValueError("STABILIZATION_BATCH_BUDGET_EXHAUSTED")
            prior = a.binding.next_artifact
            if event["release"] != dict(
                manifest=prior.manifest,
                bundle=prior.bundle,
                image=prior.image,
                tcx_manifest=prior.root_manifest,
            ):
                raise ValueError("REASSESSMENT_NEXT_ARTIFACT")
            event.update(
                batch="BATCH2",
                controller_sha256=self.controller_sha,
                admission_amendment_sha=self.amendment_sha,
                reassessment_record_sha=a.reassessment_record_sha,
                next_session=a.binding.next_session,
                r2_receipt_sha=self.execution_receipt["r2_receipt_sha"],
            )
            return event

        return self._admission_transaction(guarded)

    def _admission_transaction(self, guarded):
        return NativeCampaign._locked(self, guarded)


class _PreviewComplete(Exception):
    def __init__(self, event):
        self.event = event


class _PreviewCampaign(ReassessedCampaign):
    """Reuse every reservation validator, abort before the chain writer appends."""

    def _admission_transaction(self, guarded):
        def inspect(rows):
            raise _PreviewComplete(guarded(rows))

        return NativeCampaign._locked(self, inspect)


def preview_reservation(
    directory: Path,
    *,
    amendment_file: Path,
    amendment_sha: str,
    identity: dict,
    scope: dict,
    dns_scope: dict,
    approval_file: Path,
    approval_sha: str,
    root_cost: int,
    git_commit: str,
) -> dict:
    """Read-only exact-approval/R1/budget validation, not a reservation or grant.

    Calls the same amendment, receipt, Scope, SHA, latest-chain, replay, previous
    failure and budget checks as reserve(). No authentication or callback runs.
    The real reserve must repeat them atomically immediately before execution.
    """
    campaign = _PreviewCampaign(
        directory, amendment_file=amendment_file, amendment_sha=amendment_sha
    )
    try:
        campaign.reserve(
            identity,
            scope,
            dns_scope,
            approval_file,
            approval_sha,
            root_cost=root_cost,
            git_commit=git_commit,
        )
    except _PreviewComplete as preview:
        event = preview.event
        return dict(
            status="PREVIEW_ONLY_NOT_RESERVED",
            native_admission=False,
            release=event["release"],
            next_session=event["next_session"],
            reassessment_record_sha=event["reassessment_record_sha"],
            native_used_if_reserved=event["native_used"],
            root_used_if_reserved=event["root_installations_used"],
        )
    raise ValueError("REASSESSMENT_PREVIEW_UNEXPECTED_RETURN")


def require_r2_reservation(
    directory: Path, *, session: str, receipt_sha: str, identity: dict
) -> None:
    """Read/validate the existing chain under its lock, without appending an event."""
    campaign = StabilizationCampaign(directory, "BATCH2")

    class Checked(Exception):
        pass

    def inspect(rows):
        matching = [
            r
            for r in rows
            if r["event"] == "NATIVE_ATTEMPT_RESERVED"
            and r.get("next_session") == session
            and r.get("r2_receipt_sha") == receipt_sha
            and r.get("release") == identity
            and r.get("admission_amendment_sha")
            and r.get("reassessment_record_sha")
        ]
        finished = {r.get("attempt_id") for r in rows if r["event"] == "NATIVE_ATTEMPT_FINISHED"}
        if len(matching) != 1 or matching[0]["attempt_id"] in finished:
            raise ValueError("R2_APPROVED_RESERVATION_REQUIRED")
        reviews = [
            r for r in rows if r.get("record_sha256") == matching[0]["reassessment_record_sha"]
        ]
        if (
            len(reviews) != 1
            or reviews[0].get("decision") != "ALLOW_NEXT_ADMISSION_ONLY"
            or time.time() >= reviews[0].get("expires_at", 0)
        ):
            raise ValueError("R2_REASSESSMENT_EXPIRED_OR_MISSING")
        raise Checked

    try:
        NativeCampaign._locked(campaign, inspect)
    except Checked:
        return


def execute(
    directory: Path,
    manifest: str,
    image: str,
    *,
    campaign: Path,
    amendment_file: Path,
    amendment_sha: str,
    approval_file: Path,
    approval_sha: str,
    traffic_file: Path,
    traffic_sha: str,
    claim_file: Path,
    management_file: Path | None = None,
    management_sha: str | None = None,
) -> dict:
    """Existing Supervisor/TTY path, once, after independent amendment + execution + R2 grants."""
    import json

    from soc_agent.security_ai.ebpf_tc import phase_d
    from soc_agent.security_ai.ebpf_tc.r2_diagnostic import LaunchApproval, R2Launcher
    from soc_agent.security_ai.ebpf_tc.unified_image import installed_release

    value = phase_d.validate(directory, manifest, image)
    ledger = ReassessedCampaign(
        campaign, amendment_file=amendment_file, amendment_sha=amendment_sha
    )
    receipt = held_json(approval_file, approval_sha)
    binding = ledger.amendment.binding
    launch = LaunchApproval(
        traffic_file, traffic_sha, binding.next_session, binding.next_artifact, claim_file, campaign
    )
    R2Launcher(launch)  # Validate without traffic/claim/authentication before reserving.
    if receipt.get("r2_receipt_sha") != traffic_sha:
        raise ValueError("R2_EXECUTION_RECEIPT_MISMATCH")
    identity = dict(
        manifest=manifest, bundle=value["bundle"], image=image, tcx_manifest=value["tcx_manifest"]
    )
    dns = json.loads((directory / "dns-sidecar/release.json").read_bytes())["scope"]
    root_cost = int(value["tcx_manifest"] != binding.previous_artifact.root_manifest)
    from soc_agent.security_ai.ebpf_tc.operational_recovery import readiness

    if "recovery" in value:
        checked = readiness(
            directory,
            manifest,
            image,
            campaign=campaign,
            amendment_file=amendment_file,
            amendment_sha=amendment_sha,
            approval_file=approval_file,
            approval_sha=approval_sha,
            traffic_file=traffic_file,
            traffic_sha=traffic_sha,
            claim_file=claim_file,
        )
        if checked["status"] != "EXECUTION_READY":
            raise ValueError("RECOVERY_EXECUTION_NOT_READY:" + checked.get("error", "BLOCKED"))
    if "recovery" not in value:
        root_cost = int(installed_release().identity != value["tcx_manifest"])
    if management_file is not None or management_sha is not None:
        if management_file is None or management_sha is None:
            raise ValueError("EXECUTION_MANAGEMENT_POLICY_REQUIRED")
        from soc_agent.security_ai.ebpf_tc.execution_management import verify_policy

        verify_policy(management_file, management_sha, ledger, binding)
        return _managed_execution(
            directory,
            manifest,
            image,
            ledger=ledger,
            launch=launch,
            reserve=lambda: ledger.reserve(
                identity,
                value["scope"],
                dns,
                approval_file,
                approval_sha,
                root_cost=root_cost,
                git_commit=binding.next_artifact.git_commit,
            ),
            management_file=management_file,
            management_sha=management_sha,
        )
    reserved = ledger.reserve(
        identity,
        value["scope"],
        dns,
        approval_file,
        approval_sha,
        root_cost=root_cost,
        git_commit=binding.next_artifact.git_commit,
    )
    try:
        result = phase_d.execute(directory, manifest, image, gui=False, r2_approval=launch)
    except BaseException as exc:
        try:
            ledger.finish(
                reserved["attempt_id"],
                outcome="FAILED",
                evidence=dict(
                    exception_class=type(exc).__name__, errno=getattr(exc, "errno", None)
                ),
            )
        except (OSError, ValueError) as audit_error:
            exc.add_note("REASSESSMENT_FINAL_AUDIT_FAILED:" + type(audit_error).__name__)
            raise exc from audit_error
        raise
    failed = bool(result.get("last_error")) or result.get("cleanup_status") != (
        "PROCESS_AND_AUDIT_VERIFIED"
    )
    ledger.finish(
        reserved["attempt_id"],
        outcome="FAILED" if failed else ("RETURNED_PENDING_EVIDENCE_REVIEW"),
        evidence=dict(
            result_sha256=hashlib.sha256(
                (directory / "supervised-result.json").read_bytes()
            ).hexdigest(),
            application_session=result.get("broker_session"),
            native_verified=False,
        ),
    )
    return result


def _managed_execution(
    directory, manifest, image, *, ledger, launch, reserve, management_file, management_sha
):
    from soc_agent.security_ai.ebpf_tc import phase_d
    from soc_agent.security_ai.ebpf_tc.execution_management import (
        ExecutionControl,
        LifecycleJournal,
    )
    from soc_agent.security_ai.ebpf_tc.termination import termination_boundary

    # Existing directory is a permanent one-shot marker, including after reboot.
    journal = LifecycleJournal.create(
        directory / "execution-management",
        digest(ledger.amendment.binding.model_dump()),
        ledger.amendment.binding.next_session,
    )
    control = ExecutionControl(
        journal,
        reserve,
        policy_file=management_file,
        policy_sha=management_sha,
        campaign=ledger,
        binding=ledger.amendment.binding,
    )
    with control, termination_boundary():
        try:
            result = phase_d.execute(
                directory, manifest, image, gui=False, r2_approval=launch, execution_control=control
            )
        except BaseException as exc:
            observed = journal.end(failed=True)
            if control.reservation is not None:
                if observed["disposition"] == "CANCELLED_BEFORE_EXECUTION":
                    # Diagnostic closure only: no refund, replay unlock or legacy safe=True.
                    NativeCampaign._locked(
                        ledger,
                        lambda rows: dict(
                            event="EXECUTION_PREAUTH_CANCELLED_V1",
                            attempt_id=control.reservation["attempt_id"],
                            observation=observed,
                            approval_reusable=False,
                            budget_action="KEEP_RESERVATION_CHARGE",
                        ),
                    )
                else:
                    ledger.finish(
                        control.reservation["attempt_id"],
                        outcome="FAILED",
                        evidence=dict(exception_class=type(exc).__name__, **observed),
                    )
            raise
        failed = bool(result.get("last_error") or result.get("first_failure")) or (
            result.get("cleanup_status") != "PROCESS_AND_AUDIT_VERIFIED"
        )
        observed = journal.end(failed=failed)
        if control.reservation is None:
            raise ValueError("EXECUTION_RESERVATION_NOT_REACHED")
        ledger.finish(
            control.reservation["attempt_id"],
            outcome="FAILED" if failed else "RETURNED_PENDING_EVIDENCE_REVIEW",
            evidence=dict(
                result_sha256=hashlib.sha256(
                    (directory / "supervised-result.json").read_bytes()
                ).hexdigest(),
                application_session=result.get("broker_session"),
                native_verified=False,
                **observed,
            ),
        )
        return dict(result, execution_management=observed)
