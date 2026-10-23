"""Ordinary-UID budget adapter; delegates authentication/capture to the pinned Supervisor.

The legacy Phase D campaign stays immutable. This module is not part of the Root
execution image and does not install, invoke sudo, attach, or execute commands.
"""

import json
import os
from collections.abc import Callable
from pathlib import Path

from soc_agent.security_ai.ebpf_tc.dependencies import read_held
from soc_agent.security_ai.native_campaign import NativeCampaign, sha

CAMPAIGN = "SOC_NATIVE_STABILIZATION"


class StabilizationCampaign(NativeCampaign):
    def __init__(self, directory: Path, batch: str) -> None:
        self.directory = directory
        self.budget_body = read_held(directory / "budget.json", owner=os.getuid(), limit=65536)
        self.baseline_body = read_held(directory / "baseline.json", owner=os.getuid(), limit=262144)
        self.budget = json.loads(self.budget_body)
        self.controller_sha = sha(Path(__file__).read_bytes())
        if batch not in {f"BATCH{i}" for i in range(1, 6)}:
            raise ValueError("STABILIZATION_BATCH_IDENTITY")
        self.batch = batch
        expected = dict(
            native_used=0,
            root_installations_used=0,
            native_max=10,
            root_installations_max=10,
            native_per_batch_max=2,
            root_per_batch_max=2,
        )
        if (
            self.budget.get("campaign") != CAMPAIGN
            or self.budget.get("execution_contract") != "EXACT_SHA_SINGLE_ATTEMPT_V1"
            or self.budget.get("controller_sha256") != self.controller_sha
            or any(
                type(self.budget.get(k)) is not int or self.budget[k] != v
                for k, v in expected.items()
            )
        ):
            raise ValueError("STABILIZATION_BUDGET_CONTRACT")

    def _locked(self, operation: Callable[[list[dict]], dict]) -> dict:
        def guarded(rows: list[dict]) -> dict:
            if any(
                r.get("event") == "NATIVE_ATTEMPT_RESERVED"
                and r.get("batch") not in {f"BATCH{i}" for i in range(1, 6)}
                for r in rows
            ):
                raise ValueError("STABILIZATION_LEDGER_BATCH")
            event = operation(rows)
            if event["event"] == "NATIVE_ATTEMPT_RESERVED":
                reservations = [r for r in rows if r["event"] == "NATIVE_ATTEMPT_RESERVED"]
                finished = {
                    r.get("attempt_id") for r in rows if r["event"] == "NATIVE_ATTEMPT_FINISHED"
                }
                reviewed = {
                    r.get("attempt_id")
                    for r in rows
                    if r["event"] == "DIAGNOSTIC_E2E_EVIDENCE_REVIEW_COMPLETED"
                    and r.get("safe_for_next_attempt") is True
                }
                if any(
                    r["attempt_id"] not in finished or r["attempt_id"] not in reviewed
                    for r in reservations
                ):
                    raise ValueError("STABILIZATION_PREVIOUS_ATTEMPT_UNREVIEWED")
                batch = [r for r in reservations if r["batch"] == self.batch]
                if (
                    len(batch) + 1 > 2
                    or sum(r["root_cost"] for r in batch) + event["root_cost"] > 2
                ):
                    raise ValueError("STABILIZATION_BATCH_BUDGET_EXHAUSTED")
                event.update(batch=self.batch, controller_sha256=self.controller_sha)
            return event

        return super()._locked(guarded)

    def reserve(
        self,
        identity: dict,
        scope: dict,
        dns_scope: dict,
        approval_file: Path,
        approval_sha: str,
        *,
        root_cost: int,
        git_commit: str | None = None,
    ) -> dict:
        approval = json.loads(read_held(approval_file, owner=os.getuid(), limit=65536))
        if (
            approval.get("batch") != self.batch
            or approval.get("controller_sha256") != self.controller_sha
            or approval.get("budget_sha256") != sha(self.budget_body)
        ):
            raise ValueError("STABILIZATION_APPROVAL_BINDING")
        return super().reserve(
            identity,
            scope,
            dns_scope,
            approval_file,
            approval_sha,
            root_cost=root_cost,
            git_commit=git_commit,
        )


def execute(
    directory: Path,
    manifest: str,
    image: str,
    *,
    campaign: Path,
    batch: str,
    approval_file: Path,
    approval_sha: str,
) -> dict:
    from soc_agent.security_ai.ebpf_tc import phase_d
    from soc_agent.security_ai.ebpf_tc.unified_image import installed_release

    value = phase_d.validate(directory, manifest, image)
    ledger = StabilizationCampaign(campaign, batch)
    identity = dict(
        manifest=manifest, bundle=value["bundle"], image=image, tcx_manifest=value["tcx_manifest"]
    )
    dns = json.loads((directory / "dns-sidecar/release.json").read_bytes())["scope"]
    receipt = json.loads(read_held(approval_file, owner=os.getuid(), limit=65536))
    reserved = ledger.reserve(
        identity,
        value["scope"],
        dns,
        approval_file,
        approval_sha,
        root_cost=int(installed_release().identity != value["tcx_manifest"]),
        git_commit=receipt.get("artifact_git_commit"),
    )
    try:
        result = phase_d.execute(directory, manifest, image, gui=False)
    except BaseException as exc:
        try:
            ledger.finish(
                reserved["attempt_id"],
                outcome="FAILED",
                evidence=dict(
                    exception_class=type(exc).__name__,
                    errno=getattr(exc, "errno", None),
                    signal=getattr(exc, "signum", None),
                ),
            )
        except (OSError, ValueError) as audit_error:
            exc.add_note("STABILIZATION_FINAL_AUDIT_FAILED:" + type(audit_error).__name__)
            raise exc from audit_error
        raise
    failed = (
        bool(result.get("last_error"))
        or result.get("cleanup_status") != "PROCESS_AND_AUDIT_VERIFIED"
    )
    ledger.finish(
        reserved["attempt_id"],
        outcome="FAILED" if failed else "RETURNED_PENDING_EVIDENCE_REVIEW",
        evidence=dict(
            result_sha256=sha((directory / "supervised-result.json").read_bytes()),
            application_session=result.get("broker_session"),
            native_verified=False,
        ),
    )
    return result
