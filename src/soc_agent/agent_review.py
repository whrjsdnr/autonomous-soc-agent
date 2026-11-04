"""Human batch review over existing exact sealed-job Action approvals.

No future-input delegation, capture, model execution, API call or policy issuer.
Only an explicit local operator decision publishes the existing worker's receipts.
"""

import hashlib
import json
import os
from datetime import datetime, timedelta
from pathlib import Path

from pydantic import Field, JsonValue

from soc_agent.approval import ApprovalManager, ApprovalRequest
from soc_agent.continuous.cli import observed_status
from soc_agent.continuous.models import ContinuousConfig
from soc_agent.review.persistence.secure_storage import (
    create_private_directory,
    create_private_file,
    validate_file,
)
from soc_agent.runtime_lock import exclusive_runtime_lock
from soc_agent.security_ai.research.environment import read_local
from soc_agent.security_ai.research.models import SPECS, Frozen, digest
from soc_agent.security_ai.tcx_analysis import METADATA, analysis_action
from soc_agent.security_ai.tcx_input import candidates
from soc_agent.security_ai.workflow_models import JOB
from soc_agent.state.evidence import utc_now


class ModelReviewItem(Frozen):
    job: str
    input_sha256: str
    eligible: int
    calls: int
    action: dict[str, JsonValue]
    family: str = "NETWORK_RF_LR"
    model_details: dict[str, JsonValue] = Field(default_factory=dict)
    evidence_revision: str | None = None


class ModelReviewBatch(Frozen):
    runtime_session: str
    request_sha256: str
    maximum_invocations: int
    previous_invocations: int
    models: dict[str, JsonValue]
    jobs: tuple[ModelReviewItem, ...]
    authentication_maximum_invocations: int = 0
    authentication_previous_invocations: int = 0


def _context(review: Path):
    from soc_agent.agent_runtime import verify_review
    from soc_agent.continuous.cli import observation

    request = verify_review(review)
    runtime = review / "future-runtime"
    cfg = ContinuousConfig.model_validate_json(read_local(review / "runtime-config-v2.json", 32768))
    record = observation(runtime)
    if (
        record is None
        or record["store_id"] != request["runtime_session"]
        or record["configuration"] != cfg.model_dump(mode="json")
        or cfg.source != "NATIVE_SERVICE"
        or observed_status(runtime).get("state") != "RUNNING"
        or cfg.native_model_approvals is None
        or read_local(runtime / "code-identity", 128).decode() != request["code_identity"]
    ):
        raise ValueError("MODEL_REVIEW_REQUIRES_BOUND_RUNNING_NATIVE_SESSION")
    return request, cfg, runtime


def pending_models(review: Path) -> ModelReviewBatch:
    request, cfg, runtime = _context(review)
    limit = request["model_action_review"]["max_model_invocations"]
    if type(limit) is not int or not 1 <= limit <= 16:
        raise ValueError("MODEL_REVIEW_INVOCATION_SCOPE_INVALID")
    if_limit = request.get("authentication_model_action_review", {}).get("max_model_invocations", 0)
    if type(if_limit) is not int or not 0 <= if_limit <= 16:
        raise ValueError("IF_MODEL_REVIEW_INVOCATION_SCOPE_INVALID")
    previous_if = if_grants = 0
    previous = 0
    grant_count = 0
    jobs = []
    for path in sorted((runtime / "inputs").glob("*.json")):
        body = read_local(path, 1024 * 1024)
        job = JOB.validate_json(body)
        if job.kind == "authentication_window" and job.host_binding is not None:
            if not if_limit:
                continue
            from soc_agent.continuous.host_authentication import validate_job
            from soc_agent.security_ai.authentication_action import analysis_action as if_action

            pin = digest(job.model_dump(mode="json"))
            if path.stem != pin:
                raise ValueError("IF_MODEL_REVIEW_JOB_PIN_CHANGED")
            bound = job.host_binding
            if (
                str(bound.session) != request["runtime_session"]
                or bound.runtime_directory != str(runtime)
                or bound.scope_sha256 != cfg.input_sha256
                or bound.namespace != cfg.namespace
                or tuple(job.packages) != cfg.authentication_packages
            ):
                raise ValueError("IF_MODEL_REVIEW_SESSION_SCOPE_MISMATCH")
            contract = validate_job(job)
            out = runtime / "analysis" / ("run-" + pin)
            proposed = if_action(job, out)
            grant = cfg.native_model_approvals / (pin + ".json")
            if grant.exists():
                old = ApprovalRequest.model_validate_json(read_local(grant, 32768))
                if (
                    old.action_id != proposed.action_id
                    or old.action_input_json != proposed.tool_input
                ):
                    raise ValueError("IF_MODEL_REVIEW_EXISTING_GRANT_CHANGED")
                previous_if += 1
                if_grants += 1
            elif not out.exists():
                jobs.append(
                    ModelReviewItem(
                        job=pin,
                        input_sha256=hashlib.sha256(body).hexdigest(),
                        eligible=1,
                        calls=1,
                        action=proposed.model_dump(mode="json", exclude={"created_at"}),
                        family="AUTHENTICATION_IF",
                        model_details=contract,
                        evidence_revision=bound.evidence_revision,
                    )
                )
            continue
        if job.kind != "tcx_analysis":
            continue
        pin = digest(job.model_dump(mode="json"))
        if path.stem != pin:
            raise ValueError("MODEL_REVIEW_JOB_PIN_CHANGED")
        if job.origin != "REAL_NATIVE":
            continue
        _, transport, rows = candidates(job)
        if (
            job.namespace != cfg.namespace
            or tuple(job.profiles) != cfg.profiles
            or transport["processing"]["plan"]["source_digest"] != cfg.input_sha256
            or job.release_manifest != request["root_file_map_release_identity"]
        ):
            raise ValueError("MODEL_REVIEW_CAPTURE_SCOPE_MISMATCH")
        eligible = sum(bool(r["eligible"]) for r in rows)
        calls = eligible * len(job.profiles)
        out = runtime / "analysis" / ("run-" + pin)
        action = analysis_action(job, out)
        grant = cfg.native_model_approvals / (pin + ".json")
        if grant.exists():
            prior = ApprovalRequest.model_validate_json(read_local(grant, 32768))
            if prior.action_id != action.action_id or prior.action_input_json != action.tool_input:
                raise ValueError("MODEL_REVIEW_EXISTING_GRANT_BINDING_MISMATCH")
            previous += calls
            grant_count += 1
            continue
        if not calls or out.exists():
            continue  # Preserve completed, failed and unapproved historical attempts.
        jobs.append(
            ModelReviewItem(
                job=pin,
                input_sha256=hashlib.sha256(body).hexdigest(),
                eligible=eligible,
                calls=calls,
                action=action.model_dump(mode="json", exclude={"created_at"}),
            )
        )
    network_jobs = [j for j in jobs if j.family == "NETWORK_RF_LR"]
    if_jobs = [j for j in jobs if j.family == "AUTHENTICATION_IF"]
    if previous_if + len(if_jobs) > if_limit or if_grants + len(if_jobs) > if_limit:
        raise ValueError("IF_MODEL_REVIEW_SCOPE_LIMIT_EXCEEDED")
    if grant_count + len(network_jobs) > 2 or previous + sum(j.calls for j in network_jobs) > limit:
        raise ValueError("MODEL_REVIEW_SCOPE_LIMIT_EXCEEDED")
    return ModelReviewBatch(
        runtime_session=request["runtime_session"],
        request_sha256=hashlib.sha256(
            read_local(review / "approval-request-final-v2.json", 131072)
        ).hexdigest(),
        maximum_invocations=limit,
        previous_invocations=previous,
        models=SPECS,
        jobs=tuple(jobs),
        authentication_maximum_invocations=if_limit,
        authentication_previous_invocations=previous_if,
    )


def _write_new(path: Path, value: dict) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(value, stream, indent=2)
        stream.flush()
        os.fsync(stream.fileno())


def approve_models(review: Path, batch_digest: str, *, actor: str, confirmed: bool) -> dict:
    if confirmed is not True or not actor.strip():
        raise ValueError("EXPLICIT_HUMAN_MODEL_REVIEW_REQUIRED")
    request, cfg, runtime = _context(review)
    lock = cfg.native_model_approvals / ".operator-review.lock"
    try:
        create_private_file(lock)
    except FileExistsError:
        pass  # Existing coordination file is validated, never repaired or truncated.
    validate_file(lock)
    with exclusive_runtime_lock(lock):
        batch = pending_models(review)
        if digest(batch.model_dump(mode="json")) != batch_digest:
            raise ValueError("MODEL_REVIEW_BATCH_CHANGED_REVIEW_AGAIN")
        if not batch.jobs:
            raise ValueError("MODEL_REVIEW_NO_ELIGIBLE_JOBS")
        now = utc_now()
        expiry = min(now + timedelta(hours=1), datetime.fromisoformat(request["expires_at"]))
        if expiry <= now:
            raise ValueError("MODEL_REVIEW_PARENT_EXPIRED")
        archive = runtime / "operator-model-reviews" / batch_digest
        create_private_directory(archive, exist_ok=False)
        _write_new(
            archive / "human-decision.json",
            dict(
                actor=actor,
                decision="APPROVED_WITH_CONDITIONS",
                explicit_human_confirmation=True,
                decided_at=now.isoformat(),
                batch=batch.model_dump(mode="json"),
            ),
        )
        for item in batch.jobs:
            _context(review)  # No grants after the live Session has ended.
            body = read_local(runtime / "inputs" / (item.job + ".json"), 1024**2)
            if hashlib.sha256(body).hexdigest() != item.input_sha256:
                raise ValueError("MODEL_REVIEW_INPUT_CHANGED_AFTER_CONFIRMATION")
            job = JOB.validate_json(body)
            metadata = METADATA
            if item.family == "AUTHENTICATION_IF":
                from soc_agent.security_ai.authentication_action import METADATA as IF_METADATA
                from soc_agent.security_ai.authentication_action import analysis_action as if_action

                action = if_action(job, runtime / "analysis" / ("run-" + item.job))
                metadata = IF_METADATA
            else:
                action = analysis_action(job, runtime / "analysis" / ("run-" + item.job))
            if action.model_dump(mode="json", exclude={"created_at"}) != item.action:
                raise ValueError("MODEL_REVIEW_ACTION_CHANGED_AFTER_CONFIRMATION")
            manager = ApprovalManager()
            pending = manager.create(
                incident_id=action.incident_id,
                metadata=metadata,
                reason="Explicit local operator review of exactly displayed sealed ELIGIBLE jobs",
                action_id=action.action_id,
                action_input_json=action.tool_input,
                expires_at=expiry,
            )
            approved = manager.approve(pending.approval_id, actor=actor)
            _write_new(archive / (item.job + "-request.json"), pending.model_dump(mode="json"))
            receipt = archive / (item.job + "-approval.json")
            _write_new(receipt, approved.model_dump(mode="json"))
            # Atomic no-overwrite publication, exactly as the existing terminal review.
            os.link(receipt, cfg.native_model_approvals / (item.job + ".json"))
        descriptor = os.open(cfg.native_model_approvals, os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    return dict(
        status="EXACT_DISPLAYED_ACTIONS_APPROVED", jobs=len(batch.jobs), capture_started=False
    )
