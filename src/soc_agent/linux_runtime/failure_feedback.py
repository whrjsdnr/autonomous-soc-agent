"""Authenticated failure opinions, immutable snapshots, existing candidate generator."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Literal, Self
from uuid import UUID

from pydantic import Field, JsonValue, model_validator

from soc_agent.experience.failure import FailureQuery, capture_failure
from soc_agent.improvement_candidates.generation import generate
from soc_agent.improvement_candidates.models import DatasetBinding, ImprovementCandidate
from soc_agent.improvement_candidates.runtime_models import (
    RuntimeFailurePattern,
    RuntimeFailurePatternContent,
)
from soc_agent.improvement_dataset.models import ArtifactReference
from soc_agent.linux_runtime.feedback_loop import authenticated_uid
from soc_agent.review.identity import content_digest
from soc_agent.security_ai.external.models import Hash, Snapshot, content_digest_payload
from soc_agent.state.evidence import UTCTimestamp, utc_now

if TYPE_CHECKING:
    from soc_agent.linux_runtime.service import LinuxMonitor


class FailureFeedbackRequest(Snapshot):
    feedback_id: UUID
    query: FailureQuery
    expected_experience_id: Hash
    reason_code: Literal[
        "OBSERVED_RUNTIME_FAILURE", "EXPECTED_RULE_MISSING", "INSUFFICIENT_CONTEXT"
    ]
    supersedes: UUID | None = None


class FailureFeedback(Snapshot):
    contract_version: Literal["soc-failure-feedback:v1"] = "soc-failure-feedback:v1"
    request: FailureFeedbackRequest
    experience: dict[str, JsonValue]
    reviewer_uid: int = Field(ge=0, strict=True)
    reviewer_assurance: Literal["OS_PEER_IDENTITY"] = "OS_PEER_IDENTITY"
    reviewed_at: UTCTimestamp
    feedback_digest: Hash

    @model_validator(mode="after")
    def digest(self) -> Self:
        if self.request.expected_experience_id != self.experience.get(
            "experience_id"
        ) or self.experience.get("query") != self.request.query.model_dump(mode="json"):
            raise ValueError("FAILURE_FEEDBACK_BINDING_REJECTED")
        if (
            content_digest_payload(
                {k: v for k, v in self.experience.items() if k != "experience_id"}
            )
            != self.experience["experience_id"]
        ):
            raise ValueError("FAILURE_EXPERIENCE_DIGEST_REJECTED")
        if (
            content_digest_payload(self.model_dump(mode="json", exclude={"feedback_digest"}))
            != self.feedback_digest
        ):
            raise ValueError("FAILURE_FEEDBACK_DIGEST_REJECTED")
        return self


class FailureFeedbackLoop:
    def __init__(self, monitor: LinuxMonitor) -> None:
        self.monitor, self.store = monitor, monitor.store

    def events(self, kind: str) -> list[dict[str, JsonValue]]:
        self.store.verify_audit()
        with self.store.database.transaction(write=False) as c:
            return [
                json.loads(r[0])["details"]
                for r in c.execute("SELECT payload FROM monitor_audit ORDER BY sequence")
                if json.loads(r[0])["kind"] == kind
            ]

    def records(self) -> tuple[FailureFeedback, ...]:
        values = tuple(
            FailureFeedback.model_validate(v["record"]) for v in self.events("FAILURE_FEEDBACK")
        )
        ids = set()
        latest = {}
        for value in values:
            key = (content_digest(value.request.query), value.reviewer_uid)
            old = latest.get(key)
            if value.request.feedback_id in ids or value.request.supersedes != (
                old.request.feedback_id if old else None
            ):
                raise ValueError("FAILURE_FEEDBACK_HISTORY_REJECTED")
            ids.add(value.request.feedback_id)
            latest[key] = value
        return values

    def active(self) -> tuple[FailureFeedback, ...]:
        latest = {}
        for value in self.records():
            latest[content_digest(value.request.query), value.reviewer_uid] = value
        for value in latest.values():
            if capture_failure(self.monitor, value.request.query) != value.experience:
                raise ValueError("STALE_FAILURE_FEEDBACK")
        return tuple(sorted(latest.values(), key=lambda v: str(v.request.feedback_id)))

    def submit(self, request: FailureFeedbackRequest, peer_socket) -> FailureFeedback:
        if peer_socket is None:
            raise ValueError("OS_PEER_IDENTITY_REQUIRED")
        uid = authenticated_uid(peer_socket)
        request = FailureFeedbackRequest.model_validate(request.model_dump())
        experience = capture_failure(self.monitor, request.query)
        if experience["experience_id"] != request.expected_experience_id:
            raise ValueError("STALE_FAILURE_EXPERIENCE")
        from soc_agent.linux_runtime.feedback_loop import RuntimeFeedbackLoop

        if any(
            v.request.feedback_id == request.feedback_id
            for v in RuntimeFeedbackLoop(self.monitor).records()
        ):
            raise ValueError("CROSS_FAMILY_FEEDBACK_ID_CONFLICT")
        values = self.records()
        for value in values:
            if value.request.feedback_id == request.feedback_id:
                if (
                    value.request != request
                    or value.reviewer_uid != uid
                    or value.experience != experience
                ):
                    raise ValueError("CONFLICTING_FAILURE_FEEDBACK_RETRY")
                return value
        previous = next(
            (
                v
                for v in reversed(values)
                if v.request.query == request.query and v.reviewer_uid == uid
            ),
            None,
        )
        if request.supersedes != (previous.request.feedback_id if previous else None):
            raise ValueError("EXPLICIT_FAILURE_CORRECTION_REQUIRED")
        body = {
            "contract_version": "soc-failure-feedback:v1",
            "request": request.model_dump(mode="json"),
            "experience": experience,
            "reviewer_uid": uid,
            "reviewer_assurance": "OS_PEER_IDENTITY",
            "reviewed_at": utc_now().isoformat().replace("+00:00", "Z"),
        }
        value = FailureFeedback.model_validate_json(
            json.dumps(body | {"feedback_digest": content_digest_payload(body)})
        )
        with self.store.database.transaction() as c:
            self.store._audit(c, "FAILURE_FEEDBACK", {"record": value.model_dump(mode="json")})
        return value

    def candidates(self) -> tuple[ImprovementCandidate, ...]:
        candidates = []
        for kind in ("SUSPECTED_MISS", "LLM_FAILURE", "TOOL_FAILURE", "INVESTIGATION_FAILURE"):
            values = [v for v in self.active() if v.request.query.kind == kind]
            # Correction copies of one snapshot never create extra support.
            values = list({v.experience["experience_id"]: v for v in values}.values())
            if not values:
                continue
            digest = content_digest_payload(
                {
                    "schema_version": "failure-review-dataset:v1",
                    "feedback": sorted(v.feedback_digest for v in values),
                }
            )
            content = RuntimeFailurePatternContent(
                dataset=DatasetBinding(
                    dataset_id=digest, dataset_version=digest, manifest_digest=digest
                ),
                pattern_type=kind,
                supporting_sample_refs=tuple(
                    sorted(
                        (
                            ArtifactReference(
                                identity=v.experience["experience_id"],
                                digest=content_digest_payload(v.experience),
                            )
                            for v in values
                        ),
                        key=lambda r: r.identity,
                    )
                ),
                supporting_feedback_refs=tuple(
                    sorted(
                        (
                            ArtifactReference(
                                identity=content_digest_payload(
                                    {"feedback_id": str(v.request.feedback_id)}
                                ),
                                digest=v.feedback_digest,
                            )
                            for v in values
                        ),
                        key=lambda r: r.identity,
                    )
                ),
                occurrence_count=len(values),
            )
            candidates.extend(
                generate(RuntimeFailurePattern(pattern_id=content_digest(content), content=content))
            )
        return tuple(candidates)

    def prepare_candidates(self) -> tuple[ImprovementCandidate, ...]:
        existing = {
            v["candidate"]["candidate_id"]: v for v in self.events("FAILURE_REVIEW_CANDIDATE")
        }
        result = []
        with self.store.database.transaction() as c:
            for value in self.candidates():
                if value.candidate_id in existing:
                    old = ImprovementCandidate.model_validate(
                        existing[value.candidate_id]["candidate"]
                    )
                    if old.content != value.content:
                        raise ValueError("FAILURE_CANDIDATE_CONFLICT")
                    result.append(old)
                else:
                    self.store._audit(
                        c,
                        "FAILURE_REVIEW_CANDIDATE",
                        {
                            "candidate": value.model_dump(mode="json"),
                            "eligibility": "REQUIRES_INDEPENDENT_HOLDOUT_OR_RELIABILITY_REPLAY",
                            "risk": "REVIEW_ONLY_NO_AUTHORITY",
                            "human_review_status": "PENDING_REVIEW",
                        },
                    )
                    result.append(value)
        return tuple(result)

    def candidate(self, identity: Hash) -> ImprovementCandidate:
        values = [
            v
            for v in self.events("FAILURE_REVIEW_CANDIDATE")
            if v["candidate"]["candidate_id"] == identity
        ]
        if len(values) != 1:
            raise ValueError("FAILURE_CANDIDATE_MISSING_OR_DUPLICATE")
        value = ImprovementCandidate.model_validate(values[0]["candidate"])
        if not any(v.content == value.content for v in self.candidates()):
            raise ValueError("STALE_FAILURE_CANDIDATE")
        return value

    def observed_metrics(self) -> dict[str, JsonValue]:
        """Audit telemetry only, not a matched baseline/candidate reliability experiment."""
        self.store.verify_audit()
        with self.store.database.transaction(write=False) as c:
            events = self.monitor.simulation._events(c)
        started = sum(e["kind"] == "LLM_INVOCATION_STARTED" for e in events)
        failures = [e for e in events if e["kind"] == "LLM_INVOCATION_FAILED"]
        timeouts = sum(e["details"].get("category") == "LLMTimeoutError" for e in failures)
        responses = sum(e["kind"] == "LLM_RESPONSE_RECEIVED" for e in events)
        llm_complete = responses + len(failures) == started
        attempts = sum(e["kind"] == "INVESTIGATION_STARTED" for e in events)
        finished = sum(
            e["kind"]
            in {
                "INVESTIGATION_DONE",
                "INVESTIGATION_DONE_READ_ONLY",
                "INVESTIGATION_DONE_SCRIPTED",
                "INVESTIGATION_FAILED",
                "INVESTIGATION_BLOCKED",
                "INVESTIGATION_PENDING",
            }
            for e in events
        )
        successes = sum(
            e["kind"]
            in ("INVESTIGATION_DONE", "INVESTIGATION_DONE_READ_ONLY", "INVESTIGATION_DONE_SCRIPTED")
            for e in events
        )
        with self.store.database.transaction(write=False) as c:
            rows = list(c.execute("SELECT * FROM monitor_findings"))
        results = []
        for row in rows:
            self.store._decode(row)
            if row["result"]:
                results.append(json.loads(row["result"]))
        # Failed investigations do not retain every attempted tool result. Never claim zero.
        calls = (
            None
            if any(row["result"] is None for row in rows)
            or any("investigation" not in r for r in results)
            else sum(len(r["investigation"]["plan"]["steps"]) for r in results)
        )
        return {
            "scope": "LOCAL_AUDIT_TELEMETRY_NOT_IMPROVEMENT_EFFECT",
            "llm_invocations_started": started,
            "llm_failures_recorded": len(failures),
            "timeout_rate": timeouts / started if started and llm_complete else None,
            "failure_rate": len(failures) / started if started and llm_complete else None,
            "successful_investigation_rate": successes / attempts
            if attempts and finished == attempts
            else None,
            "incomplete_llm_invocations": started - responses - len(failures),
            "tool_call_count": calls,
            "invocation_budget_violations": sum(e["kind"] == "LLM_BUDGET_EXCEEDED" for e in events),
        }

    def evaluate(self, identity: Hash) -> dict[str, JsonValue]:
        value = self.candidate(identity)
        body = {
            "candidate_reference": identity,
            "candidate_digest": content_digest(value),
            "verdict": "BLOCKED",
            "reason": "INDEPENDENT_HOLDOUT_OR_MATCHED_RELIABILITY_REPLAY_MISSING",
            "metrics": {
                "timeout_rate": None,
                "failure_rate": None,
                "successful_investigation_rate": None,
                "tool_call_count": None,
                "invocation_budget_violations": None,
            },
            "observed_runtime_metrics": self.observed_metrics(),
            "promotion": "BLOCKED",
            "automatic_application": "DISABLED",
        }
        body["evaluation_id"] = content_digest_payload(body)
        with self.store.database.transaction() as c:
            if not any(
                v.get("evaluation_id") == body["evaluation_id"]
                for v in self.events("RUNTIME_OFFLINE_EVALUATION")
            ):
                self.store._audit(c, "RUNTIME_OFFLINE_EVALUATION", body)
        return body
