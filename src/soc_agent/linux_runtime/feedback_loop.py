"""Monitor-owned, immutable human opinions and explicit offline trials. No activation.

Core checkpoint experiences and provider-confirmed feedback remain unchanged. This
versioned adapter references real monitor results, never fabricated core workflow traces.
"""

import json
import os
import socket
import struct
from hashlib import sha256
from pathlib import Path
from typing import Literal, Self
from uuid import UUID

from pydantic import Field, model_validator

from soc_agent.evaluation.authentication import evaluate, fixture_dataset
from soc_agent.experience.runtime import RuntimeExperience, capture_runtime_experience
from soc_agent.improvement_candidates.generation import generate
from soc_agent.improvement_candidates.models import DatasetBinding, ImprovementCandidate
from soc_agent.improvement_candidates.runtime_models import (
    RuntimeFailurePattern,
    RuntimePatternContent,
)
from soc_agent.improvement_dataset.models import ArtifactReference
from soc_agent.improvement_review.models import ReviewDecision
from soc_agent.review.identity import content_digest
from soc_agent.security_ai.external.models import Hash, Snapshot, content_digest_payload
from soc_agent.state.evidence import UTCTimestamp, utc_now


class RuntimeFeedbackRequest(Snapshot):
    feedback_id: UUID
    finding_id: Hash
    expected_experience_id: Hash
    label: Literal["TRUE_POSITIVE", "FALSE_POSITIVE", "INCONCLUSIVE"]
    reason_code: Literal[
        "EXPECTED_ACTIVITY",
        "SUSPICIOUS_PATTERN",
        "INSUFFICIENT_CONTEXT",
        "INVESTIGATION_INACCURATE",
    ]
    supersedes: UUID | None = None
    interpretation: Literal["OPERATOR_OPINION_NOT_GROUND_TRUTH"] = (
        "OPERATOR_OPINION_NOT_GROUND_TRUTH"
    )


class RuntimeFeedback(Snapshot):
    contract_version: Literal["soc-monitor-human-feedback:v1"] = "soc-monitor-human-feedback:v1"
    request: RuntimeFeedbackRequest
    experience: RuntimeExperience
    reviewer_uid: int = Field(ge=0, strict=True)
    reviewer_assurance: Literal["OS_PEER_IDENTITY"] = "OS_PEER_IDENTITY"
    reviewed_at: UTCTimestamp
    review_status: Literal["RECORDED"] = "RECORDED"
    feedback_digest: Hash

    @model_validator(mode="after")
    def integrity(self) -> Self:
        if (
            self.request.finding_id != self.experience.finding_id
            or self.request.expected_experience_id != self.experience.experience_id
        ):
            raise ValueError("FEEDBACK_EXPERIENCE_BINDING_REJECTED")
        if self.feedback_digest != content_digest_payload(
            self.model_dump(mode="json", exclude={"feedback_digest"})
        ):
            raise ValueError("FEEDBACK_DIGEST_REJECTED")
        return self


def authenticated_uid(peer_socket) -> int:
    _, uid, _ = struct.unpack(
        "3i", peer_socket.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
    )
    if uid != os.geteuid():
        raise ValueError("FEEDBACK_REVIEWER_DENIED")
    return uid


class RuntimeFeedbackLoop:
    def __init__(self, monitor):
        self.monitor = monitor
        self.store = monitor.store

    def _events(self, c, kind):
        return [
            json.loads(row[0])
            for row in c.execute("SELECT payload FROM monitor_audit ORDER BY sequence")
            if json.loads(row[0])["kind"] == kind
        ]

    def records(self) -> tuple[RuntimeFeedback, ...]:
        self.store.verify_audit()
        with self.store.database.transaction(write=False) as c:
            values = tuple(
                RuntimeFeedback.model_validate(e["details"]["record"])
                for e in self._events(c, "DIAGNOSTIC_FEEDBACK")
            )
        ids = set()
        latest = {}
        for value in values:
            if value.request.feedback_id in ids:
                raise ValueError("DUPLICATE_STORED_FEEDBACK_REJECTED")
            ids.add(value.request.feedback_id)
            old = latest.get((value.experience.finding_id, value.reviewer_uid))
            if value.request.supersedes != (old.request.feedback_id if old else None):
                raise ValueError("FEEDBACK_CORRECTION_HISTORY_REJECTED")
            latest[value.experience.finding_id, value.reviewer_uid] = value
        return values

    def submit(self, request: RuntimeFeedbackRequest, peer_socket) -> RuntimeFeedback:
        uid = authenticated_uid(peer_socket)
        from soc_agent.linux_runtime.failure_feedback import FailureFeedbackLoop

        if any(
            v.request.feedback_id == request.feedback_id
            for v in FailureFeedbackLoop(self.monitor).records()
        ):
            raise ValueError("CROSS_FAMILY_FEEDBACK_ID_CONFLICT")
        request = RuntimeFeedbackRequest.model_validate(request.model_dump())
        experience = capture_runtime_experience(self.monitor, request.finding_id)
        if experience.experience_id != request.expected_experience_id:
            raise ValueError("FEEDBACK_STALE_SOURCE_REJECTED")
        values = self.records()
        for value in values:
            if value.request.feedback_id == request.feedback_id:
                if (
                    value.request != request
                    or value.reviewer_uid != uid
                    or value.experience != experience
                ):
                    raise ValueError("CONFLICTING_FEEDBACK_RETRY_REJECTED")
                return value
        previous = next(
            (
                v
                for v in reversed(values)
                if v.experience.finding_id == request.finding_id and v.reviewer_uid == uid
            ),
            None,
        )
        if request.supersedes != (previous.request.feedback_id if previous else None):
            raise ValueError("EXPLICIT_FEEDBACK_CORRECTION_REQUIRED")
        body = {
            "contract_version": "soc-monitor-human-feedback:v1",
            "request": request.model_dump(mode="json"),
            "experience": experience.model_dump(mode="json"),
            "reviewer_uid": uid,
            "reviewer_assurance": "OS_PEER_IDENTITY",
            "reviewed_at": utc_now().isoformat().replace("+00:00", "Z"),
            "review_status": "RECORDED",
        }
        value = RuntimeFeedback.model_validate_json(
            json.dumps(body | {"feedback_digest": content_digest_payload(body)})
        )
        with self.store.database.transaction() as c:
            # One writer; experience snapshot, opinion and audit are one append transaction.
            self.store._audit(c, "DIAGNOSTIC_FEEDBACK", {"record": value.model_dump(mode="json")})
        return value

    def active_records(self):
        latest = {}
        for value in self.records():
            latest[value.experience.finding_id, value.reviewer_uid] = value
        values = tuple(sorted(latest.values(), key=lambda v: str(v.request.feedback_id)))
        for value in values:
            if (
                capture_runtime_experience(self.monitor, value.request.finding_id)
                != value.experience
            ):
                raise ValueError("FEEDBACK_SOURCE_CHANGED")
        return values

    def _pattern(self):
        # Same source observations in two rule Findings are one support unit, not two.
        selected, seen = [], set()
        for value in self.active_records():
            if value.request.label != "FALSE_POSITIVE":
                continue
            evidence = {
                (value.experience.incident_id, r) for r in value.experience.evidence_references
            }
            if evidence & seen:
                continue
            seen |= evidence
            selected.append(value)
        if len(selected) < 2:
            return None
        origins = {v.experience.source_origin for v in selected}
        if len(origins) != 1:
            raise ValueError("MIXED_ORIGIN_CANDIDATE_REJECTED")
        digest = content_digest_payload(
            {
                "contract_version": "soc-monitor-feedback-dataset:v1",
                "feedback": [v.feedback_digest for v in selected],
            }
        )
        content = RuntimePatternContent(
            dataset=DatasetBinding(
                dataset_id=digest, dataset_version=digest, manifest_digest=digest
            ),
            supporting_sample_refs=tuple(
                sorted(
                    (
                        ArtifactReference(
                            identity=v.experience.experience_id, digest=content_digest(v.experience)
                        )
                        for v in selected
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
                        for v in selected
                    ),
                    key=lambda r: r.identity,
                )
            ),
            occurrence_count=len(selected),
        )
        return RuntimeFailurePattern(pattern_id=content_digest(content), content=content)

    def candidates(self):
        pattern = self._pattern()
        return () if pattern is None else generate(pattern)

    def prepare_candidates(self):
        candidates = self.candidates()
        persisted = []
        with self.store.database.transaction() as c:
            events = self._events(c, "RUNTIME_IMPROVEMENT_CANDIDATE")
            existing = {e["details"]["candidate"]["candidate_id"]: e["details"] for e in events}
            pattern = self._pattern()
            for candidate in candidates:
                body = {
                    "candidate": candidate.model_dump(mode="json"),
                    "pattern": pattern.model_dump(mode="json"),
                    "review_status": "PENDING_REVIEW",
                    "risk": "OFFLINE_TRIAL_ONLY_NO_AUTHORITY",
                }
                if candidate.candidate_id in existing:
                    old = existing[candidate.candidate_id]
                    previous = ImprovementCandidate.model_validate(old["candidate"])
                    if previous.content != candidate.content or old["pattern"] != body["pattern"]:
                        raise ValueError("CANDIDATE_CONTENT_CONFLICT")
                    persisted.append(previous)
                else:
                    self.store._audit(c, "RUNTIME_IMPROVEMENT_CANDIDATE", body)
                    persisted.append(candidate)
        return tuple(persisted)

    def candidate(self, identity: str) -> ImprovementCandidate:
        self.store.verify_audit()
        with self.store.database.transaction(write=False) as c:
            rows = [
                e["details"]
                for e in self._events(c, "RUNTIME_IMPROVEMENT_CANDIDATE")
                if e["details"]["candidate"]["candidate_id"] == identity
            ]
        if not rows:
            from soc_agent.linux_runtime.failure_feedback import FailureFeedbackLoop

            return FailureFeedbackLoop(self.monitor).candidate(identity)
        if len(rows) != 1:
            raise ValueError("CANDIDATE_MISSING_OR_DUPLICATE")
        candidate = ImprovementCandidate.model_validate(rows[0]["candidate"])
        pattern = RuntimeFailurePattern.model_validate(rows[0]["pattern"])
        if not any(v.content == candidate.content for v in generate(pattern)) or not any(
            v.content == candidate.content for v in self.candidates()
        ):
            raise ValueError("CANDIDATE_SOURCE_CHANGED")
        return candidate

    def review_records(self):
        self.store.verify_audit()
        with self.store.database.transaction(write=False) as c:
            return [e["details"] for e in self._events(c, "RUNTIME_CANDIDATE_REVIEW")]

    def evaluate(self, identity: str, *, repeated_failures: int, multiple_accounts: int):
        candidate = self.candidate(identity)
        if candidate.content.schema_version == "improvement-candidate:v4":
            from soc_agent.linux_runtime.failure_feedback import FailureFeedbackLoop

            return FailureFeedbackLoop(self.monitor).evaluate(identity)
        if (
            type(repeated_failures) is not int
            or not 2 <= repeated_failures <= 10000
            or type(multiple_accounts) is not int
            or not 2 <= multiple_accounts <= 10000
        ):
            raise ValueError("OFFLINE_THRESHOLD_TRIAL_REJECTED")
        # Independent pre-authored Fixture GT. Human feedback is never supplied to evaluate().
        dataset = fixture_dataset()
        baseline = evaluate(
            dataset,
            repeated_failures=self.monitor.config.repeated_failures,
            multiple_accounts=self.monitor.config.multiple_accounts,
        )
        trial = evaluate(
            dataset, repeated_failures=repeated_failures, multiple_accounts=multiple_accounts
        )
        # Wall-clock timings are observations, not content identity or efficacy evidence.
        timings = {
            "baseline": baseline.pop("measured_replay_seconds"),
            "trial": trial.pop("measured_replay_seconds"),
        }
        if baseline["ground_truth_digest"] != trial["ground_truth_digest"]:
            raise ValueError("OFFLINE_DATASET_MISMATCH")
        self.candidate(identity)  # Revalidate the source after non-atomic offline work.
        regression = any(
            trial["confusion_matrix"][k] > baseline["confusion_matrix"][k] for k in ("FP", "FN")
        )
        body = {
            "contract_version": "soc-monitor-offline-trial:v1",
            "candidate_reference": candidate.candidate_id,
            "candidate_digest": content_digest(candidate),
            "adapter_sha256": {
                str(path.relative_to(Path(__file__).parents[1])): sha256(
                    path.read_bytes()
                ).hexdigest()
                for path in (
                    Path(__file__),
                    Path(__file__).parents[1] / "experience/runtime.py",
                    Path(__file__).parents[1] / "improvement_candidates/generation.py",
                    Path(__file__).parents[1] / "improvement_candidates/models.py",
                    Path(__file__).parents[1] / "improvement_candidates/runtime_models.py",
                )
            },
            "ground_truth_digest": dataset.ground_truth_digest,
            "ground_truth_assurance": "INDEPENDENT_PREAUTHORED_FIXTURE_NOT_HUMAN_FEEDBACK",
            "feedback_is_ground_truth": False,
            "baseline": baseline,
            "trial": trial,
            "regression_result": "REGRESSED" if regression else "NO_FP_FN_COUNT_REGRESSION",
            "verdict": "INCONCLUSIVE",
            "promotion": "BLOCKED",
            "automatic_application": "DISABLED",
            "limitations": [
                "Fixed fixture replay is not operating accuracy "
                "or an independent held-out experiment.",
                "No causal improvement inferred; no runtime configuration is modified.",
            ],
        }
        body["evaluation_id"] = content_digest_payload(body)
        with self.store.database.transaction() as c:
            events = self._events(c, "RUNTIME_OFFLINE_EVALUATION")
            if not any(e["details"]["evaluation_id"] == body["evaluation_id"] for e in events):
                self.store._audit(c, "RUNTIME_OFFLINE_EVALUATION", body)
                self.store._audit(
                    c,
                    "RUNTIME_OFFLINE_TIMINGS",
                    {"evaluation_id": body["evaluation_id"], "measured_replay_seconds": timings},
                )
        return body

    def review(
        self, identity: str, decision: ReviewDecision, expected_evaluation: Hash, peer_socket
    ):
        uid = authenticated_uid(peer_socket)
        self.candidate(identity)
        with self.store.database.transaction() as c:
            evaluations = [
                e["details"]
                for e in self._events(c, "RUNTIME_OFFLINE_EVALUATION")
                if e["details"]["candidate_reference"] == identity
            ]
            if not evaluations or evaluations[-1]["evaluation_id"] != expected_evaluation:
                raise ValueError("REVIEW_EVALUATION_BINDING_REJECTED")
            # Existing ReviewDecision vocabulary; never feed review into activation services.
            if decision == ReviewDecision.APPROVE:
                raise ValueError("INCONCLUSIVE_TRIAL_APPROVAL_BLOCKED")
            prior = [
                e["details"]
                for e in self._events(c, "RUNTIME_CANDIDATE_REVIEW")
                if e["details"]["candidate_id"] == identity
            ]
            body = {
                "candidate_id": identity,
                "evaluation_id": expected_evaluation,
                "reviewer_uid": uid,
                "reviewer_assurance": "OS_PEER_IDENTITY",
                "status": "REJECTED" if decision == ReviewDecision.REJECT else "INCONCLUSIVE",
                "promotion": "BLOCKED",
            }
            if prior:
                if prior[-1] != body:
                    raise ValueError("CANDIDATE_REVIEW_ALREADY_DECIDED")
                return body
            self.store._audit(c, "RUNTIME_CANDIDATE_REVIEW", body)
        return body
