"""Explicit stopped-runtime paired replay; one-use holdout, no operating promotion."""

from soc_agent.evaluation.authentication import evaluate
from soc_agent.linux_runtime.feedback_loop import RuntimeFeedbackLoop
from soc_agent.offline_evaluation.holdout import HoldoutContract
from soc_agent.review.persistence.models import StorageError
from soc_agent.security_ai.external.models import content_digest_payload


class HoldoutEvaluation:
    def __init__(self, monitor):
        self.monitor, self.store = monitor, monitor.store

    def run(
        self,
        candidate_id,
        contract: HoldoutContract,
        dataset,
        *,
        repeated_failures,
        multiple_accounts,
    ):
        candidate = RuntimeFeedbackLoop(self.monitor).candidate(candidate_id)
        contract = HoldoutContract.model_validate_json(contract.model_dump_json())
        held = contract.validate_dataset(dataset)
        # Do not trust matching digests as independent operating label attestation.
        if contract.source_assurance != "PREAUTHORED_FIXTURE":
            return self._blocked(
                candidate_id, contract, "OPERATING_SOURCE_AND_LABEL_ATTESTATION_UNAVAILABLE"
            )
        if (
            candidate.content.schema_version == "improvement-candidate:v4"
            and candidate.content.proposal.candidate_type.value != "detection_rule_review"
        ):
            return self._blocked(
                candidate_id, contract, "RELIABILITY_REQUIRES_MATCHED_REPLAY_NOT_DETECTION_LABELS"
            )
        if any(
            type(v) is not int or not 2 <= v <= 10000
            for v in (repeated_failures, multiple_accounts)
        ):
            raise ValueError("HOLDOUT_TRIAL_CONFIG_REJECTED")
        # Independent holdout must exclude the source observations that selected this candidate.
        candidate_refs = set()
        candidate_events = set()
        from soc_agent.linux_runtime.failure_feedback import FailureFeedbackLoop

        for value in RuntimeFeedbackLoop(self.monitor).active_records():
            if any(
                r.identity == value.experience.experience_id
                for r in candidate.content.supporting_sample_refs
            ):
                candidate_refs.update(value.experience.evidence_references)
        for value in FailureFeedbackLoop(self.monitor).active():
            if any(
                r.identity == value.experience["experience_id"]
                for r in candidate.content.supporting_sample_refs
            ):
                candidate_refs.update(value.experience["source_references"])
                candidate_events.update(value.experience["event_references"])
        for member in contract.members:
            if member.split == "HOLDOUT" and (
                member.incident_id == self.monitor.config.incident_id
                or candidate_refs & set(member.content_digests)
                or candidate_events & {str(r) for r in member.event_references}
            ):
                raise ValueError("CANDIDATE_HOLDOUT_SELECTION_LEAKAGE")
        # Claim before either run; interrupted/failed evaluations consume the holdout too.
        self.store.verify_audit()
        held_sources = sorted({m.source_identity for m in contract.members if m.split == "HOLDOUT"})
        held_events = sorted(
            {
                str(ref)
                for m in contract.members
                if m.split == "HOLDOUT"
                for ref in m.event_references
            }
        )
        held_digests = sorted(
            {ref for m in contract.members if m.split == "HOLDOUT" for ref in m.content_digests}
        )
        with self.store.database.transaction() as c:
            events = self.monitor.simulation._events(c)
            if any(
                e["kind"] == "HOLDOUT_CLAIM"
                and (
                    e["details"]["source_digest"] == contract.source_digest
                    or set(e["details"].get("held_sources", ())) & set(held_sources)
                    or set(e["details"].get("held_events", ())) & set(held_events)
                    or set(e["details"].get("held_digests", ())) & set(held_digests)
                )
                for e in events
            ):
                raise ValueError("HOLDOUT_REUSE_REJECTED")
            self.store._audit(
                c,
                "HOLDOUT_CLAIM",
                {
                    "source_digest": contract.source_digest,
                    "held_sources": held_sources,
                    "held_events": held_events,
                    "held_digests": held_digests,
                    "contract_digest": contract.contract_digest,
                    "candidate": candidate_id,
                    "trial_config": {
                        "repeated_failures": repeated_failures,
                        "multiple_accounts": multiple_accounts,
                    },
                },
            )
        try:
            baseline = evaluate(
                held,
                repeated_failures=self.monitor.config.repeated_failures,
                multiple_accounts=self.monitor.config.multiple_accounts,
            )
            trial = evaluate(
                held, repeated_failures=repeated_failures, multiple_accounts=multiple_accounts
            )
            for result in (baseline, trial):
                result.pop("measured_replay_seconds", None)
            self._candidate_current(candidate_id, candidate)
        except (ValueError, OSError, RuntimeError, StorageError) as error:
            self.store.event(
                "HOLDOUT_EVALUATION_FAILED",
                {
                    "contract_digest": contract.contract_digest,
                    "category": type(error).__name__,
                    "holdout_consumed": True,
                },
            )
            raise
        regressed = any(
            trial["confusion_matrix"][m] > baseline["confusion_matrix"][m] for m in ("FP", "FN")
        )
        # No candidate-specific security/crash replay here. Shared regression is separate evidence.
        body = {
            "contract_version": "soc-holdout-comparison:v1",
            "candidate_reference": candidate_id,
            "holdout_contract_digest": contract.contract_digest,
            "source_digest": contract.source_digest,
            "ground_truth_digest": held.ground_truth_digest,
            "scope": "DECLARED_DISJOINT_FIXTURE_ONLY_NOT_OPERATING_HOLDOUT",
            "baseline": baseline,
            "trial": trial,
            "regression_gate": "REGRESSED"
            if regressed
            else "INCONCLUSIVE_SECURITY_AND_PROSPECTIVE_VALIDATION_REQUIRED",
            "verdict": "INCONCLUSIVE",
            "promotion": "BLOCKED",
            "automatic_application": "DISABLED",
        }
        return self._persist(body)

    def _candidate_current(self, identity, expected):
        if RuntimeFeedbackLoop(self.monitor).candidate(identity) != expected:
            raise ValueError("HOLDOUT_CANDIDATE_CHANGED")

    def _blocked(self, identity, contract, reason):
        return self._persist(
            {
                "contract_version": "soc-holdout-comparison:v1",
                "candidate_reference": identity,
                "holdout_contract_digest": contract.contract_digest,
                "reason": reason,
                "metrics": None,
                "verdict": "BLOCKED",
                "promotion": "BLOCKED",
                "automatic_application": "DISABLED",
            }
        )

    def _persist(self, body):
        body = body | {"evaluation_id": content_digest_payload(body)}
        with self.store.database.transaction() as c:
            events = self.monitor.simulation._events(c)
            if not any(
                e["kind"] == "RUNTIME_OFFLINE_EVALUATION"
                and e["details"].get("evaluation_id") == body["evaluation_id"]
                for e in events
            ):
                self.store._audit(c, "RUNTIME_OFFLINE_EVALUATION", body)
        return body
