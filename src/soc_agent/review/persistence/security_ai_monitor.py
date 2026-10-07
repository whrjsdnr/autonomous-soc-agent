"""Bounded retained-context read; deliberately no checkpoint authority/Fusion rebuild."""

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from uuid import UUID

from pydantic import ValidationError

from soc_agent._json import canonical_json_object
from soc_agent.assessment import AssessmentResult
from soc_agent.review.identity import state_fingerprint
from soc_agent.review.models import StateAnchor
from soc_agent.review.persistence import SQLiteGovernanceStore
from soc_agent.review.persistence.models import StoredDataError
from soc_agent.review.persistence.session import GovernanceSession
from soc_agent.security_ai.fusion.models import FusionResult
from soc_agent.security_ai.network.classifier import ClassificationPrediction


@dataclass(frozen=True)
class RetainedSignalSource:
    incident_id: UUID
    run_id: UUID
    checkpoint_revision: int
    snapshot_revision: int
    assessment_id: UUID
    fusion: FusionResult


def read_security_ai_snapshot(
    store: SQLiteGovernanceStore, visible: Callable[[UUID], bool]
) -> tuple[RetainedSignalSource, ...]:
    """Validate stored content/local links, NOT inference or analytical correctness.

    Full WorkflowCheckpoint decode triggers FusionAssessmentResult's aggregation
    revalidation. A monitoring read instead parses just the retained analytical
    structures after canonical row digest and source snapshot verification.
    """
    with store.database.transaction(write=False) as connection:
        connection.execute("PRAGMA query_only=ON")
        session = GovernanceSession(connection, store.store_id)
        result = []
        for row in connection.execute("SELECT * FROM workflow_checkpoints ORDER BY incident_id"):
            identity = UUID(row["incident_id"])
            if not visible(identity):
                continue
            try:
                raw = json.loads(row["payload"])
                canonical = canonical_json_object(raw)
                if (
                    canonical != row["payload"]
                    or hashlib.sha256(canonical.encode()).hexdigest() != row["digest"]
                    or raw["incident_id"] != str(identity)
                    or raw["run_id"] != row["run_id"]
                    or type(raw["revision"]) is not int
                    or raw["revision"] != row["revision"]
                ):
                    raise StoredDataError("Monitoring checkpoint content binding mismatch")
                anchor = StateAnchor.model_validate(raw["artifacts"]["snapshot"])
                current = session.load(identity)
                if (
                    anchor.repository_id != store.store_id
                    or anchor.incident_id != identity
                    or anchor.revision > current.anchor.revision
                ):
                    raise StoredDataError("Monitoring snapshot binding mismatch")
                retained = session.snapshot(anchor)
                assessment = raw["artifacts"]["assessment"]
                if not assessment or "model_derived_context" not in assessment:
                    continue
                base = AssessmentResult.model_validate(
                    {k: assessment[k] for k in ("incident_state", "threat_assessment")}
                )
                fusion = FusionResult.model_validate(assessment["model_derived_context"])
                refs = {r["kind"]: r["identity"] for r in raw["result"]["references"]}
                if (
                    len(refs) != len(raw["result"]["references"])
                    or len(fusion.signals) > 128
                    or len(fusion.contributions) > 128
                    or len(fusion.model_references) > 16
                    or fusion.incident_id != identity
                    or base.incident_state.incident_id != identity
                    or state_fingerprint(base.incident_state) != anchor.fingerprint
                    or base.incident_state != retained.state
                    or raw["result"]["incident_id"] != str(identity)
                    or refs.get("assessment") != str(base.threat_assessment.assessment_id)
                    or refs.get("fusion") != fusion.fusion_id
                ):
                    raise StoredDataError("Monitoring assessment/Fusion binding mismatch")
                signal_ids = {s.signal_id for s in fusion.signals}
                bindings = {b.manifest_digest: b for b in fusion.model_references}
                if len(signal_ids) != len(fusion.signals) or len(bindings) != len(
                    fusion.model_references
                ):
                    raise StoredDataError("Monitoring duplicate source identity")
                evidence = {e.evidence_id for e in retained.state.evidence}
                for binding in bindings.values():
                    metadata = {"value": binding.manifest.model_dump(mode="json")}
                    if hashlib.sha256(canonical_json_object(metadata).encode()).hexdigest() != (
                        binding.manifest_digest
                    ):
                        raise StoredDataError("Monitoring manifest digest mismatch")
                for signal in fusion.signals:
                    if (
                        signal.incident_id != identity
                        or not set(signal.source_evidence_ids) <= evidence
                    ):
                        raise StoredDataError("Monitoring signal source binding mismatch")
                for contribution in fusion.contributions:
                    binding = bindings.get(contribution.model_reference)
                    if (
                        binding is None
                        or binding.manifest.model_kind != contribution.model_kind
                        or not contribution.signal_ids
                        or not set(contribution.signal_ids) <= signal_ids
                        or contribution.provenance.incident_id not in (None, identity)
                        or not set(contribution.provenance.source_evidence_ids) <= evidence
                        or (contribution.model_kind == "network_classifier")
                        != isinstance(contribution.scores, ClassificationPrediction)
                        or (contribution.model_kind == "network_classifier")
                        != (contribution.operating_point == "argmax")
                        or contribution.score_semantics
                        != (
                            "class probabilities"
                            if contribution.model_kind == "network_classifier"
                            else "empirical anomaly rank; raw=-score_samples"
                        )
                    ):
                        raise StoredDataError("Monitoring contribution source binding mismatch")
                    for signal in fusion.signals:
                        if signal.signal_id in contribution.signal_ids and (
                            signal.model_name != binding.manifest.model_id
                            or signal.model_version != binding.manifest.model_version
                        ):
                            raise StoredDataError("Monitoring model identity mismatch")
                result.append(
                    RetainedSignalSource(
                        identity,
                        UUID(raw["run_id"]),
                        raw["revision"],
                        anchor.revision,
                        base.threat_assessment.assessment_id,
                        fusion,
                    )
                )
            except (ValueError, TypeError, KeyError, ValidationError) as error:
                raise StoredDataError("Invalid retained monitoring snapshot") from error
        return tuple(result)
