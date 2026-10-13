"""Offline decision equivalence: original domain artifacts validate before projection."""

import json
from typing import Literal

from pydantic import JsonValue

from soc_agent.api.models import WorkflowView
from soc_agent.assessment.fusion import FusionAssessmentResult
from soc_agent.decision import IncidentDecisionEngine
from soc_agent.ingestion.models import IngestionReceipt
from soc_agent.investigation.runtime.models import WorkflowFailure, WorkflowResult
from soc_agent.investigation.runtime.persistence.models import WorkflowCheckpoint
from soc_agent.investigation.runtime.trace import OrchestrationTrace
from soc_agent.policy.models import PolicyResult
from soc_agent.review.identity import state_fingerprint
from soc_agent.review.persistence.models import GovernanceEvent
from soc_agent.review.validation import validate_decision
from soc_agent.state import IncidentState
from soc_agent.tools.models import ToolMetadata
from tests.diagnose_native_inference import Record, encoded, sha

CONTRACT = "soc-decision-trace:v1"
FIXTURE_PIN = "f7a7fd1f57cd11589d8df37a722641887aaa9a7427b18ff15262d9d0c72527a2"


class PolicyCall(Record):
    metadata: ToolMetadata
    result: PolicyResult


class RuntimeEvent(Record):
    receipt: IngestionReceipt
    duplicate: bool
    initial_state: IncidentState
    state: IncidentState
    checkpoint: WorkflowCheckpoint
    trace: OrchestrationTrace
    progress: list[WorkflowView]
    policy_calls: list[PolicyCall]

    def verify(self):
        cp = self.checkpoint
        if (
            cp.incident_id != self.state.incident_id
            or state_fingerprint(self.state) != cp.artifacts.snapshot.fingerprint
            or self.receipt.incident_id != self.state.incident_id
        ):
            raise ValueError("State/checkpoint/event binding mismatch")
        assessment = cp.artifacts.assessment
        decision = cp.artifacts.decision
        if assessment is None or decision is None or not self.trace.entries or not self.progress:
            raise ValueError("Required decision pipeline stages missing")
        if (
            self.trace.entries[-1].content.result != cp.result
            or self.trace.entries[-1].content.snapshot != cp.artifacts.snapshot
        ):
            raise ValueError("Final trace/checkpoint differs")
        if not self.duplicate and self.trace.entries[
            0
        ].content.snapshot.fingerprint != state_fingerprint(self.initial_state):
            raise ValueError("Initial state/trace binding differs")
        if assessment.incident_state != self.state:
            raise ValueError("Assessment state differs")
        expected_entries = self.trace.entries[-1:] if self.duplicate else self.trace.entries
        if len(self.progress) != len(expected_entries):
            raise ValueError("Persisted workflow read surface missing")
        for progress, entry in zip(self.progress, expected_entries, strict=True):
            result = WorkflowResult.model_validate(
                progress.model_dump(exclude={"workflow_id", "checkpoint_revision"})
            )
            if (
                progress.workflow_id != cp.run_id
                or progress.checkpoint_revision != entry.content.sequence - 1
                or result != entry.content.result
            ):
                raise ValueError("Workflow read surface differs from durable trace")
        validate_decision(self.state, decision)
        recomputed = IncidentDecisionEngine().decide(
            self.state,
            assessment.threat_assessment,
            fusion_assessment=assessment
            if isinstance(assessment, FusionAssessmentResult)
            else None,
        )
        if recomputed != decision:
            raise ValueError("Decision differs from actual decision rules")


class SequenceTrace(Record):
    case_id: str
    events: list[RuntimeEvent]
    audit: list[GovernanceEvent]
    write_calls: int
    approval_rows: int
    execution_rows: int


class DecisionExport(Record):
    contract: Literal["soc-decision-trace:v1"]
    fixture_sha256: str
    fixture: dict[str, JsonValue]
    policy_sha256: str
    policy_configuration: dict[str, JsonValue]
    model_files: dict[str, dict[str, str]]
    environment: dict[str, str]
    adapter: Literal["existing DemoLLM; source-scripted offline response; real domain validation"]
    sequences: list[SequenceTrace]
    guards: list[dict[str, JsonValue]]
    metadata: dict[str, JsonValue]


def _sources(provenance: dict) -> dict:
    # Ingestion uses stable uuid5 record IDs: preserve them and all source times.
    return provenance


def model_projection(result) -> dict:
    data = result.model_dump(mode="json")
    contributions = sorted(
        result.contributions, key=lambda c: (c.model_kind, c.feature_fingerprint)
    )
    mapping = {c.contribution_id: f"contribution:{i}" for i, c in enumerate(contributions)}
    signal_mapping = {
        str(sid): f"signal:{i}:{j}"
        for i, c in enumerate(contributions)
        for j, sid in enumerate(c.signal_ids)
    }
    signals = []
    for signal in result.signals:
        value = signal.model_dump(mode="json")
        explanation = (
            json.loads(value["explanation"])
            if isinstance(value["explanation"], str)
            else value["explanation"].copy()
        )
        if isinstance(value["scores"], str):
            value["scores"] = json.loads(value["scores"])
        if "feature_provenance" in explanation:
            explanation["feature_provenance"] = _sources(explanation["feature_provenance"])
        value.update(
            signal_id=signal_mapping[value["signal_id"]],
            source_result_id=signal_mapping[value["signal_id"]] + ":result",
            explanation=explanation,
        )
        value.pop("created_at")
        value.pop("source_created_at")  # inference receipt time; source observed_at is retained
        signals.append(value)
    data["signals"] = sorted(signals, key=lambda s: s["signal_id"])
    data["contributions"] = [
        c.model_dump(mode="json")
        | {
            "contribution_id": mapping[c.contribution_id],
            "signal_ids": [signal_mapping[str(i)] for i in c.signal_ids],
            "provenance": _sources(c.provenance.model_dump(mode="json")),
        }
        for c in contributions
    ]
    data["correlation_groups"] = sorted(
        [
            g.model_dump(mode="json")
            | {
                "group_id": f"group:{i}",
                "contribution_ids": sorted(mapping[c] for c in g.contribution_ids),
            }
            for i, g in enumerate(result.correlation_groups)
        ],
        key=lambda g: g["contribution_ids"],
    )
    data["fusion_id"] = "validated-derived-fusion-identity"
    # Fusion created_at is the source watermark: deliberately retained.
    return data


def event_projection(event: RuntimeEvent) -> dict:
    event.verify()
    state, cp = event.state, event.checkpoint
    ids = {str(e.evidence_id): f"evidence:{i}" for i, e in enumerate(state.evidence)}
    for entry in event.trace.entries:
        for ref in entry.content.result.references:
            if ref.identity not in ids:
                ids[ref.identity] = (
                    f"{ref.kind}:{sum(v.startswith(ref.kind + ':') for v in ids.values())}"
                )

    def references(value):
        if isinstance(value, dict):
            return {k: references(v) for k, v in value.items()}
        if isinstance(value, list):
            return [references(v) for v in value]
        return ids.get(value, value) if isinstance(value, str) else value

    evidence = []
    for e in state.evidence:
        value = e.model_dump(mode="json")
        value.pop("observed_at")  # investigation/evidence.py defines this as receipt time
        value.pop("collected_at")
        value["raw_data"] = json.loads(value["raw_data"])
        evidence.append(references(value))
    assessment = cp.artifacts.assessment.threat_assessment.model_dump(mode="json")
    assessment.pop("created_at")
    decision = cp.artifacts.decision.model_dump(mode="json")
    decision["assessment"] = assessment
    fusion = cp.artifacts.assessment.model_derived_context
    decision["model_derived_context"] = model_projection(fusion)
    plan = cp.artifacts.investigation.model_dump(mode="json")
    plan.pop("created_at")
    plan["steps"] = [
        s | {"step_id": f"step:{i}", "action_id": f"investigation-action:{i}"}
        for i, s in enumerate(plan["steps"])
    ]
    return {
        "event": event.receipt.event.model_dump(mode="json"),
        "event_digest": event.receipt.canonical_digest,
        "duplicate": event.duplicate,
        "incident_id": str(state.incident_id),
        "incident_status": state.status.value,
        "incident_severity": state.severity.value,
        "incident_confidence": state.confidence,
        "evidence": evidence,
        "observations": [o.model_dump(mode="json") for o in state.observations],
        "hypotheses": [h.model_dump(mode="json") for h in state.hypotheses],
        "investigation": references(plan),
        "assessment": references(assessment),
        "decision": references(decision),
        "workflow": [
            references(e.content.result.model_dump(mode="json")) for e in event.trace.entries
        ],
        "read_surface": [
            references(p.model_dump(mode="json", exclude={"workflow_id"})) for p in event.progress
        ],
        "policy_calls": [p.model_dump(mode="json") for p in event.policy_calls],
        "approval_id": cp.approval_id,
        "review_id": cp.review_id,
        "promoted_id": cp.promoted_id,
        "execution_intent_id": cp.artifacts.execution_intent_id,
        "rounds": cp.rounds,
        "round_limit": cp.round_limit,
        "attempted": cp.attempted,
    }


def correctness(value: DecisionExport) -> list[str]:
    errors = []
    if value.fixture_sha256 != FIXTURE_PIN or sha(encoded(value.fixture)) != FIXTURE_PIN:
        errors.append("Fixture pin differs")
    if value.policy_sha256 != sha(encoded(value.policy_configuration)):
        errors.append("Policy configuration digest differs")
    from tests.diagnose_decision_pipeline import policy_configuration

    if value.policy_configuration != policy_configuration():
        errors.append("Policy differs from current trusted diagnostic composition")
    from soc_agent.security_ai.packaging.files import read_package, strict_json
    from tests.diagnose_native_inference import ROOT
    from tests.scenarios.test_security_ai_fusion import PINS

    trusted_files = {}
    for kind, pin, _ in PINS:
        files = read_package(ROOT / "tests/fixtures/security_ai_packages" / kind)
        manifest = strict_json(files["manifest.json"])
        expected = {"manifest.json": pin} | {
            f["path"]: f["sha256"] for f in manifest["file_hashes"]
        }
        if {k: sha(v) for k, v in files.items()} != expected:
            raise ValueError("Trusted model files changed")
        trusted_files[kind] = expected
    if value.model_files != trusted_files:
        errors.append("Model artifact inventory differs")
    expected_sequences = value.fixture["sequences"]
    if [s.case_id for s in value.sequences] != [s["id"] for s in expected_sequences]:
        errors.append("Sequence scope missing or reordered")
    for sequence, expected in zip(value.sequences, expected_sequences, strict=False):
        if len(sequence.events) != len(expected["events"]):
            errors.append("Sequence event missing")
            continue
        if sequence.write_calls or sequence.approval_rows or sequence.execution_rows:
            errors.append("Unexpected authority or WRITE")
        expected_audit = [
            (kind, item.state.incident_id)
            for item in sequence.events
            if not item.duplicate
            for kind in ("incident_registered", "evidence_appended")
        ]
        if [(a.event_type, a.incident_id) for a in sequence.audit] != expected_audit:
            errors.append("Required durable audit missing or differs")
        audit_projection(sequence)
        for item, key in zip(sequence.events, expected["events"], strict=True):
            if item.receipt.event.model_dump(mode="json") != value.fixture["events"][key]:
                errors.append("Event fixture differs")
            item.verify()
            cp = item.checkpoint
            if (
                not cp.result.waiting_for_human
                or cp.artifacts.execution_intent_id is not None
                or cp.approval_id is not None
                or cp.review_id is not None
                or cp.promoted_id is not None
                or cp.result.failure != WorkflowFailure.LOOP_GUARD
                or cp.result.reason != "Repeated investigation intent; human review required"
                or cp.artifacts.response_plan is not None
            ):
                errors.append("Human boundary bypassed")
            if (
                item.state.severity != item.initial_state.severity
                or item.state.status != item.initial_state.status
            ):
                errors.append("Unauthorized incident mutation")
            if len(item.state.evidence) != 1 or item.state.observations or item.state.hypotheses:
                errors.append("Unexpected evidence/interpretation promotion")
            fusion = cp.artifacts.assessment.model_derived_context
            applicable = (
                {"network_classifier", "network_anomaly"}
                if item.receipt.event.event_type == "network"
                else {"authentication_anomaly"}
            )
            if (
                len(fusion.signals) != len(applicable)
                or {c.model_kind for c in fusion.contributions} != applicable
                or {c.model_kind for c in fusion.coverage if c.status == "observed"} != applicable
            ):
                errors.append("Applicable real model signal missing or wrong domain")
            from soc_agent.policy import PolicyDecision, PolicyEngine

            if any(p.result.decision != PolicyDecision.ALLOW for p in item.policy_calls):
                errors.append("Unexpected investigation policy")
            if any(
                not p.metadata.is_read_only_capability
                or PolicyEngine().evaluate(p.metadata) != p.result
                for p in item.policy_calls
            ):
                errors.append("Policy result violates trusted declarations")
            if not item.duplicate and not item.policy_calls:
                errors.append("Runtime policy stage missing")
            failures = (
                sum(
                    a.authentication_result == "failure"
                    for a in item.receipt.event.attributes.attempts
                )
                if item.receipt.event.event_type == "authentication"
                else 0
            )
            if cp.artifacts.assessment.threat_assessment.severity.value != (
                "high" if failures > 1 else "info"
            ):
                errors.append("Scripted assessment contract differs")
    if [g["case_id"] for g in value.guards] != value.fixture["guard_cases"]:
        errors.append("Guard scope missing")
    for guard in value.guards:
        if guard["case_id"] == "read_allowed":
            if guard.get("permitted") is not True:
                errors.append("Read-only unexpectedly blocked")
        elif guard["case_id"] == "invalid_policy_metadata":
            if (
                guard.get("policy", {}).get("decision") != "deny"
                or guard.get("blocked") is not True
            ):
                errors.append("Invalid metadata not denied")
        elif guard["case_id"] in ("advisory_info", "advisory_low"):
            expected = (
                "insufficient_basis"
                if guard["case_id"] == "advisory_info"
                else "suspicion_for_review"
            )
            if guard.get("decision") != expected:
                errors.append("Advisory boundary rule differs")
        elif (
            guard.get("blocked") is not True
            or guard.get("permitted") is True
            or not guard.get("error_type")
        ):
            errors.append("Invalid condition granted authority")
        if guard["case_id"] in (
            "write_without_approval",
            "pending_write",
            "forged_approval_id",
            "stable_action_id_mismatch",
            "approval_target_mismatch",
        ):
            if (
                guard.get("policy", {}).get("decision") != "require_approval"
                or guard.get("approval_required") is not True
            ):
                errors.append("Write approval requirement missing")
        if any(status != "pending" for status in guard.get("approval_statuses", [])):
            errors.append("Unexpected decided approval")
        if guard.get("write_calls", 0) != 0 or guard.get("verification_records", 0) != 0:
            errors.append("Guard dispatched WRITE or human authorization")
    return errors


def audit_projection(sequence: SequenceTrace) -> list[dict]:
    snapshots = {}
    repositories = set()
    identities = {}
    for event in sequence.events:
        for entry in event.trace.entries:
            snapshot = entry.content.snapshot
            snapshots[(str(snapshot.incident_id), snapshot.revision)] = snapshot
            repositories.add(str(snapshot.repository_id))
            for ref in entry.content.result.references:
                if ref.identity not in identities:
                    identities[ref.identity] = (
                        f"{snapshot.incident_id}:{ref.kind}:{len(identities)}"
                    )
    if len(repositories) != 1:
        raise ValueError("Mixed audit repositories")
    result = []
    for i, audit in enumerate(sequence.audit):
        data = audit.model_dump(mode="json")
        data.pop("occurred_at")
        data["event_id"] = f"audit:{i}"
        for key in ("before", "after"):
            if data[key] is not None:
                anchor = getattr(audit, key)
                if snapshots.get((str(anchor.incident_id), anchor.revision)) != anchor:
                    raise ValueError("Audit snapshot differs from actual runtime lineage")
                data[key] |= {
                    "repository_id": "isolated-store",
                    "fingerprint": f"validated-snapshot:{anchor.incident_id}:{anchor.revision}",
                }
        if data["decision_id"] in identities:
            data["decision_id"] = identities[data["decision_id"]]
        result.append(data)
    return result


def projection(value: DecisionExport) -> dict:
    return {
        "sequences": [
            {
                "case_id": s.case_id,
                "events": [event_projection(e) for e in s.events],
                "audit": audit_projection(s),
                "write_calls": s.write_calls,
                "approval_rows": s.approval_rows,
                "execution_rows": s.execution_rows,
            }
            for s in value.sequences
        ],
        "guards": value.guards,
    }


def compare(left: dict, right: dict) -> dict:
    result = {"contract": "soc-decision-comparison:v1", "status": "INCONCLUSIVE"}
    if (
        left.get("contract") is not None
        and left.get("contract") != CONTRACT
        or right.get("contract") is not None
        and right.get("contract") != CONTRACT
    ):
        return result | {"status": "FAIL", "reason": "Decision trace contract mismatch"}
    try:
        a, b = DecisionExport.model_validate(left), DecisionExport.model_validate(right)
        errors = correctness(a) + correctness(b)
        if errors:
            return result | {"status": "FAIL", "correctness": "FAIL", "errors": sorted(set(errors))}
        identity = (a.fixture_sha256, a.policy_sha256, a.model_files) == (
            b.fixture_sha256,
            b.policy_sha256,
            b.model_files,
        )
        from tests.diagnose_windows_selection import different_fields

        differences = different_fields(projection(a), projection(b), limit=64)
        equal = identity and not differences
        cross = {a.environment["system"], b.environment["system"]} == {"Linux", "Windows"}
        return result | {
            "status": "PASS" if equal and cross else "INCONCLUSIVE" if equal else "FAIL",
            "scope": "fixed synthetic fixtures + scripted LLM + actual domain/guard logic",
            "identity": "PASS" if identity else "FAIL",
            "correctness": "PASS",
            "decision_equivalence": "PASS" if equal else "FAIL",
            "cross_platform_execution": "PASS" if cross else "INCONCLUSIVE",
            "difference_paths": differences,
            "not_validated": [
                "real LLM behavior",
                "accepted operational human authorization",
                "runtime GOVERN/ACT/EVALUATE and promoted stable action ID (not reached)",
                "privileged response execution",
                "production deployment",
                "legacy ApprovalRequest TTL (not implemented)",
            ],
        }
    except (ValueError, KeyError, TypeError, AttributeError) as error:
        from pydantic import ValidationError

        missing = (
            isinstance(error, KeyError)
            or isinstance(error, ValidationError)
            and any(e["type"] == "missing" for e in error.errors())
        )
        return result | {
            "status": "INCONCLUSIVE" if missing else "FAIL",
            "error_type": type(error).__name__,
        }
