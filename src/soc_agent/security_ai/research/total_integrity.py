"""Runtime proof envelopes over immutable model receipts and append-only audit.

Model receipts keep their v1 schema. This separate, hash-bound integrity receipt
records eligibility at inference time; projections expose later quarantine without
rewriting either historical receipt or audit history.
"""

import json
from typing import Literal
from uuid import UUID

from soc_agent.review.models import Hash
from soc_agent.security_ai.operational.network_capture.isolated_flow import POLICY
from soc_agent.security_ai.research.models import Frozen, digest


class InferenceIntegrity(Frozen):
    contract: Literal["soc-total-inference-integrity:v1"]
    capture_session: UUID
    flow_id: Hash
    flow_key_digest: Hash
    feature_digest: Hash
    artifact_digest: Hash
    model_receipt_digest: Hash
    integrity_status: Literal["FLOW_LOCAL_VERIFIED"]
    quarantine_reference: None
    event_time_policy: Literal[POLICY]
    capture_integrity: Literal["FIXTURE_NO_CAPTURE", "VERIFIED_PREFIX_ONLY"]
    future_capture_quality: Literal["UNKNOWN"]
    source_origin: Literal["FIXTURE", "NATIVE_AF_PACKET"]
    source_digest: Hash
    provenance_digest: Hash
    research_status: Literal["RESEARCH_ONLY"]
    operational_gate: Literal["BLOCKED"]


class FlowQuarantined(ValueError):
    def __init__(self, flow_id):
        super().__init__("TOTAL_FLOW_QUARANTINED_NO_RETRY")
        self.flow_id = flow_id


class FlowFeatureMismatch(FlowQuarantined):
    pass


class TotalIntegrity:
    def __init__(self, owner):
        self.owner = owner
        self.proofs = {}
        self.quarantines = {}

    def restore(self):
        runtime = self.owner.store.runtime
        runtime.verify_audit()
        policies = []
        with runtime.database.transaction(write=False) as c:
            for row in c.execute("SELECT payload FROM monitor_audit ORDER BY sequence"):
                event = json.loads(row[0])
                if event["kind"] == "TOTAL_INTEGRITY_POLICY":
                    policies.append(event["details"])
                elif event["kind"] == "TOTAL_FLOW_INTEGRITY_RECEIPT":
                    proof = event["details"]
                    self._check(proof)
                    self.proofs[proof["binding_digest"]] = proof
                elif event["kind"] == "TOTAL_FLOW_QUARANTINED":
                    details = event["details"]
                    value = details["event"]
                    content = {
                        k: v for k, v in value.items() if k not in ("kind", "quarantine_reference")
                    }
                    if details["capture_session"] != str(self.owner.session.session_id) or value[
                        "quarantine_reference"
                    ] != digest(content):
                        raise ValueError("TOTAL_QUARANTINE_REFERENCE_REJECTED")
                    self.quarantines[value["flow_key_digest"]] = value["quarantine_reference"]
        if len(self.proofs) > 256 or len(self.quarantines) > 1024:
            raise ValueError("TOTAL_RETAINED_INTEGRITY_BUDGET")
        if policies:
            if len(policies) != 1 or policies[0] != dict(
                policy=POLICY,
                capture_session=str(self.owner.session.session_id),
                session_digest=digest(self.owner.session.model_dump(mode="json")),
                capture_wide_fail_closed=True,
                key_history_limit=self.owner.policy.max_flow_records,
                active_key_limit=self.owner.policy.active_flows,
                dns_connection_limit=128,
            ):
                raise ValueError("TOTAL_INTEGRITY_POLICY_BINDING_FAILED")
        elif self.proofs or self.quarantines:
            raise ValueError("TOTAL_INTEGRITY_POLICY_MISSING")

    @staticmethod
    def _check(proof):
        value = {k: v for k, v in proof.items() if k != "binding_digest"}
        InferenceIntegrity.model_validate(value)
        if proof.get("binding_digest") != digest(value):
            raise ValueError("TOTAL_INTEGRITY_RECEIPT_TAMPERED")

    def guard(self, request):
        owner = self.owner
        if owner.aborted:
            raise ValueError("TOTAL_CAPTURE_INTEGRITY_UNVERIFIED")
        if owner.current is None or request.capture_session != owner.session.session_id:
            raise ValueError("TOTAL_UNREGISTERED_FLOW_REQUEST")
        if request.flow_id not in owner.aggregator.flow_keys:
            raise ValueError("TOTAL_FLOW_INDEPENDENCE_UNKNOWN")
        if not owner.aggregator.allowed(request.flow_id):
            raise FlowQuarantined(request.flow_id)
        expected, _ = owner.store.load(owner.current.event, request.profile)
        if expected.model_copy(update={"invocation_id": request.invocation_id}) != request:
            raise ValueError("TOTAL_FLOW_REQUEST_SOURCE_MISMATCH")

    def seal(self, request, receipt):
        self.guard(request)
        owner = self.owner
        value = dict(
            contract="soc-total-inference-integrity:v1",
            capture_session=str(request.capture_session),
            flow_id=request.flow_id,
            flow_key_digest=owner.aggregator.flow_keys[request.flow_id],
            feature_digest=receipt.feature_digest,
            artifact_digest=receipt.artifact_digest,
            model_receipt_digest=digest(receipt.model_dump(mode="json")),
            integrity_status="FLOW_LOCAL_VERIFIED",
            quarantine_reference=None,
            event_time_policy=owner.aggregator.snapshot()["policy"],
            capture_integrity="FIXTURE_NO_CAPTURE" if owner.fixture else "VERIFIED_PREFIX_ONLY",
            future_capture_quality="UNKNOWN",
            source_origin=request.origin,
            source_digest=receipt.source_digest,
            provenance_digest=request.provenance_digest,
            research_status="RESEARCH_ONLY",
            operational_gate="BLOCKED",
        )
        proof = dict(**value, binding_digest=digest(value))
        self._check(proof)
        if len(self.proofs) >= 256:
            raise ValueError("TOTAL_INTEGRITY_RECEIPT_LIMIT")
        owner.store.runtime.event("TOTAL_FLOW_INTEGRITY_RECEIPT", proof)
        self.proofs[proof["binding_digest"]] = proof
        return proof

    def project(self, research):
        owner = self.owner
        quarantines = dict(self.quarantines)
        if getattr(owner, "aggregator", None) is not None and owner.task is not None:
            quarantines.update(owner.aggregator.snapshot()["quarantine_references"])
        for record in research.get("records", []):
            proof = record.get("integrity_receipt")
            if proof is None:  # Historical receipts are not silently given a new proof.
                record["integrity_status_current"] = "LEGACY_NO_ISOLATION_PROOF"
                continue
            self._check(proof)
            receipt = record.get("receipt")
            if (
                self.proofs.get(proof["binding_digest"]) != proof
                or not receipt
                or proof["model_receipt_digest"] != digest(receipt)
                or proof["capture_session"] != str(owner.session.session_id)
                or proof["flow_id"] != receipt["flow_id"]
            ):
                raise ValueError("TOTAL_INTEGRITY_AUDIT_BINDING_FAILED")
            reference = quarantines.get(proof["flow_key_digest"])
            record["integrity_status_current"] = (
                "CAPTURE_INTEGRITY_FAILED"
                if owner.metrics.get("integrity_scope") in ("CAPTURE_WIDE", "UNKNOWN")
                else "QUARANTINED_FLOW"
                if reference
                else "RECOVERY_PENDING"
                if owner.metrics.get("recovery_terminal_verified") is False
                else "FLOW_LOCAL_VERIFIED"
            )
            record["quarantine_reference"] = reference
            record["advisory_current"] = (
                "RETAINED_RESEARCH_ONLY"
                if record["integrity_status_current"] == "FLOW_LOCAL_VERIFIED"
                else "WITHDRAWN_RESEARCH_ONLY"
            )
        return research
