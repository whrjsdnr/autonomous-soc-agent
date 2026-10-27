"""Post-Supervisor evidence bridge. No capture, permission grant, or source promotion.

Recompute capture and input receipts; a stored VERIFIED string is never admission.
Native analysis additionally needs an exact action approval in trusted composition.
"""

import hashlib
from pathlib import Path
from typing import Literal
from uuid import UUID

from pydantic import Field, model_validator

from soc_agent.review.models import Hash
from soc_agent.security_ai.ebpf.input_eligibility import input_receipts
from soc_agent.security_ai.ebpf_tc.capture_evidence import assess_capture
from soc_agent.security_ai.research.environment import catalogue
from soc_agent.security_ai.research.models import SPECS, Frozen, WorkerLimits, digest
from soc_agent.security_ai.workflow_models import TCXAnalysisJob
from soc_agent.state.evidence import UTCTimestamp


def implementation_digest() -> str:
    root = Path(__file__).parents[1]
    return digest(
        {
            str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(root.rglob("*.py"))
        }
    )


def candidates(job: TCXAnalysisJob) -> tuple[dict, dict, list[dict]]:
    tcx = job.result.get("tcx")
    if not isinstance(tcx, dict):
        raise ValueError("TCX_SUPERVISOR_RESULT_REQUIRED")
    transport = tcx.get("data_plane")
    if not isinstance(transport, dict) or not isinstance(transport.get("processing"), dict):
        raise ValueError("TCX_PROCESSING_RESULT_REQUIRED")
    summary = transport["processing"]
    if not isinstance(summary.get("feature_tail"), list) or len(summary["feature_tail"]) > 4:
        raise ValueError("TCX_RETAINED_VECTOR_BOUND")
    plan = summary.get("plan") or {}
    expected_source = (
        "KERNEL_TCX_NATIVE" if job.origin == "REAL_NATIVE" else "ORDINARY_UID_PACKET_FIXTURE"
    )
    if (
        plan.get("session_id") != str(job.session)
        or plan.get("net_namespace") != job.namespace
        or plan.get("interface") != "lo"
        or plan.get("hook") != "INGRESS"
        or tcx.get("release_manifest_digest") != job.release_manifest
        or transport.get("source") != expected_source
    ):
        raise ValueError("TCX_SESSION_NAMESPACE_RELEASE_OR_ORIGIN_MISMATCH")
    stored = transport.get("capture_evidence")
    if not isinstance(stored, dict):
        raise ValueError("TCX_CAPTURE_EVIDENCE_MISSING")
    scope = stored.get("source_provenance") or {}
    computed = assess_capture(
        transport.get("counter_evidence"),
        transport.get("delivery_accounting"),
        summary,
        closed=transport.get("terminal_closed_observed") is True,
        error=transport.get("error") or transport.get("cleanup_error"),
        source=1 if job.origin == "REAL_NATIVE" else 2,
        scope=scope,
        cpu_windows=transport.get("cpu_windows"),
        clock_samples=transport.get("clock_samples"),
    )
    if computed != stored:
        raise ValueError("TCX_CAPTURE_REASSESSMENT_MISMATCH")
    receipts = input_receipts(summary, transport)
    # Persist all candidate rejections. Source drain/errors cannot be erased by a
    # valid feature row, and the Root/Native approval is not a model approval.
    if (
        any(transport.get(k) for k in ("transport_failed", "io_failure", "processing_io_failure"))
        or transport.get("drain_state") != "VERIFIED"
    ):
        receipts = [
            dict(
                r,
                input_state="INCOMPLETE" if r["input_state"] == "ELIGIBLE" else r["input_state"],
                eligible=False,
                reasons=r["reasons"] + ["TCX_DRAIN_OR_TRANSPORT_NOT_VERIFIED"],
            )
            for r in receipts
        ]
        receipts = [
            dict(r, receipt_digest=digest({k: v for k, v in r.items() if k != "receipt_digest"}))
            for r in receipts
        ]
    return summary, transport, receipts


def vector(job: TCXAnalysisJob, flow_id: str, receipt_digest: str):
    summary, _, receipts = candidates(job)
    receipt = next((r for r in receipts if r["flow_id"] == flow_id), None)
    if (
        not receipt
        or receipt["input_state"] != "ELIGIBLE"
        or receipt["receipt_digest"] != receipt_digest
    ):
        raise ValueError("TCX_INPUT_NOT_ELIGIBLE")
    rows = [r for r in summary["feature_tail"] if r["flow_id"] == flow_id]
    if len(rows) != 1 or rows[0]["feature_names"] != catalogue()["feature_names"]:
        raise ValueError("TCX_MODEL_SCHEMA_MISMATCH")
    row = rows[0]
    if digest(row["values"]) != receipt["feature_fingerprint"]:
        raise ValueError("TCX_MODEL_FEATURE_FINGERPRINT_MISMATCH")
    return row, receipt


class VectorRequest(Frozen):
    contract: Literal["soc-tcx-vector-request:v1"] = "soc-tcx-vector-request:v1"
    profile: Literal["quality", "edge"]
    invocation_id: UUID
    job: TCXAnalysisJob
    flow_id: Hash
    input_receipt_digest: Hash

    @model_validator(mode="after")
    def eligible(self):
        if self.profile not in self.job.profiles:
            raise ValueError("TCX_MODEL_PROFILE_SCOPE")
        vector(self.job, self.flow_id, self.input_receipt_digest)
        return self


class VectorReceipt(Frozen):
    contract: Literal["soc-tcx-model-receipt:v1"] = "soc-tcx-model-receipt:v1"
    origin: Literal["REAL_NATIVE", "FIXTURE"]
    profile: Literal["quality", "edge"]
    request_digest: Hash
    invocation_id: UUID
    source_digest: Hash
    session: UUID
    namespace: str
    release_manifest: Hash
    flow_id: Hash
    input_receipt_digest: Hash
    feature_fingerprint: Hash
    feature_names: tuple[str, ...] = Field(min_length=14, max_length=14)
    feature_values: tuple[float, ...] = Field(min_length=14, max_length=14)
    model_id: str
    artifact_digest: Hash
    model_manifest_digest: Hash
    score: float = Field(ge=0, le=1)
    threshold: float
    prediction: Literal["CLASS_0", "CLASS_1"]
    inferred_at: UTCTimestamp
    inference_latency_ms: float = Field(ge=0)
    worker_limits: WorkerLimits
    operational_promotion: Literal["BLOCKED"] = "BLOCKED"

    @model_validator(mode="after")
    def bindings(self):
        spec = SPECS[self.profile]
        if (
            self.model_id != spec["model_id"]
            or self.artifact_digest != spec["sha256"]
            or self.model_manifest_digest != spec["manifest"]
            or self.threshold != spec["threshold"]
            or self.prediction != ("CLASS_1" if self.score >= self.threshold else "CLASS_0")
            or list(self.feature_names) != catalogue()["feature_names"]
            or digest(self.feature_values) != self.feature_fingerprint
        ):
            raise ValueError("TCX_MODEL_RECEIPT_INCOMPATIBLE")
        return self


def validate_vector_result(request: VectorRequest, receipt: VectorReceipt):
    row, _ = vector(request.job, request.flow_id, request.input_receipt_digest)
    expected = dict(
        origin=request.job.origin,
        session=request.job.session,
        namespace=request.job.namespace,
        release_manifest=request.job.release_manifest,
        source_digest=digest(request.job.model_dump(mode="json")),
        flow_id=request.flow_id,
        input_receipt_digest=request.input_receipt_digest,
        request_digest=digest(request.model_dump(mode="json")),
        invocation_id=request.invocation_id,
        profile=request.profile,
        feature_fingerprint=row["values_digest"],
    )
    if any(getattr(receipt, k) != v for k, v in expected.items()) or list(
        receipt.feature_values
    ) != list(row["values"]):
        raise ValueError("TCX_WORKER_RECEIPT_BINDING_MISMATCH")


def from_supervisor(
    result: dict, *, namespace: str, session: UUID, release_manifest: str
) -> TCXAnalysisJob:
    source = result.get("tcx", {}).get("data_plane", {}).get("source")
    if source not in ("KERNEL_TCX_NATIVE", "ORDINARY_UID_PACKET_FIXTURE"):
        raise ValueError("TCX_SOURCE_UNKNOWN")
    job = TCXAnalysisJob(
        kind="tcx_analysis",
        origin="REAL_NATIVE" if source == "KERNEL_TCX_NATIVE" else "FIXTURE",
        namespace=namespace,
        session=session,
        release_manifest=release_manifest,
        result=result,
    )
    candidates(job)
    return job


def dns_admission(job: TCXAnalysisJob) -> dict:
    """Preserve existing Sidecar transaction metadata; never reconstruct absent wire bytes."""
    tcx = job.result["tcx"]
    summary = tcx.get("zeek_summary") or {}
    metadata = summary.get("dns_transactions") if isinstance(summary, dict) else None
    body = dict(
        contract="soc-supervisor-dns-admission:v1",
        session=str(job.session),
        namespace=job.namespace,
        release_manifest=job.release_manifest,
        source_result_digest=digest(job.result),
        transaction_metadata=metadata,
        raw_dns_status="NOT_RETAINED_IN_SUPERVISOR_RESULT",
        transaction_status="RETAINED_SIDECAR_METADATA"
        if isinstance(metadata, dict)
        else "NOT_OBSERVED",
        feature_status="INCOMPLETE",
        model_inference_executed=False,
        reasons=["DNS9_PRODUCER_PARITY_UNVERIFIED", "NO_RAW_DNS9_EXTRACTION_CONTRACT"],
        source_assurance="DECLARED_UNATTESTED",
        scope="NO_NATIVE_PAYLOAD_RETENTION_POLICY_CHANGE",
    )
    return dict(body, receipt_digest=digest(body))
