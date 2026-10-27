"""Reuse existing governed Action approval for post-capture model analysis.

This is not Root/Native capture approval and never changes Collector's BLOCKED flag.
An operator-supplied approval SHA is an explicit trust anchor, not authentication by shape.
"""

from collections.abc import Callable
from pathlib import Path
from uuid import NAMESPACE_URL, uuid4, uuid5

from pydantic import Field

from soc_agent.approval import ApprovalManager, ApprovalRequest
from soc_agent.execution import ActionProposal, GovernedExecutor
from soc_agent.policy import PolicyEngine
from soc_agent.review.models import Hash
from soc_agent.security_ai.research.adapter import ResearchAdapter
from soc_agent.security_ai.research.models import Frozen, digest
from soc_agent.security_ai.tcx_input import VectorReceipt, VectorRequest, implementation_digest
from soc_agent.security_ai.workflow_models import InferenceRecord, TCXAnalysisJob
from soc_agent.state.evidence import utc_now
from soc_agent.tools import Tool, ToolMetadata, ToolRegistry

METADATA = ToolMetadata(
    name="analyze_retained_tcx",
    description="Exact retained eligible TCX vectors; no capture or host action",
    permission="file_read",
    risk_level="medium",
)


class TCXActionInput(Frozen):
    job_sha256: Hash
    implementation_sha256: Hash
    attempt_directory: str
    session: str
    namespace: str
    release_manifest: Hash


class TCXActionOutput(Frozen):
    inferences: int = Field(ge=0)


def incident_id(job):
    return uuid5(NAMESPACE_URL, "soc-retained-tcx:" + digest(job.model_dump(mode="json")))


def analysis_action(job: TCXAnalysisJob, directory: Path) -> ActionProposal:
    binding = TCXActionInput(
        job_sha256=digest(job.model_dump(mode="json")),
        implementation_sha256=implementation_digest(),
        attempt_directory=str(directory.absolute()),
        session=str(job.session),
        namespace=job.namespace,
        release_manifest=job.release_manifest,
    )
    return ActionProposal(
        action_id=uuid5(NAMESPACE_URL, digest(binding.model_dump(mode="json"))),
        incident_id=incident_id(job),
        tool_name=METADATA.name,
        tool_input=binding.model_dump(mode="json"),
    )


async def infer(job, receipts, adapter: ResearchAdapter, record: Callable[[InferenceRecord], None]):
    count = 0
    for row in receipts:
        if row["input_state"] != "ELIGIBLE":
            continue
        for profile in job.profiles:
            request = VectorRequest(
                profile=profile,
                invocation_id=uuid4(),
                job=job,
                flow_id=row["flow_id"],
                input_receipt_digest=row["receipt_digest"],
            )
            result = await adapter.infer(request)
            if result.get("status") != "SUCCESS":
                raise ValueError("TCX_MODEL_WORKER_FAILED_NO_RETRY")
            r = VectorReceipt.model_validate(result["receipt"])
            record(
                InferenceRecord(
                    event_identity=r.flow_id,
                    model_id=r.model_id,
                    model_version="manifest-sha256:" + r.model_manifest_digest,
                    model_manifest_digest=r.model_manifest_digest,
                    artifact_digest=r.artifact_digest,
                    feature_fingerprint=r.feature_fingerprint,
                    evidence_references=(r.source_digest, r.input_receipt_digest),
                    prediction=r.prediction,
                    score=r.score,
                    score_semantics="Research-only ranking; not calibrated attack probability",
                    inferred_at=r.inferred_at,
                    latency_ms=r.inference_latency_ms,
                    receipt=r.model_dump(mode="json"),
                )
            )
            count += 1
    return count


async def analyze(
    job, receipts, adapter, record, directory, write, event, approval: ApprovalRequest | None
):
    if job.origin == "FIXTURE":
        await infer(job, receipts, adapter, record)
        return True
    action = analysis_action(job, directory)
    approvals = ApprovalManager()
    registry = ToolRegistry()
    executor = GovernedExecutor(registry=registry, policy=PolicyEngine(), approvals=approvals)

    def authorize(request):
        if digest(request.job.model_dump(mode="json")) != digest(job.model_dump(mode="json")):
            raise ValueError("TCX_APPROVED_JOB_MUTATION")
        if analysis_action(job, directory).input_payload() != action.input_payload():
            raise ValueError("TCX_APPROVED_SOURCE_MUTATION")
        executor.preflight(action, approval_id=approval.approval_id)

    async def handle(value: TCXActionInput):
        if value.model_dump(mode="json") != action.input_payload():
            raise ValueError("TCX_ACTION_BINDING_MISMATCH")
        adapter.authorize_tcx = authorize
        return TCXActionOutput(inferences=await infer(job, receipts, adapter, record))

    registry.register(Tool(METADATA, TCXActionInput, TCXActionOutput, handle))
    write("tcx-model-action.json", action.model_dump(mode="json"))
    event("TCX_MODEL_ACTION_BOUND", action.model_dump(mode="json"))
    if approval is None:
        pending = executor.request_approval(
            action, reason="Human review required for exact retained Native model analysis"
        )
        write("tcx-model-approval-pending.json", pending.model_dump(mode="json"))
        event("TCX_MODEL_APPROVAL_REQUIRED", pending.model_dump(mode="json"))
        return False
    if (
        approval.expires_at is None
        or approval.decision is None
        or approval.decision.decided_at > utc_now()
    ):
        raise ValueError("TCX_HUMAN_APPROVAL_TIME_OR_DECISION_REQUIRED")
    approvals.restore(approval)
    executor.preflight(action, approval_id=approval.approval_id)
    write("tcx-model-approval.json", approval.model_dump(mode="json"))
    event("TCX_MODEL_APPROVAL_VALIDATED", approval.model_dump(mode="json"))
    event("TCX_MODEL_EXECUTION_INTENT", action.model_dump(mode="json"))
    try:
        await executor.execute(action, approval_id=approval.approval_id)
    except BaseException:
        event("TCX_MODEL_EXECUTION_FAILED", action.model_dump(mode="json"))
        raise
    event("TCX_MODEL_EXECUTION_COMPLETED", action.model_dump(mode="json"))
    return True
