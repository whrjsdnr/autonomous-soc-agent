"""Exact already sealed Host journal IF Action using existing deterministic governance."""

from pathlib import Path
from uuid import NAMESPACE_URL, uuid5

from pydantic import Field

from soc_agent.approval import ApprovalManager, ApprovalRequest
from soc_agent.continuous.host_authentication import implementation_digest, validate_job
from soc_agent.execution import ActionProposal, GovernedExecutor
from soc_agent.policy import PolicyEngine
from soc_agent.review.models import Hash
from soc_agent.security_ai.research.models import Frozen, digest
from soc_agent.security_ai.workflow_models import AuthenticationWindowJob
from soc_agent.state.evidence import utc_now
from soc_agent.tools import Tool, ToolMetadata, ToolRegistry

METADATA = ToolMetadata(
    name="analyze_retained_host_authentication_if",
    description="One exact sealed declared journal window using pinned research IF; no Host read",
    permission="file_read",
    risk_level="medium",
)


class IFActionInput(Frozen):
    job_sha256: Hash
    implementation_sha256: Hash
    attempt_directory: str
    session: str
    namespace: str
    scope_sha256: Hash
    evidence_revision: Hash
    model_manifest_sha256: Hash
    feature_fingerprint: Hash


class IFActionOutput(Frozen):
    inferences: int = Field(ge=0, le=1)


def incident_id(job: AuthenticationWindowJob):
    return uuid5(NAMESPACE_URL, "soc-retained-host-if:" + digest(job.model_dump(mode="json")))


def analysis_action(job: AuthenticationWindowJob, directory: Path) -> ActionProposal:
    validate_job(job)
    binding = job.host_binding
    body = IFActionInput(
        job_sha256=digest(job.model_dump(mode="json")),
        implementation_sha256=implementation_digest(),
        attempt_directory=str(directory.absolute()),
        session=str(binding.session),
        namespace=binding.namespace,
        scope_sha256=binding.scope_sha256,
        evidence_revision=binding.evidence_revision,
        model_manifest_sha256=job.packages[0].manifest_sha256,
        feature_fingerprint=binding.feature_fingerprint,
    )
    return ActionProposal(
        action_id=uuid5(NAMESPACE_URL, "soc-host-if:" + digest(body.model_dump(mode="json"))),
        incident_id=incident_id(job),
        tool_name=METADATA.name,
        tool_input=body.model_dump(mode="json"),
    )


async def analyze(job, state, record, directory, write, event, approval: ApprovalRequest | None):
    from soc_agent.security_ai.workflow_inputs import packaged

    proposed = analysis_action(job, directory)
    manager = ApprovalManager()
    registry = ToolRegistry()
    executor = GovernedExecutor(registry=registry, policy=PolicyEngine(), approvals=manager)
    fusion = None

    def authorize():
        if analysis_action(job, directory).input_payload() != proposed.input_payload():
            raise ValueError("HOST_IF_SOURCE_CHANGED_AFTER_APPROVAL")
        executor.preflight(proposed, approval_id=approval.approval_id)

    async def handle(value: IFActionInput):
        nonlocal fusion
        if value.model_dump(mode="json") != proposed.input_payload():
            raise ValueError("HOST_IF_EXACT_ACTION_CHANGED")
        fusion = await packaged(job, state, record, authorize=authorize)
        return IFActionOutput(inferences=1)

    registry.register(Tool(METADATA, IFActionInput, IFActionOutput, handle))
    write("host-if-action.json", proposed.model_dump(mode="json"))
    event("HOST_IF_ACTION_BOUND", proposed.model_dump(mode="json"))
    if approval is None:
        pending = executor.request_approval(
            proposed, reason="Exact declared Host window, research IF only"
        )
        write("host-if-approval-pending.json", pending.model_dump(mode="json"))
        event("HOST_IF_APPROVAL_REQUIRED", pending.model_dump(mode="json"))
        return None
    if (
        approval.expires_at is None
        or approval.decision is None
        or approval.decision.decided_at > utc_now()
    ):
        raise ValueError("HOST_IF_EXPLICIT_CURRENT_HUMAN_APPROVAL_REQUIRED")
    manager.restore(approval)
    executor.preflight(proposed, approval_id=approval.approval_id)
    write("host-if-approval.json", approval.model_dump(mode="json"))
    event("HOST_IF_APPROVAL_VALIDATED", approval.model_dump(mode="json"))
    event("HOST_IF_EXECUTION_INTENT", proposed.model_dump(mode="json"))
    await executor.execute(proposed, approval_id=approval.approval_id)
    event("HOST_IF_EXECUTION_COMPLETED", proposed.model_dump(mode="json"))
    return fusion
