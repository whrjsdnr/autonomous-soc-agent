"""Single-process in-memory approval boundary; no policy or execution."""

from uuid import UUID

from pydantic import ValidationError

from soc_agent.approval.errors import (
    ApprovalAlreadyDecidedError,
    ApprovalNotFoundError,
    ApprovalValidationError,
)
from soc_agent.approval.models import ApprovalDecision, ApprovalRequest, ApprovalStatus, utc_now
from soc_agent.tools.models import ToolMetadata


class ApprovalManager:
    """Trusted human-facing callers invoke approve/reject explicitly.

    Do not expose these methods to an LLM as tools. Actor authentication and
    authorization are the future caller's responsibility. This is not durable or
    thread-safe storage. A request or approval never overrides a policy denial.
    """

    def __init__(self) -> None:
        self._requests: dict[UUID, ApprovalRequest] = {}

    def create(
        self,
        *,
        incident_id: UUID,
        metadata: ToolMetadata,
        reason: str,
        action_id: UUID | None = None,
        action_input_json: str | None = None,
    ) -> ApprovalRequest:
        if not isinstance(metadata, ToolMetadata):
            raise ApprovalValidationError("Invalid tool metadata")
        try:
            validated = ToolMetadata.model_validate(metadata.model_dump(warnings=False))
            request = ApprovalRequest(
                incident_id=incident_id,
                action_id=action_id,
                action_input_json=action_input_json,
                tool_name=validated.name,
                permission=validated.permission,
                risk_level=validated.risk_level,
                reason=reason,
            )
        except ValidationError as error:
            raise ApprovalValidationError("Invalid approval request") from error
        if request.approval_id in self._requests:
            raise ApprovalValidationError("Approval ID already exists")
        self._requests[request.approval_id] = request
        return request

    def get(self, approval_id: UUID) -> ApprovalRequest:
        try:
            return self._requests[approval_id]
        except KeyError as error:
            raise ApprovalNotFoundError("Approval request not found") from error

    def list(self) -> tuple[ApprovalRequest, ...]:
        return tuple(self._requests.values())

    def approve(self, approval_id: UUID, *, actor: str) -> ApprovalRequest:
        return self._decide(approval_id, actor=actor, status=ApprovalStatus.APPROVED)

    def reject(self, approval_id: UUID, *, actor: str) -> ApprovalRequest:
        return self._decide(approval_id, actor=actor, status=ApprovalStatus.REJECTED)

    def _decide(self, approval_id: UUID, *, actor: str, status: ApprovalStatus) -> ApprovalRequest:
        request = self.get(approval_id)
        if request.status != ApprovalStatus.PENDING:
            raise ApprovalAlreadyDecidedError("Approval request already has a decision")
        try:
            decision = ApprovalDecision.model_validate(
                {
                    "status": status,
                    "decided_by": actor,
                    "decided_at": max(utc_now(), request.created_at),
                }
            )
            updated = ApprovalRequest.model_validate(
                request.model_dump() | {"status": status, "decision": decision.model_dump()}
            )
        except ValidationError as error:
            raise ApprovalValidationError("Invalid human decision") from error
        self._requests[approval_id] = updated
        return updated
