"""Single-process in-memory approval boundary; no policy or execution."""

from collections.abc import Callable
from datetime import datetime
from uuid import UUID

from pydantic import TypeAdapter, ValidationError

from soc_agent.approval.errors import (
    ApprovalAlreadyDecidedError,
    ApprovalExpiredError,
    ApprovalNotFoundError,
    ApprovalValidationError,
)
from soc_agent.approval.models import (
    ApprovalDecision,
    ApprovalRequest,
    ApprovalStatus,
    UTCTimestamp,
    utc_now,
)
from soc_agent.tools.models import ToolMetadata


class ApprovalManager:
    """Trusted human-facing callers invoke approve/reject explicitly.

    Do not expose these methods to an LLM as tools. Actor authentication and
    authorization are the future caller's responsibility. This is not durable or
    thread-safe storage. A request or approval never overrides a policy denial.
    """

    def __init__(self, *, clock: Callable[[], datetime] = utc_now) -> None:
        self.execution_guard = None
        self._clock = clock
        self._requests: dict[UUID, ApprovalRequest] = {}

    def create(
        self,
        *,
        incident_id: UUID,
        metadata: ToolMetadata,
        reason: str,
        action_id: UUID | None = None,
        action_input_json: str | None = None,
        expires_at: datetime | None = None,
    ) -> ApprovalRequest:
        if self.execution_guard is not None:
            self.execution_guard.mutation(incident_id, "APPROVAL_ISSUANCE_DENIED")
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
                created_at=self.now(),
                expires_at=expires_at,
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

    def now(self) -> datetime:
        return TypeAdapter(UTCTimestamp).validate_python(self._clock())

    def require_current(self, approval_id: UUID) -> ApprovalRequest:
        request = ApprovalRequest.model_validate(self.get(approval_id).model_dump())
        if request.expires_at is not None and self.now() >= request.expires_at:
            raise ApprovalExpiredError("Approval expired")
        return request

    def restore(self, request: ApprovalRequest) -> None:
        """Trusted persistence-only restoration, never a human approval API."""
        request = ApprovalRequest.model_validate(request.model_dump())
        if self.execution_guard is not None:
            self.execution_guard.mutation(request.incident_id, "APPROVAL_ISSUANCE_DENIED")
        if request.approval_id in self._requests:
            raise ApprovalValidationError("Approval ID already exists")
        self._requests[request.approval_id] = request

    def approve(self, approval_id: UUID, *, actor: str) -> ApprovalRequest:
        return self._decide(approval_id, actor=actor, status=ApprovalStatus.APPROVED)

    def reject(self, approval_id: UUID, *, actor: str) -> ApprovalRequest:
        return self._decide(approval_id, actor=actor, status=ApprovalStatus.REJECTED)

    def _decide(self, approval_id: UUID, *, actor: str, status: ApprovalStatus) -> ApprovalRequest:
        request = self.get(approval_id)
        if self.execution_guard is not None:
            self.execution_guard.mutation(request.incident_id, "APPROVAL_REPLAY")
        if request.status != ApprovalStatus.PENDING:
            raise ApprovalAlreadyDecidedError("Approval request already has a decision")
        self.require_current(approval_id)
        try:
            decision = ApprovalDecision.model_validate(
                {
                    "status": status,
                    "decided_by": actor,
                    "decided_at": max(self.now(), request.created_at),
                }
            )
            updated = ApprovalRequest.model_validate(
                request.model_dump() | {"status": status, "decision": decision.model_dump()}
            )
        except ValidationError as error:
            raise ApprovalValidationError("Invalid human decision") from error
        self._requests[approval_id] = updated
        return updated
