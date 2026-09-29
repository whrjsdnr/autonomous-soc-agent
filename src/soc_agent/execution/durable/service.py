"""Explicit durable dispatch; no worker, automatic retry or external transaction."""

from uuid import UUID

from pydantic import BaseModel

from soc_agent.approval import ApprovalManager, ApprovalRequest
from soc_agent.execution import GovernedExecutor
from soc_agent.execution.durable.errors import ClaimConflict, ExecutionOutcomeUnknown
from soc_agent.execution.durable.models import ExecutionRecord, Lifecycle
from soc_agent.execution.durable.store import ExecutionStore
from soc_agent.policy import PolicyEngine
from soc_agent.response.promotion.errors import PromotionPolicyChanged
from soc_agent.response.promotion.validation import CurrentValidation
from soc_agent.review.identity import content_digest
from soc_agent.review.persistence.models import CommitOutcomeUnknown, StorageError
from soc_agent.tools import ToolRegistry, ToolResult
from soc_agent.tools.errors import ToolExecutionError


class _RecordedApproval(ApprovalManager):
    """Read-only approved snapshot, restored only from the validated execution ledger.

    This is not general ApprovalManager persistence or an approval issuance API.
    """

    def __init__(self, approval: ApprovalRequest | None) -> None:
        super().__init__()
        if approval:
            self._requests[approval.approval_id] = approval

    def approve(self, approval_id: UUID, *, actor: str) -> ApprovalRequest:
        raise TypeError("Execution snapshot cannot issue approval")


class DurableExecutor:
    def __init__(
        self, *, store: ExecutionStore, registry: ToolRegistry, policy: PolicyEngine
    ) -> None:
        self.store = store
        self.validation = CurrentValidation(store.governance, registry, policy)

    async def execute(
        self, identity: str, *, claimant: str, lease_seconds: int = 60
    ) -> ToolResult[BaseModel]:
        claimed = self.store.claim(identity, claimant=claimant, lease_seconds=lease_seconds)
        return await self.execute_claim(claimed)

    async def execute_claim(self, claimed: ExecutionRecord) -> ToolResult[BaseModel]:
        # No caller-supplied intent is trusted: compare with persisted exact claim first.
        stored = self.store.load(claimed.intent.execution_intent_id)
        if stored != claimed or stored.state != Lifecycle.CLAIMED:
            raise ClaimConflict("Unregistered, forged or stale execution claim")
        intent = stored.intent
        try:
            current = self.validation.check(intent.plan, intent.promoted.content.request.target)
            if current != intent.promoted.content.current_policy:
                raise PromotionPolicyChanged("Policy changed since promotion")
            # ExecutionIntent revalidation on storage reads verifies exact Approval binding.
        except Exception as error:
            self.store.transition(stored, Lifecycle.FAILED, reason=type(error).__name__)
            raise
        # COMMIT must return successfully before any Tool invocation. An ambiguous commit
        # raises and leaves recovery/query to the caller; it never triggers dispatch.
        executing = self.store.transition(stored, Lifecycle.EXECUTING)
        executor = GovernedExecutor(
            registry=self.validation.registry,
            policy=self.validation.policy,
            approvals=_RecordedApproval(intent.approval),
        )
        try:
            result = await executor.execute(intent.action(), approval_id=intent.binding.approval_id)
        except BaseException as error:
            # Tool wrappers can hide timeout/connection loss behind ToolExecutionError.
            # An explicit adapter-reported ToolExecutionError (without an underlying
            # transport exception) is a reported failure, not proof of no partial effects.
            # Wrapped exceptions, timeout, cancellation and invalid output remain uncertain.
            outcome = (
                Lifecycle.FAILED
                if isinstance(error, ToolExecutionError) and error.__cause__ is None
                else Lifecycle.UNCERTAIN
            )
            try:
                self.store.transition(executing, outcome, reason=type(error).__name__)
            except (StorageError, CommitOutcomeUnknown, ClaimConflict) as storage_error:
                raise ExecutionOutcomeUnknown(
                    "Outcome persistence unavailable; query/recover"
                ) from storage_error
            raise
        try:
            self.store.transition(
                executing, Lifecycle.SUCCEEDED, result_digest=content_digest(result)
            )
        except Exception as error:
            # Success may already be committed. Never overwrite it or repeat the tool.
            # Serialization failures are also ambiguous after the external call.
            raise ExecutionOutcomeUnknown(
                "Tool returned; durable outcome requires fresh query"
            ) from error
        return result
