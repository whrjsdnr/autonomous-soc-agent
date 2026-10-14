"""Test-only response contracts; no operational resource paths or execution authority."""

import hashlib
from typing import Literal
from uuid import UUID

from pydantic import Field, model_validator

from soc_agent.approval import ApprovalRequest
from soc_agent.execution import ActionProposal
from soc_agent.security_ai.external.models import Hash, Snapshot, content_digest_payload
from soc_agent.state.evidence import UTCTimestamp, utc_now

ResourceID = Literal["test-marker"]
ActionType = Literal["TEST_RESOURCE_QUARANTINE", "TEST_RESOURCE_ROLLBACK"]
AVAILABLE = b"SOC_TEST_RESOURCE_AVAILABLE\n"
QUARANTINED = b"SOC_TEST_RESOURCE_QUARANTINED\n"


class ResourceRegistration(Snapshot):
    resource_id: ResourceID = "test-marker"
    runtime_location_digest: Hash | None = None
    runtime_identity: tuple[int, int]
    root_identity: tuple[int, int]
    marker_identity: tuple[int, int]

    @property
    def digest(self) -> str:
        return content_digest_payload(self.model_dump(mode="json"))


class RestrictedInput(Snapshot):
    action_type: ActionType
    resource_id: ResourceID = "test-marker"
    resource_registration_digest: Hash
    finding_id: Hash
    finding_digest: Hash
    incident_id: UUID
    investigation_digest: Hash
    evidence_digest: Hash
    evidence_references: tuple[Hash, ...]
    policy_digest: Hash
    runtime_config_digest: Hash
    before_digest: Hash
    original_receipt_digest: Hash | None = None

    @model_validator(mode="after")
    def rollback_binding(self):
        if (self.action_type == "TEST_RESOURCE_ROLLBACK") != (
            self.original_receipt_digest is not None
        ):
            raise ValueError("RESTRICTED_ROLLBACK_BINDING_REQUIRED")
        return self


class MarkerOutput(Snapshot):
    resource_id: ResourceID = "test-marker"
    before_digest: Hash
    after_digest: Hash
    actual_test_filesystem_change: Literal[True] = True
    os_security_configuration_changed: Literal[False] = False


class RestrictedReceipt(Snapshot):
    action_id: UUID
    approval_id: UUID
    input_digest: Hash
    output: MarkerOutput
    operator_uid: int = Field(strict=True, ge=0)
    operator_assurance: Literal["OS_PEER_UID"] = "OS_PEER_UID"
    recorded_at: UTCTimestamp

    @property
    def digest(self) -> str:
        return content_digest_payload(self.model_dump(mode="json"))


class RestrictedRecord(Snapshot):
    contract_version: Literal["soc-restricted-test-response:v1"] = "soc-restricted-test-response:v1"
    candidate_id: Hash
    action: ActionProposal
    approval: ApprovalRequest
    status: Literal[
        "PENDING_APPROVAL",
        "APPROVED",
        "REJECTED",
        "STARTED",
        "TEST_RESOURCE_CHANGED",
        "ROLLED_BACK",
        "UNKNOWN",
    ] = "PENDING_APPROVAL"
    receipt: RestrictedReceipt | None = None
    observed_digest: Hash | None = None
    recovery_observation: (
        Literal["UNCHANGED", "EXPECTED_AFTER", "CONFLICT", "UNAVAILABLE"] | None
    ) = None

    @model_validator(mode="after")
    def coherent(self):
        value = RestrictedInput.model_validate(self.action.input_payload())
        before = AVAILABLE if value.action_type == "TEST_RESOURCE_QUARANTINE" else QUARANTINED
        after = QUARANTINED if value.action_type == "TEST_RESOURCE_QUARANTINE" else AVAILABLE
        if (
            self.approval.expires_at is None
            or value.before_digest != hashlib.sha256(before).hexdigest()
        ):
            raise ValueError("RESTRICTED_EXPLICIT_STATE_AND_EXPIRY_REQUIRED")
        if self.action.incident_id != value.incident_id:
            raise ValueError("RESTRICTED_INCIDENT_BINDING_REJECTED")
        if self.status in ("TEST_RESOURCE_CHANGED", "ROLLED_BACK"):
            if self.receipt is None:
                raise ValueError("RESTRICTED_RECEIPT_REQUIRED")
            if (
                self.receipt.action_id != self.action.action_id
                or self.receipt.approval_id != self.approval.approval_id
                or self.receipt.input_digest
                != content_digest_payload(value.model_dump(mode="json"))
                or self.receipt.output.before_digest != value.before_digest
                or self.receipt.output.after_digest != hashlib.sha256(after).hexdigest()
                or self.approval.decision is None
                or self.approval.decision.decided_by != f"os-uid:{self.receipt.operator_uid}"
                or (self.status == "ROLLED_BACK") != (value.action_type == "TEST_RESOURCE_ROLLBACK")
            ):
                raise ValueError("RESTRICTED_RECEIPT_BINDING_REJECTED")
        elif self.receipt is not None:
            raise ValueError("RESTRICTED_UNCONFIRMED_RECEIPT_REJECTED")
        return self

    @property
    def digest(self) -> str:
        return content_digest_payload(self.model_dump(mode="json"))


def record_view(record: RestrictedRecord, now=None):
    state = record.status
    if (
        state in ("PENDING_APPROVAL", "APPROVED")
        and (now or utc_now()) >= record.approval.expires_at
    ):
        state = "EXPIRED"
    return {
        "record": record.model_dump(mode="json"),
        "record_digest": record.digest,
        "status": state,
    }
