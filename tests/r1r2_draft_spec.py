"""UNAPPROVED specification simulator: no production imports, I/O or authority.

Its events intentionally cannot satisfy StabilizationCampaign's real review gate.
A successful simulation is never a valid review, execution receipt or policy update.
"""

import hashlib
import json
from dataclasses import dataclass
from typing import Annotated, Literal, get_args, get_origin

from pydantic import BaseModel, ConfigDict, Field, model_validator

Hash = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class FrozenSpec(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    @model_validator(mode="before")
    @classmethod
    def literal_types(cls, data: object) -> object:
        # Literal[1] otherwise accepts True via Python equality, even in strict mode.
        if isinstance(data, dict):
            for name, field in cls.model_fields.items():
                if name in data and get_origin(field.annotation) is Literal:
                    expected = {type(v) for v in get_args(field.annotation)}
                    if type(data[name]) not in expected:
                        raise ValueError("SPEC_LITERAL_TYPE")
        return data


class Artifact(FrozenSpec):
    release: str
    manifest: Hash
    bundle: Hash
    image: Hash
    root_manifest: Hash


class Binding(FrozenSpec):
    campaign: Literal["SOC_NATIVE_STABILIZATION"] = "SOC_NATIVE_STABILIZATION"
    batch: Literal["BATCH2"] = "BATCH2"
    attempt: str
    prior_session: str
    prior_generation: int = Field(gt=0, lt=2**64)
    prior_artifact: Artifact
    next_session: str
    next_artifact: Artifact
    negative_review_sha: Hash
    evidence_manifest_sha: Hash
    scope_sha: Hash
    procedure_sha: Hash


class Evidence(FrozenSpec):
    fd_closed: bool
    maps_remaining: int = Field(ge=0)
    links_remaining: int = Field(ge=0)
    filters_remaining: int = Field(ge=0)
    container_absent: bool
    drain_verified: bool
    new_unknown_programs: int = Field(ge=0)
    foreign_attach_owner: Literal["ATTRIBUTED_EXTERNAL", "UNKNOWN"]
    external_removal_cause: Literal["UNKNOWN", "OBSERVED"]


class Receipt(FrozenSpec):
    contract: Literal["DRAFT_SPEC_NOT_A_PRODUCTION_RECEIPT_V1"] = (
        "DRAFT_SPEC_NOT_A_PRODUCTION_RECEIPT_V1"
    )
    receipt_id: str = Field(min_length=1, max_length=64)
    reviewer: str = Field(min_length=1, max_length=128)
    human_reference_sha: Hash
    binding: Binding
    ledger_tip_sha: Hash
    decision: Literal["ALLOW_NEXT_ADMISSION_ONLY", "DENY", "DEFER"]
    accept_unknown_external_removal_cause: bool = False
    max_next_attempts: Literal[1] = 1
    authorize_root_execution: Literal[False] = False
    override_global_guard: Literal[False] = False
    issued_at: int = Field(ge=0)
    expires_at: int = Field(gt=0)
    scope: Literal["SIMULATION_ONLY_NEXT_ADMISSION"] = "SIMULATION_ONLY_NEXT_ADMISSION"


class Context(FrozenSpec):
    procedure_approved_in_fixture: bool = False
    reviewer: str
    trusted_human_reference_sha: Hash
    trusted_receipt_sha: Hash = "0" * 64
    binding: Binding
    evidence: Evidence
    now: int


def sha(value: object) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True)
class Event:
    kind: Literal["SPEC_ONLY_REASSESSMENT"]
    receipt_id: str
    receipt_sha: str
    human_reference_sha: str
    decision: str
    previous: str


@dataclass(frozen=True)
class History:
    original_failed: Literal[True] = True
    original_safe: Literal[False] = False
    events: tuple[Event, ...] = ()

    @property
    def tip(self) -> str:
        return sha([e.__dict__ for e in self.events])


def simulate_review(receipt: Receipt | None, ctx: Context, history: History) -> History:
    """Return a new in-memory SPEC history. Never write a real Ledger or safe flag."""
    if receipt is None:
        raise ValueError("REVIEW_RECEIPT_MISSING")
    if not ctx.procedure_approved_in_fixture:
        raise ValueError("PROCEDURE_NOT_APPROVED")
    if (
        receipt.reviewer != ctx.reviewer
        or receipt.human_reference_sha != ctx.trusted_human_reference_sha
    ):
        raise ValueError("HUMAN_APPROVAL_UNVERIFIED")
    if receipt.binding.evidence_manifest_sha != sha(ctx.evidence.model_dump()):
        raise ValueError("EVIDENCE_MANIFEST_MISMATCH")
    if receipt.binding != ctx.binding:
        raise ValueError("REVIEW_BINDING_MISMATCH")
    if sha(receipt.model_dump()) != ctx.trusted_receipt_sha:
        raise ValueError("REVIEW_RECEIPT_SHA_MISMATCH")
    if not receipt.issued_at <= ctx.now < receipt.expires_at:
        raise ValueError("REVIEW_EXPIRED_OR_FUTURE")
    digest = sha(receipt.model_dump())
    if any(e.receipt_id == receipt.receipt_id or e.receipt_sha == digest for e in history.events):
        raise ValueError("REVIEW_REPLAY")
    if any(e.human_reference_sha == receipt.human_reference_sha for e in history.events):
        raise ValueError("REVIEW_APPROVAL_ALREADY_USED")
    if receipt.ledger_tip_sha != history.tip:
        raise ValueError("REVIEW_STALE_TIP")
    e = ctx.evidence
    if receipt.decision == "ALLOW_NEXT_ADMISSION_ONLY":
        if (
            not e.fd_closed
            or e.maps_remaining
            or e.links_remaining
            or e.filters_remaining
            or not e.container_absent
            or not e.drain_verified
            or e.new_unknown_programs
            or e.foreign_attach_owner == "UNKNOWN"
        ):
            raise ValueError("OWNED_CLEANUP_OR_OWNERSHIP_UNPROVEN")
        if e.external_removal_cause == "UNKNOWN" and not (
            receipt.accept_unknown_external_removal_cause
        ):
            raise ValueError("EXTERNAL_UNCERTAINTY_NOT_ACCEPTED")
    return History(
        events=history.events
        + (
            Event(
                "SPEC_ONLY_REASSESSMENT",
                receipt.receipt_id,
                digest,
                receipt.human_reference_sha,
                receipt.decision,
                history.tip,
            ),
        )
    )


def simulated_latest_decision(history: History) -> str:
    return history.events[-1].decision if history.events else "NO_REVIEW"


class ScenarioScope(FrozenSpec):
    namespace: Literal["net:[4026531833]"] = "net:[4026531833]"
    interface: Literal["lo"] = "lo"
    hook: Literal["INGRESS"] = "INGRESS"
    target: Literal["127.0.0.53:53"] = "127.0.0.53:53"
    qname: Literal["native-0516.localhost."] = "native-0516.localhost."
    qtype: Literal["A"] = "A"
    udp_total: Literal[2] = 2
    tcp_total: Literal[1] = 1
    events_max: Literal[4096] = 4096
    duration_max: Literal[300] = 300
    queue: Literal[32] = 32
    sidecar_deadline: Literal[10] = 10
    sidecar_udp: Literal[1] = 1
    sidecar_tcp: Literal[1] = 1
    witness_queries: Literal[1] = 1
    witness_retries: Literal[0] = 0
    witness_delay_ns: Literal[35000000000] = 35_000_000_000
    stop_delay_ns: Literal[45000000000] = 45_000_000_000
    capture_plan_ns: Literal[60000000000] = 60_000_000_000


@dataclass
class DraftSchedule:
    """Virtual tick model; action strings have no executor and cannot send packets."""

    scope: ScenarioScope
    fixture_scope_approved: bool = False
    witness_requested: bool = False
    stopped: bool = False
    previous_ns: int = -1

    def tick(
        self, now_ns: int, *, tcp_closed_ns: int | None, sidecar_closed: bool, received: int
    ) -> str:
        if not self.fixture_scope_approved:
            raise ValueError("R2_SCOPE_NOT_APPROVED")
        if now_ns < self.previous_ns or not 0 <= received <= self.scope.events_max:
            raise ValueError("R2_CLOCK_OR_COUNTER_INVALID")
        self.previous_ns = now_ns
        if self.stopped:
            return "SPEC_ONLY_ALREADY_STOPPED"
        if received == self.scope.events_max or now_ns >= self.scope.capture_plan_ns:
            self.stopped = True
            return "SPEC_ONLY_NORMAL_STOP_INCOMPLETE"
        if tcp_closed_ns is None:
            return "SPEC_ONLY_WAIT"
        if not 0 <= tcp_closed_ns <= now_ns:
            raise ValueError("R2_TCP_CLOSE_CLOCK_INVALID")
        if now_ns >= tcp_closed_ns + self.scope.stop_delay_ns:
            self.stopped = True
            return (
                "SPEC_ONLY_NORMAL_STOP"
                if self.witness_requested
                else "SPEC_ONLY_NORMAL_STOP_INCOMPLETE"
            )
        if now_ns >= tcp_closed_ns + self.scope.witness_delay_ns and not self.witness_requested:
            if not sidecar_closed:
                raise ValueError("R2_SIDECAR_NOT_CLOSED")
            self.witness_requested = True
            return "SPEC_ONLY_REQUEST_ONE_UDP_WITNESS"
        return "SPEC_ONLY_WAIT"
