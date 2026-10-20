"""Closed broker command language; no command can carry a shell or object path."""

from typing import Literal, Self
from uuid import UUID

from pydantic import Field, model_validator

from soc_agent.review.models import Hash
from soc_agent.security_ai.ebpf_native.contracts import ApplicationPlan, RunIdentity
from soc_agent.security_ai.research.models import Frozen, digest


class BrokerPlan(Frozen):
    application: ApplicationPlan
    uid: int = Field(gt=0, strict=True)
    gid: int = Field(ge=0, strict=True)
    broker_sha256: Hash
    bundle_digest: Hash
    mode: Literal["PHASE_B1_FIXTURE"] = "PHASE_B1_FIXTURE"
    heartbeat_seconds: Literal[15] = 15
    max_commands: Literal[2048] = 2048
    broker_rss_mib: Literal[256] = 256
    broker_address_mib: Literal[512] = 512
    broker_cpu_seconds: Literal[20] = 20
    journal_bytes: Literal[1048576] = 1048576

    @property
    def identity(self) -> str:
        return digest(self.model_dump(mode="json"))

    @model_validator(mode="after")
    def same_user(self) -> Self:
        if self.application.controller.uid != self.uid:
            raise ValueError("BROKER_PLAN_UID_MISMATCH")
        if self.application.mode != "PHASE_A_FIXTURE":
            raise ValueError("BROKER_NATIVE_AUTHENTICATION_PENDING")
        return self


class Ownership(Frozen):
    owner_session: UUID
    capture_session: UUID
    generation: UUID
    namespace: str = Field(pattern=r"^net:\[[0-9]+\]$")
    ifindex: int = Field(gt=0, strict=True)
    hook: Literal["INGRESS", "EGRESS"]
    qdisc_type: Literal["clsact"] = "clsact"
    chain: Literal[0] = 0
    priority: Literal[49152] = 49152
    handle: int = Field(gt=0, lt=2**32, strict=True)
    program_id: int = Field(gt=0, strict=True)
    program_tag: str = Field(pattern=r"^[0-9a-f]{16}$")
    program_sha256: Hash
    source: Literal["TC_REGISTRY_FIXTURE_NOT_KERNEL"] = "TC_REGISTRY_FIXTURE_NOT_KERNEL"


class Command(Frozen):
    command: Literal["PREPARE", "ATTACH", "STATUS", "DETACH", "STOP", "CLEANUP"]
    plan_digest: Hash
    sequence: int = Field(gt=0, le=2048, strict=True)
    run: RunIdentity | None = None
    ownership: Ownership | None = None
    reason: (
        Literal[
            "USER_STOP",
            "GUI_CLOSE",
            "CONTROLLER_EXIT",
            "APPLICATION_EXIT",
            "TIMEOUT",
            "SIGINT",
            "SIGTERM",
        ]
        | None
    ) = None

    @model_validator(mode="after")
    def fixed_arguments(self) -> Self:
        expected = {
            "PREPARE": (False, False, False),
            "ATTACH": (True, False, False),
            "STATUS": (False, False, False),
            "DETACH": (False, True, False),
            "STOP": (False, False, True),
            "CLEANUP": (False, False, False),
        }[self.command]
        if (self.run is not None, self.ownership is not None, self.reason is not None) != expected:
            raise ValueError("BROKER_ARGUMENT_SCHEMA_DENIED")
        return self
