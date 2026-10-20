"""TCX fixture protocol only; kernel support, pin absence and Native admission unknown."""

from typing import Literal

from pydantic import Field

from soc_agent.review.models import Hash
from soc_agent.security_ai.research.models import Frozen

PHASES = (
    "NOT_ATTACHED",
    "ATTACH_PENDING",
    "LINK_ACTIVE",
    "DETACH_PENDING",
    "DETACHED",
    "ORPHANED",
    "CLEANUP_UNVERIFIED",
)


class FixtureOwner(Frozen):
    origin: Literal["C_FAKE_NOT_KERNEL"]
    link_id: int = Field(ge=0, le=0xFFFFFFFF)
    program_id: int = Field(gt=0, le=0xFFFFFFFF)
    attach_type: int = Field(gt=0, le=0xFFFFFFFF)
    ifindex: int = Field(gt=0, le=0xFFFFFFFF)
    namespace_inode: int = Field(gt=0, le=0xFFFFFFFFFFFFFFFF)
    generation: int = Field(gt=0, le=0xFFFFFFFFFFFFFFFF)
    broker_pid: int = Field(gt=0, le=0xFFFFFFFF)
    broker_ticks: int = Field(gt=0, le=0xFFFFFFFFFFFFFFFF)
    pinned: Literal[0, 1]
    program_sha: Hash
    program_tag: str = Field(pattern=r"^[a-f0-9]{16}$")
    application: str = Field(pattern=r"^[a-f0-9]{32}$")


class LinkFixtureResult(Frozen):
    source: Literal["TCX_FAKE_RESOURCE_TABLE_NOT_KERNEL"]
    native: Literal[False]
    replay: int = Field(lt=0)
    link_id: int = Field(ge=0, le=0xFFFFFFFF)
    attach: int
    detach: int
    phase: int = Field(ge=0, lt=len(PHASES))
    active: Literal[0, 1]
    references: int = Field(ge=0, le=2)
    foreign: Literal[1, 2]
    deletes: int = Field(ge=0, le=1)
    closed: int = Field(ge=0, le=1)
    trace: str = Field(max_length=1024)
    owner: FixtureOwner

    def snapshot(self) -> dict[str, object]:
        return {
            "attach_mode": "TCX_FIXTURE",
            "link_state": PHASES[self.phase],
            "link_id": self.link_id or None,
            "ownership": "FIXTURE_ONLY",
            "broker_pin_policy": "FORBIDDEN",
            "external_pins": "UNKNOWN",
            "input_origin": self.source,
            "native_release": "BLOCKED",
            "cleanup": "FIXTURE_DETACHED" if self.phase == 4 else "UNVERIFIED",
        }


def unobserved() -> dict[str, object]:
    return {
        "attach_mode": "LEGACY_TC_BLOCKED",
        "link_id": None,
        "link_state": "NOT_ATTACHED",
        "ownership": "NOT_OBSERVED",
        "broker_pin_policy": "FORBIDDEN",
        "external_pins": "UNKNOWN",
        "kernel_support": "UNKNOWN_NOT_PROBED",
        "program_semantics": "BLOCKED_TCX_PASS_SKIPS_CHAIN",
        "native_release": "BLOCKED",
    }
