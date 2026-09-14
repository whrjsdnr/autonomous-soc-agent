"""Deterministic policy outcomes, never LLM authorization."""

from enum import StrEnum
from typing import Annotated

from pydantic import BaseModel, ConfigDict, StringConstraints


class PolicyDecision(StrEnum):
    ALLOW = "allow"
    REQUIRE_APPROVAL = "require_approval"
    DENY = "deny"


class PolicyResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    decision: PolicyDecision
    reason: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]
