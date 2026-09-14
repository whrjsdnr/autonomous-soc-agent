"""Immutable proposed action with a canonical JSON object as input."""

import json
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, JsonValue, TypeAdapter, field_validator

from soc_agent.approval.models import UTCTimestamp, utc_now
from soc_agent.tools.models import ToolName


class ActionProposal(BaseModel):
    """Accept an input mapping or JSON object text; store only immutable JSON text.

    input_payload() returns a fresh object on each call. Sorted object keys remove
    key-order differences; array order and JSON value types remain significant.
    No tool-specific coercion or default insertion occurs at proposal time.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    action_id: UUID = Field(default_factory=uuid4)
    incident_id: UUID
    tool_name: ToolName
    tool_input: str
    created_at: UTCTimestamp = Field(default_factory=utc_now)

    @field_validator("tool_input", mode="before")
    @classmethod
    def canonical_input(cls, value: object) -> str:
        adapter = TypeAdapter(dict[str, JsonValue])
        payload = (
            adapter.validate_json(value, strict=True)
            if isinstance(value, str)
            else adapter.validate_python(value, strict=True)
        )
        return json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
        )

    def input_payload(self) -> dict[str, JsonValue]:
        return TypeAdapter(dict[str, JsonValue]).validate_json(self.tool_input, strict=True)
