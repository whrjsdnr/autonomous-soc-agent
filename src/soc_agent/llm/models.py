"""Provider-neutral request data; response schemas are supplied by callers."""

from pydantic import BaseModel, ConfigDict, field_validator


class LLMRequest(BaseModel):
    """Single-turn instructions and input, preserving prompt whitespace verbatim."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    system_prompt: str
    user_prompt: str

    @field_validator("system_prompt", "user_prompt")
    @classmethod
    def reject_blank_prompt(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Prompt must not be blank")
        return value
