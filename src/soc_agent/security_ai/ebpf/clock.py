"""Explicit clock evidence. Metadata arithmetic never converts monotonic time to UTC."""

from typing import Literal
from uuid import UUID

from pydantic import Field, model_validator

from soc_agent.security_ai.research.models import Frozen


class ClockSample(Frozen):
    before_ns: int = Field(ge=0, strict=True)
    wall_ns: int = Field(ge=0, strict=True)
    after_ns: int = Field(ge=0, strict=True)

    @model_validator(mode="after")
    def bracket(self):
        if not 0 <= self.after_ns - self.before_ns <= 1_000_000:
            raise ValueError("TCX_CLOCK_CALIBRATION_BRACKET")
        return self


class ClockContract(Frozen):
    session_id: UUID
    domain: Literal["KERNEL_MONOTONIC_NS", "FIXTURE_PCAP_EVENT_NS"]
    evidence: Literal["DECLARED_ONLY", "FIXTURE_CALIBRATION"] = "DECLARED_ONLY"
    samples: tuple[ClockSample, ...] = Field(default=(), max_length=8)

    @model_validator(mode="after")
    def calibration(self):
        if self.evidence == "FIXTURE_CALIBRATION":
            if len(self.samples) < 3 or any(
                b.before_ns < a.after_ns
                for a, b in zip(self.samples, self.samples[1:], strict=False)
            ):
                raise ValueError("TCX_CLOCK_CALIBRATION_SEQUENCE")
            if self.offset_interval[0] > self.offset_interval[1]:
                raise ValueError("TCX_CLOCK_CALIBRATION_DRIFT")
        elif self.samples:
            raise ValueError("TCX_CLOCK_CALIBRATION_SOURCE")
        return self

    @property
    def offset_interval(self) -> tuple[int, int]:
        if not self.samples:
            raise ValueError("TCX_CLOCK_CALIBRATION_MISSING")
        return (
            max(s.wall_ns - s.after_ns for s in self.samples),
            min(s.wall_ns - s.before_ns for s in self.samples),
        )

    def snapshot(self) -> dict:
        return dict(
            domain=self.domain,
            unit="NANOSECONDS_INTEGER_NO_ROUNDING",
            utc_conversion="NOT_PERFORMED",
            calibration=self.evidence,
            offset_interval_ns=self.offset_interval if self.samples else None,
            native_accuracy="UNVERIFIED",
            native_eligibility="BLOCKED",
        )
