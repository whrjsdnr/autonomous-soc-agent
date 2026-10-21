"""Explicit clock evidence. Metadata arithmetic never converts monotonic time to UTC."""

from dataclasses import dataclass
from typing import Literal
from uuid import UUID

from pydantic import Field, model_validator

from soc_agent.security_ai.ebpf.models import Event
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


class EventOrdering:
    """Bounded event-time policy, independent of UTC/calibration or eligibility."""

    lateness_ns = 10_000_000

    def __init__(self):
        self.maximum: int | None = None
        self.emitted: int | None = None
        self.inversions = self.max_delta = self.late = self.reordered = 0
        self.cpu_counts: dict[int, int] = {}
        self.examples: list[dict[str, int]] = []

    def observe(self, event: Event) -> None:
        self.cpu_counts[event.cpu] = self.cpu_counts.get(event.cpu, 0) + 1
        previous = self.maximum
        if previous is not None and event.ns < previous:
            delta = previous - event.ns
            self.inversions += 1
            self.max_delta = max(self.max_delta, delta)
            if len(self.examples) < 8:
                self.examples.append(
                    dict(
                        sequence=event.sequence,
                        cpu=event.cpu,
                        cpu_sequence=event.cpu_sequence,
                        timestamp_ns=event.ns,
                        previous_max_ns=previous,
                        inversion_ns=delta,
                    )
                )
            if delta > self.lateness_ns or self.emitted is not None and event.ns < self.emitted:
                self.late += 1
                raise ValueError("EBPF_REORDER_LATE_CAPTURE_GAP")
        self.maximum = event.ns if previous is None else max(previous, event.ns)

    def snapshot(self) -> dict:
        return dict(
            policy="BOUNDED_EVENT_TIME_10MS_32_EVENTS",
            lateness_ns=self.lateness_ns,
            inversions=self.inversions,
            max_inversion_delta_ns=self.max_delta,
            late_events=self.late,
            reordered_events=self.reordered,
            cpu_distribution={str(cpu): count for cpu, count in self.cpu_counts.items()},
            examples=list(self.examples),
            emitted_event_ns=self.emitted,
            timestamp_modified=False,
            calibration="NOT_ESTABLISHED_BY_REORDERING",
        )


@dataclass(frozen=True, slots=True)
class OrderedEvent:
    """Flow ordinal is separate from the immutable transport/delivery sequence."""

    event: Event
    sequence: int

    @property
    def ns(self) -> int:
        return self.event.ns

    @property
    def key(self) -> tuple:
        return self.event.key

    @property
    def source(self):
        return self.event.source

    @property
    def source_port(self) -> int:
        return self.event.source_port

    @property
    def ip_length(self) -> int:
        return self.event.ip_length

    @property
    def tcp_flags(self) -> int:
        return self.event.tcp_flags

    def model_dump(self, *, mode: str) -> dict:
        return self.event.model_dump(mode=mode) | {"flow_ordinal": self.sequence}
