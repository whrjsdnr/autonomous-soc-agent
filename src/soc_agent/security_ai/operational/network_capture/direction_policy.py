"""Separate units; fixed fixture-calibrated candidate, never an adaptive privilege policy."""

import math
from typing import Literal

from pydantic import model_validator

from soc_agent.security_ai.operational.network_capture.stream_session import StreamPolicy


class DirectionPolicy(StreamPolicy):
    contract: Literal["soc-total-direction-aware-policy:v3"] = "soc-total-direction-aware-policy:v3"
    policy_name: Literal["direction-v3"] = "direction-v3"
    seconds: Literal[300] = 300
    frames_per_second: Literal[512] = 512
    burst_frames: Literal[1024] = 1024
    analysis_per_second: Literal[256] = 256
    analysis_burst: Literal[512] = 512
    qualification: Literal["FIXTURE_CANDIDATE_NATIVE_APPROVAL_REQUIRED"] = (
        "FIXTURE_CANDIDATE_NATIVE_APPROVAL_REQUIRED"
    )

    @model_validator(mode="after")
    def fixed_resources(self):
        defaults = StreamPolicy()
        for name in type(defaults).model_fields:
            if name not in {"contract", "frames_per_second", "burst_frames", "qualification"}:
                if getattr(self, name) != getattr(defaults, name):
                    raise ValueError("V3_FIXED_RESOURCE_POLICY_REQUIRED")
        return self

    @property
    def analysis_budget(self):
        return self.seconds * self.analysis_per_second + self.analysis_burst


class Budget:
    """Single-owner monotonic bucket; diagnostic is the last attempted consumption."""

    def __init__(self, name: Literal["OBSERVATION", "ANALYSIS"], rate: int, burst: int, now: float):
        self.name, self.rate, self.burst = name, rate, burst
        self.tokens, self.last, self.consumed = float(burst), now, 0
        self.diagnostic = None

    def consume(self, now: float, sequence: int):
        if not math.isfinite(now) or now < self.last:
            raise ValueError("STREAM_MONOTONIC_CLOCK_REVERSED")
        delta = now - self.last
        self.tokens = min(self.burst, self.tokens + delta * self.rate)
        self.last = now
        self.diagnostic = dict(
            budget_type=self.name,
            token_balance=self.tokens,
            monotonic_seconds=now,
            since_last_consume_seconds=delta,
            frame_sequence=sequence,
            consumed=self.consumed,
            integrity_scope="CAPTURE_WIDE",
        )
        if self.tokens < 1:
            raise ValueError("V3_" + self.name + "_BUDGET_EXCEEDED")
        self.tokens -= 1
        self.consumed += 1


class Accounting:
    """Direction selection is not duplicate detection. Every raw receive is counted."""

    def __init__(self, policy: DirectionPolicy, now: float):
        self.policy = policy
        self.observation = Budget("OBSERVATION", policy.frames_per_second, policy.burst_frames, now)
        self.analysis = Budget("ANALYSIS", policy.analysis_per_second, policy.analysis_burst, now)
        self.raw = self.outbound = self.inbound = self.unknown = self.filtered = self.normalized = 0
        self.failure = None

    def admit(self, direction: str, now: float) -> bool:
        self.raw += 1
        if direction == "OUTBOUND":
            self.outbound += 1
        elif direction == "INBOUND":
            self.inbound += 1
        else:
            self.unknown += 1
        try:
            self.observation.consume(now, self.raw)
            if direction == "UNKNOWN" or direction not in {"OUTBOUND", "INBOUND"}:
                raise ValueError("V3_DIRECTION_UNKNOWN")
            if direction == "INBOUND":
                self.filtered += 1
                return False
            self.analysis.consume(now, self.raw)
            return True
        except ValueError as error:
            bucket = (
                self.analysis if str(error) == "V3_ANALYSIS_BUDGET_EXCEEDED" else self.observation
            )
            self.failure = (
                dict(bucket.diagnostic, abort_reason=str(error))
                if bucket.diagnostic and str(error) != "STREAM_MONOTONIC_CLOCK_REVERSED"
                else None
            )
            raise

    def snapshot(self):
        return dict(
            accounting_contract="soc-direction-accounting:v3",
            received_frames=self.raw,
            accepted_raw_frames=self.observation.consumed,
            outbound_frames=self.outbound,
            inbound_frames=self.inbound,
            unknown_direction_frames=self.unknown,
            direction_filtered_frames=self.filtered,
            analysis_accepted=self.analysis.consumed,
            normalized_packets=self.normalized,
            observation_tokens=self.observation.tokens,
            analysis_tokens=self.analysis.tokens,
            budget_failure=self.failure,
        )
