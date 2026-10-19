"""Fixture-calibrated alternatives, never an automatic replacement for legacy scope."""

import os
from pathlib import Path
from types import MappingProxyType
from typing import Literal

from pydantic import Field, model_validator

from soc_agent.security_ai.operational.network_capture.stream_session import StreamPolicy

PolicyName = Literal["conservative-v2", "balanced-v2", "performance-v2"]
CANDIDATES = MappingProxyType(
    {
        "conservative-v2": (128, 256),
        "balanced-v2": (256, 512),
        "performance-v2": (512, 512),
    }
)


class CalibratedPolicy(StreamPolicy):
    contract: Literal["soc-total-calibrated-policy:v2"] = "soc-total-calibrated-policy:v2"
    policy_name: PolicyName
    seconds: Literal[300] = 300
    frames_per_second: int = Field(strict=True, ge=128, le=512)
    burst_frames: int = Field(strict=True, ge=256, le=512)
    total_frames: int = Field(strict=True, ge=38656, le=154112)
    qualification: Literal["FIXTURE_CALIBRATED_NATIVE_CALIBRATION_PENDING"] = (
        "FIXTURE_CALIBRATED_NATIVE_CALIBRATION_PENDING"
    )

    @model_validator(mode="after")
    def reviewed_limits(self):
        expected = StreamPolicy().model_dump()
        actual = self.model_dump()
        changed = {"contract", "frames_per_second", "burst_frames", "qualification"}
        if (
            (self.frames_per_second, self.burst_frames) != CANDIDATES[self.policy_name]
            or self.total_frames != self.frames_per_second * self.seconds + self.burst_frames
            or any(actual[k] != v for k, v in expected.items() if k not in changed)
        ):
            raise ValueError("CALIBRATED_EXACT_POLICY_REQUIRED")
        return self

    @property
    def frame_budget(self):
        return self.total_frames


def policy(name: str) -> CalibratedPolicy:
    if name not in CANDIDATES:
        raise ValueError("CALIBRATED_POLICY_UNKNOWN")
    rate, burst = CANDIDATES[name]
    return CalibratedPolicy(
        policy_name=name,
        frames_per_second=rate,
        burst_frames=burst,
        total_frames=rate * 300 + burst,
    )


def hardware() -> dict:
    memory = dict(line.split(":", 1) for line in Path("/proc/meminfo").read_text().splitlines())
    return dict(
        logical_cpus=os.cpu_count(),
        affinity_cpus=len(os.sched_getaffinity(0)),
        total_memory_bytes=int(memory["MemTotal"].split()[0]) * 1024,
        available_memory_bytes=int(memory["MemAvailable"].split()[0]) * 1024,
        cgroup_limits="UNKNOWN_NOT_A_HOST_RESOURCE_GUARANTEE",
    )


def require_headroom():
    observed = hardware()
    if observed["affinity_cpus"] < 2 or observed["available_memory_bytes"] < 2 * 1024**3:
        raise ValueError("CALIBRATED_RESOURCE_HEADROOM_REQUIRED")
    return observed
