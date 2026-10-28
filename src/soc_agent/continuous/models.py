"""Separate service configuration; diagnostic receipts are never service authority."""

from enum import StrEnum
from pathlib import Path
from typing import Literal

from pydantic import Field, model_validator

from soc_agent.security_ai.research.models import Frozen
from soc_agent.security_ai.workflow_models import PackageInput


class RuntimeMode(StrEnum):
    DIAGNOSTIC = "DIAGNOSTIC"
    CONTINUOUS = "CONTINUOUS"
    OFFLINE = "OFFLINE"


class ContinuousConfig(Frozen):
    contract: Literal["soc-continuous-runtime:v1"] = "soc-continuous-runtime:v1"
    mode: Literal["CONTINUOUS"] = "CONTINUOUS"
    source: Literal["PCAP_REPLAY", "JSONL_REPLAY", "NATIVE_SERVICE"]
    input_file: Path
    input_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    ml_root: Path | None = None
    authentication_runtime: Path | None = None
    journal_replay_file: Path | None = None
    journal_replay_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    authentication_packages: tuple[PackageInput, ...] = Field(default=(), max_length=1)
    metadata_window_seconds: int = Field(default=60, ge=30, le=3600, strict=True)
    namespace: str = Field(default="net:[4026532232]", pattern=r"^net:\[[0-9]+\]$")
    interface: Literal["lo"] = "lo"
    queue_capacity: int = Field(default=8, ge=1, le=256, strict=True)
    max_active_flows: int = Field(default=128, ge=1, le=128, strict=True)
    max_windows: int = Field(default=512, ge=1, le=10000, strict=True)
    max_storage_bytes: int = Field(default=256 * 1024**2, ge=4 * 1024**2, le=1024**3, strict=True)
    max_seen_events: int = Field(default=100000, ge=128, le=1000000, strict=True)
    collector_restarts: int = Field(default=1, ge=0, le=3, strict=True)
    worker_circuit_failures: int = Field(default=2, ge=1, le=5, strict=True)
    heartbeat_seconds: float = Field(default=1, ge=0.1, le=10, allow_inf_nan=False)
    shutdown_seconds: float = Field(default=10, ge=1, le=30, allow_inf_nan=False)
    replay_delay_seconds: float = Field(default=0, ge=0, le=1, allow_inf_nan=False)
    profiles: tuple[Literal["quality", "edge"], ...] = ("quality", "edge")

    @model_validator(mode="after")
    def explicit_paths(self):
        if not self.input_file.is_absolute() or self.ml_root and not self.ml_root.is_absolute():
            raise ValueError("CONTINUOUS_ABSOLUTE_PATHS_REQUIRED")
        if self.authentication_runtime and not self.authentication_runtime.is_absolute():
            raise ValueError("CONTINUOUS_ABSOLUTE_AUTH_RUNTIME_REQUIRED")
        if bool(self.journal_replay_file) != bool(self.journal_replay_sha256):
            raise ValueError("CONTINUOUS_JOURNAL_FILE_AND_PIN_REQUIRED")
        if self.journal_replay_file and (
            not self.journal_replay_file.is_absolute() or not self.authentication_packages
        ):
            raise ValueError("CONTINUOUS_JOURNAL_PATH_AND_MODEL_REQUIRED")
        if not self.profiles or len(set(self.profiles)) != len(self.profiles):
            raise ValueError("CONTINUOUS_PROFILE_SET")
        return self


def require_source_authority(config: ContinuousConfig) -> None:
    if config.source == "NATIVE_SERVICE":
        import hashlib
        import os

        from soc_agent.continuous.native.policy import POLICY, installed, root_file

        try:
            policy = installed()
        except (ValueError, OSError) as error:
            raise ValueError(
                "CONTINUOUS_NATIVE_SERVICE_INSTALLATION_AND_POLICY_NOT_ACTIVATED"
            ) from error
        if (
            policy["uid"] != os.getuid()
            or policy["namespace"] != config.namespace
            or hashlib.sha256(root_file(POLICY)).hexdigest() != config.input_sha256
        ):
            raise ValueError("CONTINUOUS_NATIVE_SERVICE_POLICY_SCOPE")
