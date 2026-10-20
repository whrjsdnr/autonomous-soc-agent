"""Mock-only password contract. Never execute sudo, PAM, askpass or read a password."""

from typing import Literal

from pydantic import Field

from soc_agent.security_ai.ebpf_native.contracts import ApplicationPlan
from soc_agent.security_ai.research.models import Frozen


class FixtureAuthentication(Frozen):
    source: Literal["MOCK_OS_TERMINAL_NOT_NATIVE"] = "MOCK_OS_TERMINAL_NOT_NATIVE"
    tty: bool = Field(default=True, strict=True)
    password_challenge_completed: bool = Field(default=True, strict=True)
    cached_only: bool = Field(default=False, strict=True)
    nopasswd: bool = Field(default=False, strict=True)
    policy_password_guaranteed: bool = Field(default=True, strict=True)
    result: Literal["SUCCESS", "DENIED", "CANCELLED", "TIMEOUT"] = "SUCCESS"

    def verify(self, plan: ApplicationPlan) -> None:
        if plan.mode != "PHASE_A_FIXTURE":
            raise ValueError("EBPF_NATIVE_AUTHENTICATION_PENDING")
        if not self.tty:
            raise ValueError("EBPF_AUTH_TTY_REQUIRED")
        if self.nopasswd or not self.policy_password_guaranteed:
            raise ValueError("EBPF_AUTH_PASSWORD_POLICY_UNVERIFIED")
        if self.cached_only or not self.password_challenge_completed:
            raise ValueError("EBPF_AUTH_FRESH_APPLICATION_PASSWORD_REQUIRED")
        if self.result != "SUCCESS":
            raise ValueError("EBPF_AUTH_" + self.result)


def native_authenticate() -> None:
    # No bool flag, environment variable, stored approval or sudo cache can enable phase A.
    raise ValueError("EBPF_PHASE_A_NATIVE_AUTHENTICATION_DISABLED")
