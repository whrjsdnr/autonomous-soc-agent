"""Qualification observations only; existing Application/Controller own all authority."""

from typing import Literal

from pydantic import Field

from soc_agent.security_ai.ebpf_broker.controller import Controller
from soc_agent.security_ai.research.models import Frozen


class PamFixture(Frozen):
    source: Literal["MOCK_PAM_NOT_NATIVE"] = "MOCK_PAM_NOT_NATIVE"
    service: Literal["soc-agent-ebpf"] = "soc-agent-ebpf"
    uid: int = Field(gt=0)
    tty_uid: int = Field(gt=0)
    tty_foreground: bool = Field(default=True, strict=True)
    challenges: int = Field(default=1, ge=0, le=4)
    authentication: Literal["SUCCESS", "DENIED", "CANCELLED", "TIMEOUT"] = "SUCCESS"
    account: Literal["SUCCESS", "DENIED", "EXPIRED"] = "SUCCESS"
    cached_only: bool = Field(default=False, strict=True)
    password_policy_guaranteed: bool = Field(default=True, strict=True)

    def verdict(self) -> dict[str, str]:
        accepted = (
            self.uid == self.tty_uid
            and self.tty_foreground
            and self.challenges == 1
            and self.authentication == self.account == "SUCCESS"
            and not self.cached_only
            and self.password_policy_guaranteed
        )
        return {
            "contract": "FIXTURE_VERIFIED" if accepted else "BLOCKED",
            "source": self.source,
            "native_authentication": "PENDING",
            "authority_created": "NONE",
        }


def session_snapshot(controller: Controller) -> dict[str, object]:
    """Observe existing expiry/process checks, never create or restore a second grant."""
    value = controller.observe()
    app = controller.application
    return {
        "application_session": str(app.plan.application_session),
        "scope_digest": app.plan.identity,
        "broker_identity": controller.broker.identity.model_dump() if controller.broker else None,
        "authentication": app.authentication,
        "authority_in_memory": app._authenticated,
        "source": "EXISTING_FIXTURE_CONTROLLER_NOT_NATIVE",
        "state": value["state"],
        "native_release": "BLOCKED",
        "native_authentication": "PENDING",
        "restorable_authorization": False,
    }
