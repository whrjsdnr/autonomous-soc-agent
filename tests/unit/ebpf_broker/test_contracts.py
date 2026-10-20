"""Fixed commands, approval scope, Native denial and once-per-app authentication."""

import pytest
from pydantic import ValidationError
from tests.ebpf_broker_support import plan

from soc_agent.security_ai.ebpf_broker.contracts import BrokerPlan, Command
from soc_agent.security_ai.ebpf_native.authentication import FixtureAuthentication


@pytest.mark.parametrize("command", ["shell", "LOAD", "REPLACE", "QDISC_DELETE", "sudo"])
def test_no_arbitrary_command_or_path(command):
    with pytest.raises(ValidationError):
        Command(command=command, plan_digest="a" * 64, sequence=1)
    with pytest.raises(ValidationError):
        Command(command="ATTACH", plan_digest="a" * 64, sequence=1, path="/tmp/arbitrary.o")


@pytest.mark.parametrize("command", ["PREPARE", "STATUS", "CLEANUP", "ATTACH", "DETACH", "STOP"])
def test_argument_schema_not_generic_dictionary(command):
    with pytest.raises(ValidationError):
        Command(command=command, plan_digest="a" * 64, sequence=1, reason="rm -rf /")


def test_root_or_native_plan_and_unknown_fields_cannot_be_admitted():
    p = plan().model_dump(mode="json")
    p["application"]["mode"] = "PHASE_A_NATIVE_BLOCKED"
    with pytest.raises(ValidationError, match="NATIVE_AUTHENTICATION_PENDING"):
        BrokerPlan.model_validate(p)
    p = plan().model_dump(mode="json")
    p["uid"] = 0
    with pytest.raises(ValidationError):
        BrokerPlan.model_validate(p)
    p = plan().model_dump(mode="json")
    p["native_authentication"] = True
    with pytest.raises(ValidationError):
        BrokerPlan.model_validate(p)


@pytest.mark.parametrize(
    "change",
    [
        {"tty": False},
        {"cached_only": True},
        {"nopasswd": True},
        {"policy_password_guaranteed": False},
        {"password_challenge_completed": False},
        {"result": "CANCELLED"},
        {"result": "TIMEOUT"},
        {"result": "DENIED"},
    ],
)
def test_authentication_contract_rejects_cache_policy_cancel_and_timeout(change):
    p = plan()
    with pytest.raises(ValueError):
        FixtureAuthentication.model_validate(change).verify(p.application)
