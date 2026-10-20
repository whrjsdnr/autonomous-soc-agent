"""Explicit fixture setup; compiles only the unchanged program and Phase A inspector."""

import os
from uuid import uuid4

from soc_agent.security_ai.ebpf_broker.contracts import BrokerPlan
from soc_agent.security_ai.ebpf_broker.controller import Controller
from soc_agent.security_ai.ebpf_broker.identity import broker_sha, bundle
from soc_agent.security_ai.ebpf_native.authentication import FixtureAuthentication
from soc_agent.security_ai.ebpf_native.contracts import (
    ApplicationPlan,
    RunIdentity,
    Scope,
    local_controller,
)
from soc_agent.security_ai.ebpf_native.loader import bundle as phase_a_bundle
from soc_agent.security_ai.research.models import digest
from tests.ebpf_native_support import application


def plan() -> BrokerPlan:
    scope = Scope(
        hook="INGRESS",
        ifindex=1,
        net_namespace=os.readlink("/proc/self/ns/net"),
        program_sha256="a" * 64,
        loader_sha256="b" * 64,
        bundle_digest=digest(phase_a_bundle()),
    )
    app = ApplicationPlan(controller=local_controller(), scope=scope, mode="PHASE_A_FIXTURE")
    return BrokerPlan(
        application=app,
        uid=os.getuid(),
        gid=os.getgid(),
        broker_sha256=broker_sha(),
        bundle_digest=digest(bundle()),
    )


def run(plan: BrokerPlan, number=1) -> RunIdentity:
    return RunIdentity(
        application_session=plan.application.application_session,
        scope_digest=digest(plan.application.scope.model_dump(mode="json")),
        run_number=number,
        capture_session=uuid4(),
    )


def controller(directory, authenticate=True) -> Controller:
    value = Controller(application(directory))
    value.prepare()
    if authenticate:
        value.approve(value.plan.identity)
        value.authenticate(FixtureAuthentication())
    return value
