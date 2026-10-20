"""Compile fixed loader and original BPF object; no sudo/PAM/TC/kernel load calls."""

import os
from pathlib import Path

from soc_agent.security_ai.ebpf.build import compile_program
from soc_agent.security_ai.ebpf_native.application import Application
from soc_agent.security_ai.ebpf_native.authentication import FixtureAuthentication
from soc_agent.security_ai.ebpf_native.contracts import ApplicationPlan, Scope, local_controller
from soc_agent.security_ai.ebpf_native.loader import bundle, compile_loader
from soc_agent.security_ai.research.models import digest


def application(tmp_path: Path, **scope_change) -> Application:
    directory = tmp_path / "build"
    binaries = compile_program(directory)
    loader_sha = compile_loader(directory)
    scope = Scope(
        ifindex=int(Path("/sys/class/net/lo/ifindex").read_text()),
        net_namespace=os.readlink("/proc/self/ns/net"),
        hook="INGRESS",
        program_sha256=binaries["tc.bpf.o"],
        loader_sha256=loader_sha,
        bundle_digest=digest(bundle()),
    )
    if scope_change:
        scope = scope.model_copy(update=scope_change)
    plan = ApplicationPlan(controller=local_controller(), scope=scope, mode="PHASE_A_FIXTURE")
    return Application(
        tmp_path / "session", plan, directory / "tc.bpf.o", directory / "phase-a-loader"
    )


def authenticated(tmp_path: Path) -> Application:
    c = application(tmp_path)
    c.prepare()
    c.approve(c.plan.identity)
    c.authenticate(FixtureAuthentication(), now=0)
    return c
