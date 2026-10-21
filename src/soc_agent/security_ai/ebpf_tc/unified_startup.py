"""Ordinary-user one-command TCX startup, one approval and one terminal password."""

import json
import os
from pathlib import Path
from uuid import uuid4

from soc_agent.security_ai.ebpf.build import compile_program
from soc_agent.security_ai.ebpf_broker.controller import Controller
from soc_agent.security_ai.ebpf_native.application import Application
from soc_agent.security_ai.ebpf_native.contracts import ApplicationPlan, Scope, local_controller
from soc_agent.security_ai.ebpf_native.loader import bundle as preparation_bundle
from soc_agent.security_ai.ebpf_native.loader import compile_loader, file_sha
from soc_agent.security_ai.ebpf_tc.bridge import Preparation
from soc_agent.security_ai.ebpf_tc.build import compile_native
from soc_agent.security_ai.ebpf_tc.installation import create_package
from soc_agent.security_ai.ebpf_tc.live_run import start_live_run
from soc_agent.security_ai.ebpf_tc.unified_image import installed_release, prepare_unified_image
from soc_agent.security_ai.native_terminal import confirm_scope
from soc_agent.security_ai.research.models import digest


def prepare_candidate(directory: Path) -> tuple[Path, Path, Path, str]:
    """Compile unprivileged fixed sources; never install or invoke a Kernel loader."""
    legacy, artifacts, package = (
        directory / "preparation",
        directory / "artifacts",
        directory / "release",
    )
    compile_program(legacy)
    compile_loader(legacy)
    compile_native(artifacts)
    release = create_package(artifacts, package, "0.5.1")
    return legacy, artifacts, package, release.identity


def start(directory: Path | None = None) -> int:
    controller = local_controller()  # Reject Root/capability-bearing GUI/runtime.
    installed = installed_release()
    print(
        "Installed release:",
        installed.version if installed else "NOT_INSTALLED",
        installed.identity if installed else "NONE",
    )
    base = directory or Path.home() / ".local/share/autonomous-soc-agent/gui/tcx-unified"
    base.mkdir(parents=True, exist_ok=True, mode=0o700)
    work = base / ("application-" + uuid4().hex)
    work.mkdir(mode=0o700)
    print("Checking versions and building exact release; no authentication or capture yet.")
    legacy, artifacts, package, manifest = prepare_candidate(work)
    image = prepare_unified_image(package, manifest, work / "unified-image.py")
    print(json.dumps(image.model_dump(mode="json"), indent=2))
    scope = Scope(
        hook="INGRESS",
        ifindex=int(Path("/sys/class/net/lo/ifindex").read_text()),
        net_namespace=os.readlink("/proc/self/ns/net"),
        program_sha256=file_sha(legacy / "tc.bpf.o"),
        loader_sha256=file_sha(legacy / "phase-a-loader"),
        bundle_digest=digest(preparation_bundle()),
    )
    plan = ApplicationPlan(controller=controller, scope=scope, mode="PHASE_A_FIXTURE")
    owner = Controller(
        Application(work / "session", plan, legacy / "tc.bpf.o", legacy / "phase-a-loader")
    )
    handoff = None
    try:
        preparation = Preparation(owner, artifacts)
        preparation.prepare()
        handoff = preparation.os_auth_handoff(package, manifest, unified_image=image)
        if not confirm_scope(handoff):
            return 1
        handoff.authenticate_native()  # The only sudo call; same Broker for STATUS/ATTACH.
        handoff.observe()
        if handoff.error or handoff.state != "BROKER_READY":
            raise ValueError("UNIFIED_BROKER_PREFLIGHT_REJECTED")
        start_live_run(preparation, gui=True)
    finally:
        try:
            if handoff is not None:
                handoff.close()
                (work / "unified-result.json").write_text(
                    json.dumps(handoff.snapshot(), indent=2) + "\n"
                )
        finally:
            owner.close()
    return 0 if not handoff.error and handoff.cleanup == "PROCESS_AND_AUDIT_VERIFIED" else 1
