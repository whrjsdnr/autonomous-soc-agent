"""Phase A compiler, inspector and explicitly labelled application-session fixture."""

import argparse
import json
import os
from pathlib import Path

from soc_agent.security_ai.ebpf_native.application import Application
from soc_agent.security_ai.ebpf_native.authentication import FixtureAuthentication
from soc_agent.security_ai.ebpf_native.contracts import ApplicationPlan, Scope, local_controller
from soc_agent.security_ai.ebpf_native.loader import bundle, compile_loader, file_sha
from soc_agent.security_ai.research.models import digest


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    build = sub.add_parser("compile")
    build.add_argument("--output", type=Path, required=True)
    for command in ("prepare", "fixture"):
        p = sub.add_parser(command)
        p.add_argument("--program", type=Path, required=True)
        p.add_argument("--loader", type=Path, required=True)
        p.add_argument("--data-directory", type=Path, required=True)
        p.add_argument("--hook", choices=("INGRESS", "EGRESS"), default="INGRESS")
        p.add_argument("--gui", action="store_true")
    args = parser.parse_args(argv)
    if os.geteuid() == 0:
        raise ValueError("EBPF_NON_ROOT_CONTROLLER_REQUIRED")
    if args.command == "compile":
        print(json.dumps(dict(loader_sha256=compile_loader(args.output)), indent=2))
        return 0
    scope = Scope(
        ifindex=int(Path("/sys/class/net/lo/ifindex").read_text()),
        net_namespace=os.readlink("/proc/self/ns/net"),
        hook=args.hook,
        program_sha256=file_sha(args.program),
        loader_sha256=file_sha(args.loader),
        bundle_digest=digest(bundle()),
    )
    plan = ApplicationPlan(
        controller=local_controller(),
        scope=scope,
        mode="PHASE_A_FIXTURE" if args.command == "fixture" else "PHASE_A_NATIVE_BLOCKED",
    )
    application = Application(
        args.data_directory / ("application-" + plan.application_session.hex),
        plan,
        args.program,
        args.loader,
    )
    try:
        application.prepare()
        print("PHASE A / NATIVE AUTHENTICATION + KERNEL LOAD + TC ATTACH DISABLED")
        print(json.dumps(plan.model_dump(mode="json"), indent=2))
        print("Application approval digest: " + plan.identity)
        if args.command == "fixture":
            print("MOCK PASSWORD AUTHENTICATION ONLY; NO OS PASSWORD IS READ")
            # Explicit scope acceptance is not a password and cannot authorize Native activity.
            if input("Type application digest to approve this fixture: ").strip() != plan.identity:
                return 1
            application.approve(plan.identity)
            application.authenticate(FixtureAuthentication())
        if args.gui:
            from soc_agent.security_ai.ebpf_native.gui import launch

            return launch(application)
        print(json.dumps(application.snapshot(), indent=2))
        return 0
    finally:
        application.close()


if __name__ == "__main__":
    raise SystemExit(main())
