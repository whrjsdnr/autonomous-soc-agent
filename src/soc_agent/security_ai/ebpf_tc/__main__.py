"""Compile/prepare or explicit fixture only. Native execution has no admitted CLI."""

import argparse
import json
import os
from pathlib import Path

from soc_agent.security_ai.ebpf_broker.controller import Controller
from soc_agent.security_ai.ebpf_native.application import Application
from soc_agent.security_ai.ebpf_native.authentication import FixtureAuthentication
from soc_agent.security_ai.ebpf_native.contracts import ApplicationPlan, Scope, local_controller
from soc_agent.security_ai.ebpf_native.loader import bundle as phase_a_bundle
from soc_agent.security_ai.ebpf_native.loader import file_sha
from soc_agent.security_ai.ebpf_tc.bridge import Preparation
from soc_agent.security_ai.ebpf_tc.build import compile_native
from soc_agent.security_ai.research.models import digest


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subs = parser.add_subparsers(dest="mode", required=True)
    build = subs.add_parser("compile")
    build.add_argument("--output", type=Path, required=True)
    qualify = subs.add_parser("qualify", help="Read-only release/installation plan; no install")
    qualify.add_argument("--program", type=Path, required=True)
    qualify.add_argument("--artifacts", type=Path, required=True)
    for name in (
        "prepare",
        "fixture",
        "handoff-prepare",
        "handoff-fixture",
        "auth-qualify",
        "live-qualify",
    ):
        p = subs.add_parser(name)
        for flag in ("program", "inspector", "artifacts", "data-directory"):
            p.add_argument("--" + flag, type=Path, required=True)
        p.add_argument("--gui", action="store_true")
        if name.startswith("handoff-") or name in {"auth-qualify", "live-qualify"}:
            p.add_argument("--package", type=Path, required=True)
            p.add_argument("--manifest-sha", required=True)
    package = subs.add_parser("package", help="Ordinary-UID release package only")
    package.add_argument("--artifacts", type=Path, required=True)
    package.add_argument("--output", type=Path, required=True)
    package.add_argument("--version", required=True)
    verify = subs.add_parser(
        "verify-package", help="Verify package against separately approved manifest SHA"
    )
    verify.add_argument("--package", type=Path, required=True)
    verify.add_argument("--manifest-sha", required=True)
    image = subs.add_parser(
        "install-plan", help="Generate a pinned first-install image; no root actions"
    )
    image.add_argument("--package", type=Path, required=True)
    image.add_argument("--manifest-sha", required=True)
    image.add_argument("--output", type=Path, required=True)
    subs.add_parser("qualify-host", help="Read-only config/files; never probe BPF syscall")
    args = parser.parse_args(argv)
    local_controller()
    if args.mode == "install-plan":
        from soc_agent.security_ai.ebpf_tc.install_image import prepare_installation

        print(
            json.dumps(prepare_installation(args.package, args.manifest_sha, args.output), indent=2)
        )
        return 0
    if args.mode == "package":
        from soc_agent.security_ai.ebpf_tc.installation import create_package

        result = create_package(args.artifacts, args.output, args.version)
        print(
            json.dumps(
                {
                    "manifest": result.model_dump(mode="json"),
                    "manifest_sha256": result.identity,
                    "source": "UNPRIVILEGED_PACKAGE_NOT_INSTALLATION",
                },
                indent=2,
            )
        )
        return 0
    if args.mode == "verify-package":
        from soc_agent.security_ai.ebpf_tc.installation import verify_package

        result = verify_package(args.package, args.manifest_sha)
        print(
            json.dumps(
                {
                    "manifest_sha256": result.identity,
                    "package": "VERIFIED_UNPRIVILEGED",
                    "native_release": "BLOCKED",
                }
            )
        )
        return 0
    if args.mode == "qualify-host":
        from soc_agent.security_ai.ebpf_tc.qualification import observe_kernel

        facts = observe_kernel()
        print(
            json.dumps(
                {
                    "facts": facts.model_dump(),
                    "verdict": facts.verdict(facts.namespace, facts.ifindex),
                },
                indent=2,
            )
        )
        return 0
    if args.mode == "compile":
        print(json.dumps(compile_native(args.output), indent=2))
        return 0
    if args.mode == "qualify":
        from soc_agent.security_ai.ebpf_tc.bridge import inspect_artifacts
        from soc_agent.security_ai.ebpf_tc.release import MODES, ReleaseEvidence, installation_plan

        hashes = inspect_artifacts(args.artifacts)
        plan = installation_plan(hashes, file_sha(args.program))
        print(
            json.dumps(
                {
                    "installation_plan": plan.model_dump(),
                    "required_root_install_modes": {k: oct(v) for k, v in MODES.items()},
                    "release": ReleaseEvidence().snapshot(),
                },
                indent=2,
            )
        )
        return 0
    scope = Scope(
        hook="INGRESS",
        ifindex=int(Path("/sys/class/net/lo/ifindex").read_text()),
        net_namespace=os.readlink("/proc/self/ns/net"),
        program_sha256=file_sha(args.program),
        loader_sha256=file_sha(args.inspector),
        bundle_digest=digest(phase_a_bundle()),
    )
    plan = ApplicationPlan(controller=local_controller(), scope=scope, mode="PHASE_A_FIXTURE")
    owner = Controller(
        Application(
            args.data_directory / ("application-" + plan.application_session.hex),
            plan,
            args.program,
            args.inspector,
        )
    )
    preparation = Preparation(owner, args.artifacts)
    try:
        preparation.prepare()
        print("RELEASE BLOCKED / QUALIFICATION REQUIRES EXPLICIT TERMINAL SCOPE APPROVAL")
        print(json.dumps(preparation.plan.model_dump(mode="json"), indent=2))
        print("Scope approval digest: " + preparation.plan.approval)
        if args.mode.startswith("handoff-") or args.mode in {"auth-qualify", "live-qualify"}:
            from soc_agent.security_ai.ebpf_tc.os_handoff import AuthenticationFixture

            handoff = preparation.os_auth_handoff(
                args.package,
                args.manifest_sha,
                qualification_only=args.mode == "auth-qualify",
                live_qualification=args.mode == "live-qualify",
            )
            print(json.dumps(handoff.approval_scope(), indent=2))
            print("OS handoff approval digest: " + handoff.approval)
            print("Qualification argv (not executed yet): " + json.dumps(handoff.sudo_command()))
            if args.mode in {"auth-qualify", "live-qualify"}:
                print(
                    "AUTH ONLY / NO KERNEL"
                    if args.mode == "auth-qualify"
                    else "LIVE INGRESS QUALIFICATION / 300s / 4096 events / NO AI / NO RETRY"
                )
                if (
                    input("Type the displayed purpose-bound approval digest: ").strip()
                    != handoff.approval
                ):
                    return 1
                handoff.approve(handoff.approval)
                handoff.authenticate_native()
                print(json.dumps(handoff.observe(), indent=2))
                if args.mode == "auth-qualify":
                    input("Press Enter to stop the authentication-only session: ")
                else:
                    from soc_agent.security_ai.ebpf_tc.live_run import start_live_run

                    start_live_run(preparation, gui=args.gui)
                    print(json.dumps(handoff.snapshot(), indent=2))
                    return 0
            if args.mode == "handoff-fixture":
                if (
                    input("Type digest to approve TRANSPORT FIXTURE ONLY: ").strip()
                    != handoff.approval
                ):
                    return 1
                handoff.approve(handoff.approval)
                handoff.authenticate_fixture(AuthenticationFixture())
        if args.mode == "fixture":
            if input("Type digest to approve MOCK ONLY: ").strip() != preparation.plan.approval:
                return 1
            preparation.approve(preparation.plan.approval)
            owner.authenticate(FixtureAuthentication())
            preparation.transaction_fixture()
        if args.gui:
            from soc_agent.security_ai.ebpf_tc.gui import launch

            return launch(preparation)
        print(json.dumps(preparation.snapshot(), indent=2))
        return 0
    finally:
        if preparation._os_handoff:
            preparation._os_handoff.close()
        owner.close()


if __name__ == "__main__":
    raise SystemExit(main())
