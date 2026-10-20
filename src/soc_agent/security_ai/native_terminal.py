"""Ordinary-user qualification entry with scope confirmation, never password handling.

The installed Broker, release, authentication implementation and Kernel gates are
unchanged. Human confirmation binds the exact in-memory scope and session digest.
"""

import argparse
import json
import os
from collections.abc import Callable
from pathlib import Path

from soc_agent.security_ai.ebpf_broker.controller import Controller
from soc_agent.security_ai.ebpf_native.application import Application
from soc_agent.security_ai.ebpf_native.contracts import ApplicationPlan, Scope, local_controller
from soc_agent.security_ai.ebpf_native.loader import bundle as preparation_bundle
from soc_agent.security_ai.ebpf_native.loader import file_sha
from soc_agent.security_ai.ebpf_tc.bridge import Preparation
from soc_agent.security_ai.ebpf_tc.os_handoff import Handoff
from soc_agent.security_ai.research.models import digest


def confirm_scope(
    handoff: Handoff,
    read: Callable[[str], str] = input,
    display: Callable[[str], None] = print,
) -> bool:
    """Confirm one displayed scope; never accept a changed session or saved approval."""
    before = json.dumps(handoff.approval_scope(), sort_keys=True, indent=2)
    approval = handoff.approval
    display(before)
    display("Digest is bound internally; do not copy or type it. Password goes to sudo only.")
    try:
        answer = read("Approve exactly this session and scope? Type yes [default: NO]: ")
    except (EOFError, KeyboardInterrupt):
        return False
    if answer.strip().lower() != "yes":
        return False
    if (
        handoff.approval != approval
        or json.dumps(handoff.approval_scope(), sort_keys=True, indent=2) != before
    ):
        raise ValueError("TERMINAL_APPROVAL_SCOPE_CHANGED")
    handoff.approve(approval)
    return True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("auth-qualify", "live-qualify"))
    for flag in ("program", "inspector", "artifacts", "data-directory", "package"):
        parser.add_argument("--" + flag, type=Path, required=True)
    parser.add_argument("--manifest-sha", required=True)
    parser.add_argument("--gui", action="store_true")
    args = parser.parse_args(argv)
    controller = local_controller()  # Reject Root or capability-bearing runtime.
    scope = Scope(
        hook="INGRESS",
        ifindex=int(Path("/sys/class/net/lo/ifindex").read_text()),
        net_namespace=os.readlink("/proc/self/ns/net"),
        program_sha256=file_sha(args.program),
        loader_sha256=file_sha(args.inspector),
        bundle_digest=digest(preparation_bundle()),
    )
    plan = ApplicationPlan(controller=controller, scope=scope, mode="PHASE_A_FIXTURE")
    owner = Controller(
        Application(
            args.data_directory / ("application-" + plan.application_session.hex),
            plan,
            args.program,
            args.inspector,
        )
    )
    preparation = None
    handoff = None
    try:
        preparation = Preparation(owner, args.artifacts)
        preparation.prepare()
        handoff = preparation.os_auth_handoff(
            args.package,
            args.manifest_sha,
            qualification_only=args.mode == "auth-qualify",
            live_qualification=args.mode == "live-qualify",
        )
        print("AUTH ONLY / NO KERNEL" if args.mode == "auth-qualify" else "LIVE / NO AI / NO RETRY")
        if not confirm_scope(handoff):
            print("Approval denied or cancelled; no authentication requested.")
            return 1
        handoff.authenticate_native()  # Existing OS terminal; no password input here.
        print(json.dumps(handoff.observe(), indent=2))
        if args.mode == "auth-qualify":
            input("Authentication qualified. Press Enter to stop B: ")
        else:
            from soc_agent.security_ai.ebpf_tc.live_run import start_live_run

            start_live_run(preparation, gui=args.gui)
    finally:
        # Preserve real cleanup results even on an early failure; never auto retry.
        try:
            if handoff is not None:
                handoff.close()
                receipt = owner.application.directory / "terminal-qualification-result.json"
                receipt.write_text(json.dumps(handoff.snapshot(), indent=2) + "\n")
        finally:
            owner.close()
    if handoff.error or handoff.cleanup not in {
        "AUTH_ONLY_PROCESS_EXIT_VERIFIED",
        "PROCESS_AND_AUDIT_VERIFIED",
    }:
        print("Qualification cleanup unverified; do not continue or retry automatically.")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
