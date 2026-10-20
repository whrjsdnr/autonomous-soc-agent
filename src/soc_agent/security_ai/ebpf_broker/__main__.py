"""Only explicit fixture mode is admitted. No Native or privileged CLI exists in B-1."""

import argparse
import json
import os
from pathlib import Path

from soc_agent.security_ai.ebpf_broker.controller import Controller
from soc_agent.security_ai.ebpf_native.application import Application
from soc_agent.security_ai.ebpf_native.authentication import FixtureAuthentication
from soc_agent.security_ai.ebpf_native.contracts import ApplicationPlan, Scope, local_controller
from soc_agent.security_ai.ebpf_native.loader import bundle, file_sha
from soc_agent.security_ai.research.models import digest


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("fixture",))
    parser.add_argument("--program", type=Path, required=True)
    parser.add_argument("--loader", type=Path, required=True)
    parser.add_argument("--data-directory", type=Path, required=True)
    parser.add_argument("--gui", action="store_true")
    args = parser.parse_args(argv)
    scope = Scope(
        hook="INGRESS",
        ifindex=int(Path("/sys/class/net/lo/ifindex").read_text()),
        net_namespace=os.readlink("/proc/self/ns/net"),
        program_sha256=file_sha(args.program),
        loader_sha256=file_sha(args.loader),
        bundle_digest=digest(bundle()),
    )
    plan = ApplicationPlan(controller=local_controller(), scope=scope, mode="PHASE_A_FIXTURE")
    controller = Controller(
        Application(
            args.data_directory / ("application-" + plan.application_session.hex),
            plan,
            args.program,
            args.loader,
        )
    )
    try:
        controller.prepare()
        print("PHASE B-1 MOCK ONLY. NO OS PASSWORD / NATIVE LOAD / TC ATTACH")
        print(json.dumps(controller.plan.model_dump(mode="json"), indent=2))
        print("Approval digest: " + controller.plan.identity)
        if input("Type this digest to approve the fixture: ").strip() != controller.plan.identity:
            return 1
        controller.approve(controller.plan.identity)
        controller.authenticate(FixtureAuthentication())
        if args.gui:
            from soc_agent.security_ai.ebpf_broker.gui import launch

            return launch(controller)
        controller.start()
        print(json.dumps(controller.observe(), indent=2))
        controller.stop()
        return 0
    finally:
        controller.close()


if __name__ == "__main__":
    raise SystemExit(main())
