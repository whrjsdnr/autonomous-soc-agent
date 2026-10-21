"""Prepare by default; explicit SHA-pinned execution only after new Native approval."""

import argparse
import asyncio
import json
import os
import threading
import time
from pathlib import Path

from soc_agent.security_ai.collectors.live import LiveZeekCollector
from soc_agent.security_ai.collectors.live_process import StreamProcess
from soc_agent.security_ai.ebpf_broker.contracts import Command
from soc_agent.security_ai.ebpf_broker.controller import Controller
from soc_agent.security_ai.ebpf_native.application import Application
from soc_agent.security_ai.ebpf_native.contracts import (
    ApplicationPlan,
    RunIdentity,
    Scope,
    local_controller,
)
from soc_agent.security_ai.ebpf_native.loader import bundle as preparation_bundle
from soc_agent.security_ai.ebpf_native.loader import file_sha
from soc_agent.security_ai.ebpf_tc.bridge import Preparation
from soc_agent.security_ai.ebpf_tc.installation import verify_package
from soc_agent.security_ai.ebpf_tc.supervisor import (
    SupervisorImage,
    prepare_supervisor_image,
)
from soc_agent.security_ai.ebpf_tc.unified_startup import prepare_candidate
from soc_agent.security_ai.native_terminal import confirm_scope
from soc_agent.security_ai.research.models import digest


def prepare(directory: Path) -> SupervisorImage:
    local_controller()
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    _, _, package, manifest = prepare_candidate(directory, version="0.5.8", inspector=True)
    image = prepare_supervisor_image(package, manifest, directory / "supervisor-image.py")
    (directory / "supervisor-image.json").write_text(image.model_dump_json(indent=2) + "\n")
    return image


def execute(directory: Path, expected_manifest: str, expected_image: str, *, gui=False):
    local_controller()  # No Root GUI/runtime or inherited capabilities.
    image = SupervisorImage.model_validate_json((directory / "supervisor-image.json").read_bytes())
    image.verify()
    if (image.manifest, image.sha256) != (expected_manifest, expected_image):
        raise ValueError("SUPERVISOR_REVIEWED_IMAGE_REQUIRED")
    verify_package(directory / "release", expected_manifest)
    if os.readlink("/proc/self/ns/net") != image.scope_namespace:
        raise ValueError("SUPERVISOR_NAMESPACE_CHANGED")
    legacy = directory / "preparation"
    scope = Scope(
        hook="INGRESS",
        ifindex=1,
        net_namespace=image.scope_namespace,
        program_sha256=file_sha(legacy / "tc.bpf.o"),
        loader_sha256=file_sha(legacy / "phase-a-loader"),
        bundle_digest=digest(preparation_bundle()),
    )
    owner = Controller(
        Application(
            directory / "session",
            ApplicationPlan(controller=local_controller(), scope=scope, mode="PHASE_A_FIXTURE"),
            legacy / "tc.bpf.o",
            legacy / "phase-a-loader",
        )
    )
    loop = asyncio.new_event_loop()
    worker = threading.Thread(target=loop.run_forever, name="ordinary-zeek-controller")
    worker.start()
    zeek = LiveZeekCollector(directory / "dns")
    handoff = runner = None
    future = None

    def submit(coroutine):
        return asyncio.run_coroutine_threadsafe(coroutine, loop)

    async def watch_dns():
        await zeek.start()
        zeek.process_runner = runner
        zeek.process_task = asyncio.create_task(asyncio.to_thread(runner.run))
        try:
            while not zeek.process_task.done():
                handoff.zeek_snapshot = zeek.snapshot()
                await asyncio.sleep(0.2)
            await zeek.process_task
            await zeek.task
        finally:
            handoff.zeek_snapshot = zeek.snapshot()

    try:
        preparation = Preparation(owner, directory / "artifacts")
        preparation.prepare()
        handoff = preparation.os_auth_handoff(
            directory / "release", image.manifest, supervisor_image=image
        )
        submit(zeek.prepare()).result(20)  # No capture/authentication.
        if zeek.plan.bundle_digest != image.zeek_bundle:
            raise ValueError("SUPERVISOR_ZEEK_SOURCE_CHANGED")
        if not confirm_scope(handoff):
            raise ValueError("SUPERVISOR_APPROVAL_DENIED")
        handoff.authenticate_native()  # Exactly one fresh OS call; no downstream sudo.
        runner = StreamProcess(zeek.directory, zeek.plan, supervisor=handoff.supervisor)
        runner.authenticate()  # Session claim only; no password API in this branch.
        future = submit(watch_dns())
        ready_deadline = time.monotonic() + 10
        while not (handoff.zeek_snapshot and handoff.zeek_snapshot.get("collection_live")):
            if future.done():
                future.result()
                raise ValueError("SUPERVISOR_ZEEK_EXIT_BEFORE_READY")
            if time.monotonic() >= ready_deadline:
                raise ValueError("SUPERVISOR_ZEEK_READY_TIMEOUT")
            time.sleep(0.05)
        run = RunIdentity(
            application_session=handoff.plan.broker.application.application_session,
            scope_digest=digest(scope.model_dump(mode="json")),
            run_number=1,
        )
        handoff.command(
            Command(
                command="ATTACH",
                plan_digest=handoff.plan.approval,
                sequence=handoff.sequence + 1,
                run=run,
            )
        )
        if gui:
            from soc_agent.security_ai.ebpf_tc.gui import launch

            launch(preparation)
        else:
            until = time.monotonic() + 300
            while time.monotonic() < until and not handoff.error:
                handoff.observe()
                if future.done():
                    future.result()  # Preserve first DNS failure; never retry.
                    break
                if handoff.data.adapter and handoff.data.adapter.flow.closed:
                    break
                time.sleep(0.2)
    finally:
        # Both cleanup paths run even if the other's stop/teardown raises.
        failures = []
        try:
            if runner:
                runner.stop()
            if future:
                try:
                    future.result(20)
                except (OSError, ValueError, TimeoutError) as exc:
                    failures.append(str(exc))
            submit(zeek.stop()).result(35)
        finally:
            try:
                if handoff:
                    handoff.close()
                    (directory / "supervised-result.json").write_text(
                        json.dumps(
                            dict(
                                tcx=handoff.snapshot(), zeek=handoff.zeek_snapshot, errors=failures
                            ),
                            indent=2,
                        )
                        + "\n"
                    )
            finally:
                owner.close()
                loop.call_soon_threadsafe(loop.stop)
                worker.join(timeout=5)
                if worker.is_alive():
                    raise ValueError("SUPERVISOR_USER_WORKER_CLEANUP_UNVERIFIED")
                loop.close()
    return handoff.snapshot()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--manifest")
    parser.add_argument("--image-sha")
    parser.add_argument("--gui", action="store_true")
    args = parser.parse_args()
    if args.execute:
        if not args.manifest or not args.image_sha:
            parser.error("Execution requires the separately approved Manifest and image SHA")
        result = execute(args.directory.absolute(), args.manifest, args.image_sha, gui=args.gui)
    else:
        result = prepare(args.directory.absolute()).model_dump(mode="json")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
