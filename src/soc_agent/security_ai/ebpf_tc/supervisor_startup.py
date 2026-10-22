"""Prepare by default; explicit SHA-pinned execution only after new Native approval."""

import argparse
import asyncio
import hashlib
import json
import os
import signal
import threading
import time
from contextlib import contextmanager
from pathlib import Path

from soc_agent.security_ai.collectors.handoff import failure_evidence
from soc_agent.security_ai.collectors.live import LiveZeekCollector
from soc_agent.security_ai.collectors.live_contract import LivePlan
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
from soc_agent.security_ai.ebpf_tc.installation import canonical, verify_package
from soc_agent.security_ai.ebpf_tc.supervisor import (
    SupervisedSession,
    SupervisorImage,
    prepare_supervisor_image,
)
from soc_agent.security_ai.ebpf_tc.trust import release_approval
from soc_agent.security_ai.ebpf_tc.unified_startup import prepare_candidate
from soc_agent.security_ai.native_terminal import confirm_scope
from soc_agent.security_ai.research.models import digest


def prepare(directory: Path) -> SupervisorImage:
    local_controller()
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    _, _, package, manifest = prepare_candidate(directory, version="0.5.16", inspector=True)
    image = prepare_supervisor_image(package, manifest, directory / "supervisor-image.py")
    (directory / "supervisor-image.json").write_text(image.model_dump_json(indent=2) + "\n")
    return image


def prepare_run(
    handoff: SupervisedSession, image: SupervisorImage, zeek_plan: LivePlan
) -> RunIdentity:
    """Validate the complete ordinary-user binding before asking for OS authority."""
    handoff._scope()
    plan, release = handoff.plan, handoff.release
    scope = plan.broker.application.scope
    if (
        (release.identity, release.version, release.bundle_digest)
        != (image.manifest, image.version, plan.bundle_digest)
        or handoff.envelope != release_approval(plan, release)
        or plan.program_sha256 != scope.program_sha256
        or (scope.net_namespace, scope.interface, scope.ifindex, scope.hook)
        != (image.scope_namespace, "lo", 1, "INGRESS")
        or (scope.max_duration_seconds, scope.max_events, scope.queue_capacity)
        != (release.duration_seconds, release.events, release.queue_capacity)
        or zeek_plan.net_namespace != scope.net_namespace
        or zeek_plan.interface != scope.interface
        or zeek_plan.bundle_digest != image.zeek_bundle
    ):
        raise ValueError("SUPERVISOR_STARTUP_SCOPE_MISMATCH")
    run = RunIdentity(
        application_session=plan.broker.application.application_session,
        scope_digest=digest(scope.model_dump(mode="json")),
        run_number=1,
    )
    handoff.validate_run_identity(run)
    return run


async def watch_control(handoff):
    """Heartbeat the authenticated session independently of GUI and DNS completion."""
    while not handoff.ended:
        await asyncio.to_thread(handoff.observe)
        await asyncio.sleep(0.5)


class SupervisorTermination(KeyboardInterrupt):
    """A real terminal/process signal, never successful collector completion."""

    def __init__(self, signum: int):
        self.signum = signum
        super().__init__("SUPERVISOR_SIGNAL_" + signal.Signals(signum).name)


@contextmanager
def termination_boundary():
    """Unwind through the existing cleanup once; a second signal cannot skip it."""
    if threading.current_thread() is not threading.main_thread():
        raise ValueError("SUPERVISOR_MAIN_THREAD_REQUIRED")
    requested = False

    def stop(signum, _frame):
        nonlocal requested
        if not requested:
            requested = True
            raise SupervisorTermination(signum)

    previous = {sig: signal.getsignal(sig) for sig in (signal.SIGTERM, signal.SIGINT)}
    try:
        for sig in previous:
            signal.signal(sig, stop)
        yield
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def shutdown_collectors(handoff, runner, future, *, phase_d=False) -> list[dict]:
    """Revoke privileged work before user-side drain, attempt each cleanup independently."""
    failures = []
    if phase_d:
        # TCX can reach its packet budget while DNS is inside its separate 10s window.
        # Release the owned link, then finish the bounded DNS task before revoking
        # its control session. Do not close its status channel underneath wait().
        def detach():
            if handoff and not handoff.ended and handoff.link_evidence:
                handoff.stop()  # Existing scoped STOP releases owned Link, keeps Broker alive.

        operations = [
            ("TCX_STOP", "SupervisedSession.stop", detach),
            ("DNS_DRAIN", "Future.result", (lambda: future.result(12)) if future else None),
            ("NATIVE_CLOSE", "SupervisedSession.close", handoff.close if handoff else None),
        ]
    else:
        operations = [
            ("NATIVE_CLOSE", "SupervisedSession.close", handoff.close if handoff else None),
            ("DNS_STOP", "StreamProcess.stop", runner.stop if runner else None),
            ("DNS_DRAIN", "Future.result", (lambda: future.result(20)) if future else None),
        ]
    for stage, api, operation in operations:
        if operation is not None:
            try:
                operation()
            except (OSError, ValueError, EOFError, TimeoutError) as exc:
                failures.append(failure_evidence(exc, stage=stage, api=api))
    return failures


def execute(
    directory: Path, expected_manifest: str, expected_image: str, *, gui=False, phase_d=None
):
    with termination_boundary():
        return _execute(directory, expected_manifest, expected_image, gui=gui, phase_d=phase_d)


def _execute(
    directory: Path, expected_manifest: str, expected_image: str, *, gui=False, phase_d=None
):
    local_controller()  # No Root GUI/runtime or inherited capabilities.
    image = SupervisorImage.model_validate_json((directory / "supervisor-image.json").read_bytes())
    image.verify()
    if (image.manifest, image.sha256) != (expected_manifest, expected_image):
        raise ValueError("SUPERVISOR_REVIEWED_IMAGE_REQUIRED")
    verify_package(directory / "release", expected_manifest)
    if os.readlink("/proc/self/ns/net") != image.scope_namespace:
        raise ValueError("SUPERVISOR_NAMESPACE_CHANGED")
    if phase_d is not None:
        from soc_agent.security_ai.collectors.offload_session import preflight
        from soc_agent.security_ai.ebpf_tc.phase_d import validate

        checked = validate(
            directory, hashlib.sha256(canonical(phase_d)).hexdigest(), expected_image
        )
        if checked != phase_d:
            raise ValueError("PHASE_D_CONTRACT_MISMATCH")
        preflight(
            directory / "dns-sidecar",
            phase_d["dns_manifest"],
            expected_image,
            Path("tests/native_dns_live_probe.py").absolute(),
            previous_manifest=image.previous_manifest,
        )
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

    control_future = None
    first_failure = None
    stage, api = "PREPARE", "Preparation.prepare"

    try:
        preparation = Preparation(owner, directory / "artifacts")
        preparation.prepare()
        handoff = preparation.os_auth_handoff(
            directory / "release", image.manifest, supervisor_image=image
        )
        submit(zeek.prepare()).result(20)  # No capture/authentication.
        if zeek.plan.bundle_digest != image.zeek_bundle:
            raise ValueError("SUPERVISOR_ZEEK_SOURCE_CHANGED")
        run = prepare_run(handoff, image, zeek.plan)
        stage, api = "APPROVAL_CONFIRMATION", "confirm_scope"
        if not confirm_scope(handoff):
            raise ValueError("SUPERVISOR_APPROVAL_DENIED")
        stage, api = "OS_AUTHENTICATION", "SupervisedSession.authenticate_native"
        handoff.authenticate_native()  # Exactly one fresh OS call; no downstream sudo.
        control_future = submit(watch_control(handoff))
        if phase_d is not None:
            from soc_agent.security_ai.collectors.offload_session import execute as dns_execute

            stage, api = "TCX_ATTACH", "SupervisedSession.command"
            with handoff.control_lock:
                handoff.command(
                    Command(
                        command="ATTACH",
                        plan_digest=handoff.plan.approval,
                        sequence=handoff.sequence + 1,
                        run=run,
                    )
                )
            stage, api = "DNS_TASK", "offload_session.execute"
            future = submit(
                asyncio.to_thread(
                    dns_execute,
                    directory / "dns-sidecar",
                    phase_d["dns_manifest"],
                    image.sha256,
                    probe=Path("tests/native_dns_live_probe.py").absolute(),
                    supervised=handoff,
                )
            )
        else:
            runner = StreamProcess(zeek.directory, zeek.plan, supervisor=handoff.supervisor)
        if phase_d is None:
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
            with handoff.control_lock:
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

            stage, api = "GUI", "PreparedDesktop.launch"
            launch(preparation)
        else:
            stage, api = "COLLECTOR_LOOP", "SupervisedSession.observe"
            until = time.monotonic() + 300
            while time.monotonic() < until and not handoff.error:
                handoff.observe()
                if handoff.data.error:
                    stage, api = "TCX_DATA_PROCESSING", "PacketChannel.error"
                    raise ValueError(handoff.data.error)
                if handoff.error:
                    stage, api = "CONTROL_STATUS", "SupervisedSession.observe"
                    raise ValueError(handoff.error)
                if future.done():
                    stage, api = "DNS_TASK", "Future.result"
                    future.result()  # Preserve first DNS failure; never retry.
                    if phase_d is None:
                        break
                    handoff.zeek_snapshot = future.result()
                if handoff.data.adapter and handoff.data.adapter.flow.closed:
                    break
                time.sleep(0.2)
                stage, api = "COLLECTOR_LOOP", "SupervisedSession.observe"
    except BaseException as exc:
        # Cleanup must also run for signals/interruption. Re-raise the exact
        # original exception after retaining safe metadata, never normalize errno.
        first_failure = failure_evidence(exc, stage=stage, api=api)
        first_failure["signal"] = getattr(exc, "signum", None)
        raise
    finally:
        # Both cleanup paths run even if the other's stop/teardown raises.
        failures = shutdown_collectors(handoff, runner, future, phase_d=phase_d is not None)
        try:
            try:
                submit(zeek.stop()).result(35)
            except (OSError, ValueError, TimeoutError) as exc:
                failures.append(
                    failure_evidence(exc, stage="DNS_ADAPTER_STOP", api="LiveZeekCollector.stop")
                )
            if control_future:
                try:
                    control_future.result(6)
                except (OSError, ValueError, TimeoutError) as exc:
                    control_future.cancel()
                    failures.append(
                        failure_evidence(exc, stage="HEARTBEAT_STOP", api="Future.result")
                    )
        finally:
            try:
                if handoff:
                    try:
                        handoff.close()
                    except (OSError, ValueError, EOFError, TimeoutError) as exc:
                        failures.append(
                            failure_evidence(
                                exc, stage="FINAL_NATIVE_CLOSE", api="SupervisedSession.close"
                            )
                        )
                    (directory / "supervised-result.json").write_text(
                        json.dumps(
                            dict(
                                tcx=handoff.snapshot(),
                                zeek=handoff.zeek_snapshot,
                                errors=failures,
                                first_failure=first_failure,
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
