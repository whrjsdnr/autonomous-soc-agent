"""Prepare by default; explicit SHA-pinned execution only after new Native approval."""

import argparse
import asyncio
import hashlib
import json
import os
import threading
import time
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
from soc_agent.security_ai.ebpf_tc.termination import (
    SupervisorTermination as SupervisorTermination,
)
from soc_agent.security_ai.ebpf_tc.termination import (
    termination_boundary as termination_boundary,
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


def final_result(snapshot: dict, zeek: dict, failures: list[dict], first: dict | None) -> dict:
    """A returned final failure is evidence too; never replace an earlier primary."""
    failures = list(failures)
    code = snapshot.get("last_error")
    if code:
        detail = failure_evidence(
            ValueError(code), stage="FINAL_NATIVE_STATE", api="SupervisedSession.snapshot"
        )
        if detail not in failures:
            failures.append(detail)
    return dict(
        tcx=snapshot,
        zeek=zeek,
        errors=failures,
        first_failure=first if first is not None else failures[0] if failures else None,
    )


def execute(
    directory: Path,
    expected_manifest: str,
    expected_image: str,
    *,
    gui=False,
    phase_d=None,
    r2_approval=None,
    execution_control=None,
):
    with termination_boundary():
        return _execute(
            directory,
            expected_manifest,
            expected_image,
            gui=gui,
            phase_d=phase_d,
            r2_approval=r2_approval,
            execution_control=execution_control,
        )


def _execute(
    directory: Path,
    expected_manifest: str,
    expected_image: str,
    *,
    gui=False,
    phase_d=None,
    r2_approval=None,
    execution_control=None,
):
    local_controller()  # No Root GUI/runtime or inherited capabilities.
    image = SupervisorImage.model_validate_json((directory / "supervisor-image.json").read_bytes())
    image.verify()
    if (image.manifest, image.sha256) != (expected_manifest, expected_image):
        raise ValueError("SUPERVISOR_REVIEWED_IMAGE_REQUIRED")
    release = verify_package(directory / "release", expected_manifest)
    if image.recovery_binding is not None:
        from soc_agent.security_ai.ebpf_tc.recovery_policy import validate_image_recovery

        if gui or phase_d is None or r2_approval is None:
            raise ValueError("RECOVERY_APPROVED_CAMPAIGN_REQUIRED")
        validate_image_recovery(image, release, require_policy=True)
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
    r2 = None
    if r2_approval is not None:
        from soc_agent.security_ai.ebpf_tc.r2_diagnostic import R2Launcher

        if gui or phase_d is None:
            raise ValueError("R2_PHASE_D_HEADLESS_REQUIRED")
        approved = r2_approval.artifact
        if (approved.manifest, approved.image, approved.bundle, approved.root_manifest) != (
            hashlib.sha256(canonical(phase_d)).hexdigest(),
            expected_image,
            phase_d["bundle"],
            expected_manifest,
        ):
            raise ValueError("R2_RELEASE_BINDING")
        from soc_agent.security_ai.ebpf_tc.reassessment_admission import require_r2_reservation

        if r2_approval.campaign_directory is None:
            raise ValueError("R2_CAMPAIGN_RESERVATION_REQUIRED")
        if execution_control is None:
            require_r2_reservation(
                r2_approval.campaign_directory,
                session=r2_approval.session,
                receipt_sha=r2_approval.receipt_sha,
                identity=dict(
                    manifest=approved.manifest,
                    bundle=approved.bundle,
                    image=approved.image,
                    tcx_manifest=approved.root_manifest,
                ),
            )
        r2 = R2Launcher(r2_approval)
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
            ApplicationPlan(
                controller=local_controller(),
                scope=scope,
                mode="PHASE_A_FIXTURE",
                **({"application_session": r2_approval.session} if r2 else {}),
            ),
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
        if execution_control:
            execution_control.waiting()
            print("AWAITING_USER_CONFIRMATION — no budget reservation; cancel with Ctrl-C.")
        if not confirm_scope(handoff):
            raise ValueError("SUPERVISOR_APPROVAL_DENIED")
        if execution_control:
            execution_control.confirmed()
        stage, api = "OS_AUTHENTICATION", "SupervisedSession.authenticate_native"
        if r2:
            r2.claim()  # Extra traffic approval is consumed before OS authentication.
        if execution_control:
            execution_control.step("AUTHENTICATING")  # Durable intent BEFORE the OS call.
        handoff.authenticate_native()  # Exactly one fresh OS call; no downstream sudo.
        if execution_control:
            execution_control.step("ROOT_INSTALLATION_VERIFIED")
        control_future = submit(watch_control(handoff))
        if phase_d is not None:
            from soc_agent.security_ai.collectors.offload_session import execute as dns_execute

            stage, api = "TCX_ATTACH", "SupervisedSession.command"
            if execution_control:
                execution_control.step("NATIVE_START_INTENT")
            with handoff.control_lock:
                handoff.command(
                    Command(
                        command="ATTACH",
                        plan_digest=handoff.plan.approval,
                        sequence=handoff.sequence + 1,
                        run=run,
                    )
                )
            if execution_control:
                execution_control.step("NATIVE_CAPTURE_STARTED")
            if r2:
                if not handoff.link_evidence:
                    raise ValueError("R2_CAPTURE_NOT_READY")
                r2.start(time.monotonic_ns())
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
                flow_closed = bool(handoff.data.adapter and handoff.data.adapter.flow.closed)
                if r2:
                    tcp_closed = None
                    if future.done():
                        from soc_agent.security_ai.ebpf_tc.reassessment import held_json

                        probe_file = directory / "dns-sidecar/live-attempt-1/probe.json"
                        probe = held_json(
                            probe_file, hashlib.sha256(probe_file.read_bytes()).hexdigest()
                        )
                        tcp_records = [v for v in probe["records"] if v["transport"] == "TCP"]
                        if len(tcp_records) != 1:
                            raise ValueError("R2_INITIAL_TCP_EVIDENCE")
                        tcp_closed = tcp_records[0]["socket_closed_monotonic_ns"]
                    stage, api = "R2_DIAGNOSTIC", "R2Launcher.advance"
                    if r2.advance(
                        time.monotonic_ns(),
                        tcp_closed_ns=tcp_closed,
                        sidecar_closed=future.done(),
                        received=handoff.data.adapter.received if handoff.data.adapter else 0,
                        capture_closed=flow_closed,
                    ):
                        break
                elif flow_closed:
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
                    if r2:
                        try:
                            (directory / "r2-observation.json").write_text(
                                json.dumps(r2.snapshot(), indent=2) + "\n"
                            )
                        except OSError as exc:
                            failures.append(
                                failure_evidence(
                                    exc, stage="R2_OBSERVATION_SAVE", api="Path.write_text"
                                )
                            )
                    (directory / "supervised-result.json").write_text(
                        json.dumps(
                            final_result(
                                handoff.snapshot(), handoff.zeek_snapshot, failures, first_failure
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
