"""Terminal-authenticated launcher; a prepared GUI may start the same authenticated runner.

Native output is diagnostics, not a capture-integrity attestation. Run only after
reviewing the per-session digest and explicit user approval. Offline fixtures never
call sudo or open an interface.
"""

import argparse
import concurrent.futures
import json
import math
import os
import selectors
import subprocess
import sys
import time
from pathlib import Path

from soc_agent.review.persistence.secure_storage import create_private_file
from soc_agent.security_ai.collectors.analysis_feed import AnalysisFeed
from soc_agent.security_ai.collectors.finalization import Ledger, termination_reason
from soc_agent.security_ai.collectors.finalization import publish as write_new
from soc_agent.security_ai.collectors.handoff import (
    exchange,
    failure_evidence,
    process_identity,
    read_controller,
    safe_code,
)
from soc_agent.security_ai.collectors.handoff import same_process as same_process
from soc_agent.security_ai.collectors.live_contract import LivePlan, docker_argv, verify
from soc_agent.security_ai.collectors.live_stream import decode
from soc_agent.security_ai.collectors.offline import OfflineZeek, file_digest


class StreamProcess:
    def __init__(
        self,
        directory: Path,
        plan: LivePlan,
        *,
        fixture: Path | None = None,
        supervisor=None,
        pcap_input: bytes | None = None,
        analysis_deadline: float | None = None,
        analysis_feed: AnalysisFeed | None = None,
    ):
        self.directory, self.plan, self.fixture = directory, plan, fixture
        self.supervisor = supervisor
        self.analysis_feed = analysis_feed
        if analysis_feed is not None:
            if pcap_input is not None or fixture is not None or analysis_deadline is None:
                raise ValueError("ZEEK_ANALYSIS_FEED_SCOPE")
            from soc_agent.security_ai.collectors.offload_copy import memory_pcap

            pcap_input = memory_pcap([])
        self.pcap_input = pcap_input
        self.phase_times: dict[str, float] = {}
        self.phase_wall_ns: dict[str, int] = {}
        self.analysis_deadline = analysis_deadline
        if analysis_deadline is not None and (
            pcap_input is None or not math.isfinite(analysis_deadline)
        ):
            raise ValueError("ZEEK_ANALYSIS_DEADLINE_SCOPE")
        self.file_input = fixture is not None or pcap_input is not None
        if pcap_input is not None and (
            fixture is not None
            or supervisor is not None
            or not 24 <= len(pcap_input) <= 24 + 32 * (512 + 16)
            or pcap_input[:4] != b"\x4d\x3c\xb2\xa1"
        ):
            raise ValueError("ZEEK_MEMORY_PCAP_SCOPE")
        if pcap_input is not None:
            from soc_agent.security_ai.collectors.offload_copy import validate_memory_pcap

            validate_memory_pcap(pcap_input)
        if fixture is not None and supervisor is not None:
            raise ValueError("ZEEK_FIXTURE_SUPERVISOR_MIX_REJECTED")
        self.process = None
        self.output_bytes = 0
        self.stop_requested = False
        self.container_name = "soc-zeek-" + plan.session_id.hex
        self.cleanup_verified = False
        self.container_absent = False
        self.container_identity = None
        self._authenticated_plan = None
        self._launched = False

    def deadline_expired(self) -> bool:
        return self.analysis_deadline is not None and time.monotonic() >= self.analysis_deadline

    def analysis_container_timing(self) -> dict:
        """Fixed, read-only, exact-plan Docker events; never a capture or retry."""
        if self.analysis_feed is None or "process_launched" not in self.phase_wall_ns:
            raise ValueError("ZEEK_ANALYSIS_TIMING_SCOPE")
        result = self._docker(
            "events",
            "--since",
            str(self.phase_wall_ns["process_launched"] // 10**9),
            "--until",
            str(time.time()),
            "--filter",
            "type=container",
            "--filter",
            "label=soc.plan=" + self.plan.identity,
            "--format",
            "{{json .}}",
        )
        if result.returncode or len(result.stdout) > 131072:
            return dict(verified=False, returncode=result.returncode)
        events = [json.loads(line) for line in result.stdout.splitlines()]
        if len(events) > 32:
            raise ValueError("ZEEK_ANALYSIS_TIMING_BOUND")
        return dict(
            verified=True,
            clock="DOCKER_AND_CONTROLLER_WALL_NS_NOT_KERNEL_CLOCK",
            events=[
                dict(action=e["Action"], wall_ns=e["timeNano"])
                for e in events
                if e["Action"] in {"create", "start", "die", "destroy"}
            ],
            controller_phase_wall_ns=self.phase_wall_ns,
        )

    def stop(self):
        self.stop_requested = True

    def _docker(self, *args):
        if self.supervisor is not None:
            raise ValueError("ZEEK_SUPERVISOR_ARBITRARY_DOCKER_DENIED")
        prefix = [] if self.file_input else ["sudo", "-n", "--"]
        return subprocess.run(
            prefix + ["docker", *args],
            capture_output=True,
            timeout=7 if args[0] == "stop" else 2,
            check=False,
        )

    def _absent(self):
        if self.supervisor is not None:
            return self.supervisor.stop_zeek()
        # A successful, exact-name query is required. --rm or inspect failure is not proof.
        result = self._docker(
            "container",
            "ls",
            "--all",
            "--no-trunc",
            "--filter",
            "name=^/" + self.container_name + "$",
            "--format",
            "{{.ID}}",
        )
        return result.returncode == 0 and result.stdout.strip() == b""

    def _stop_container(self):
        if self.supervisor is not None:
            return self.supervisor.stop_zeek()
        if self._absent():
            return True  # Exit raced the stop request; still drain stdout and verify CLOSED.
        fmt = '{"id":{{json .Id}},"image":{{json .Config.Image}},"labels":{{json .Config.Labels}}}'
        record = self._docker("inspect", "--format", fmt, self.container_name)
        if record.returncode or len(record.stdout) > 4096:
            return False
        try:
            identity = json.loads(record.stdout)
            import re

            if (
                not re.fullmatch(r"[a-f0-9]{64}", identity["id"])
                or identity["image"] != self.plan.image
                or not isinstance(identity["labels"], dict)
                or identity["labels"].get("soc.plan") != self.plan.identity
                or identity["labels"].get("soc.generation") != str(self.plan.controller_generation)
            ):
                return False
        except (ValueError, KeyError, TypeError):
            return False
        self.container_identity = identity["id"]
        result = self._docker("stop", "--time=5", identity["id"])
        return result.returncode == 0 or self._absent()

    def _controller(self, operation="validate"):
        return exchange(self.directory, self.plan, operation)

    def authenticate(self):
        """Main terminal thread only. No capture, password handling or persisted auth token."""
        if self.file_input or self._authenticated_plan is not None or self._launched:
            raise ValueError("ZEEK_SESSION_REUSE_DENIED")
        verify(self.plan, self.plan.identity)
        self._controller("claim")
        from soc_agent.cli import terminal_authenticate

        try:
            if self.supervisor is None:
                terminal_authenticate()
            else:
                self.supervisor.authorize(self.plan)
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            raise ValueError("ZEEK_AUTH_DENIED_CANCELLED_OR_TIMEOUT") from error
        verify(self.plan, self.plan.identity)
        self._controller()
        # Private, process-local binding. No preauthenticated CLI option or disk receipt.
        self._authenticated_plan = self.plan.identity

    def run(self, *, on_line=None):
        if self._launched:
            raise ValueError("ZEEK_SESSION_REUSE_DENIED")
        if self.deadline_expired():
            raise ValueError("ZEEK_ANALYSIS_DEADLINE_BEFORE_LAUNCH")
        # Deadline-bound sidecar sessions already inspect the immutable image
        # before authentication. Do not repeat a ten-second daemon query here;
        # --pull=never and the fixed digest remain enforced by docker_argv.
        if self.analysis_deadline is None:
            OfflineZeek().environment()
        argv = docker_argv(
            self.plan,
            Path(__file__).parent.absolute(),
            fixture=self.fixture,
            stdin_pcap=self.pcap_input is not None,
        )
        if not self.file_input:
            if self._authenticated_plan is None:
                self.authenticate()
            verify(self.plan, self.plan.identity)
            if self._authenticated_plan != self.plan.identity:
                raise ValueError("ZEEK_APPROVAL_DIGEST_MISMATCH")
            self._controller()
            if self.supervisor is None:
                argv = ["sudo", "-n", "--", *argv]
        self._launched = True
        identity = process_identity(os.getpid())
        write_new(
            self.directory / "process.json",
            dict(
                contract="soc-zeek-live-process:v1",
                plan_digest=self.plan.identity,
                generation=str(self.plan.controller_generation),
                launcher=identity,
                image=self.plan.image,
                native_capture=not self.file_input,
                analysis_copy_input=self.pcap_input is not None,
            ),
        )
        started = time.monotonic()
        create_private_file(self.directory / "stream.jsonl")
        error, sequence, closed, code = None, 0, False, None
        ledger = Ledger()
        reason = None
        requested = None
        drain_started = None
        controller_error = None
        selector = selectors.DefaultSelector()
        stopper = concurrent.futures.ThreadPoolExecutor(
            max_workers=1, thread_name_prefix="zeek-stop"
        )
        stop_future = None
        cleanup_attempted = False
        cleanup_failures = []
        input_pending = memoryview(self.pcap_input or b"")
        adapter_failure = None
        first_failure = None
        stage, api = "LAUNCH", "SupervisorClient.start/subprocess.Popen"
        discarded_after_adapter_failure = 0
        ledger_attempted = True
        envelope = None

        def preserve_failure(exc, failure_stage, failure_api):
            nonlocal first_failure
            if first_failure is None:
                first_failure = failure_evidence(exc, stage=failure_stage, api=failure_api) | dict(
                    stream_sequence=sequence, closed_observed=closed, container_exit_code=code
                )

        def failure_detail(stage, exc):
            preserve_failure(exc, stage, "StreamProcess." + stage.lower())
            if len(cleanup_failures) < 8 and not any(
                row["stage"] == stage for row in cleanup_failures
            ):
                cleanup_failures.append(
                    dict(
                        stage=stage,
                        code=safe_code(exc),
                        category=type(exc).__name__,
                        errno=exc.errno if isinstance(exc, OSError) else None,
                    )
                )

        def poll_owned():
            try:
                return self.process.poll() if self.process else None
            except (OSError, ValueError, subprocess.SubprocessError) as exc:
                failure_detail("STATUS", exc)
                return None

        try:
            try:
                if self.deadline_expired():
                    raise ValueError("ZEEK_ANALYSIS_DEADLINE_BEFORE_LAUNCH")
                if self.supervisor is not None:
                    self.process = self.supervisor.start(self.plan)
                else:
                    self.process = subprocess.Popen(
                        argv,
                        stdin=subprocess.PIPE
                        if self.pcap_input is not None
                        else subprocess.DEVNULL,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE
                        if self.analysis_feed is not None
                        else subprocess.DEVNULL,
                        # Keep the terminal session (sudo timestamp), but route Ctrl+C only
                        # through the GUI controller's verified stop/drain path.
                        **({"process_group": 0} if not self.file_input else {}),
                    )
            except OSError as start_error:
                raise ValueError("ZEEK_DOCKER_START_FAILED") from start_error
            selector.register(self.process.stdout, selectors.EVENT_READ)
            if self.analysis_feed is not None:
                selector.register(self.process.stderr, selectors.EVENT_READ)
            self.phase_times["process_launched"] = time.monotonic()
            self.phase_wall_ns["process_launched"] = time.time_ns()
            stderr_pending = b""
            stderr_bytes = 0
            input_registered = self.pcap_input is not None
            if self.pcap_input is not None:
                os.set_blocking(self.process.stdin.fileno(), False)
                selector.register(self.process.stdin, selectors.EVENT_WRITE)
            pending = b""
            stop_sent = False
            controller_checked = 0.0
            with (self.directory / "stream.jsonl").open("ab", buffering=0) as output:
                while True:
                    stage, api = "STOP_REQUEST", "stop.request.read_text/json.loads"
                    if (self.directory / "stop.request").exists():
                        self.stop_requested = True
                        tombstone = json.loads((self.directory / "stop.request").read_text())
                        requested = (
                            "USER_STOP"
                            if tombstone.get("reason") == "USER_STOP"
                            else "CONTROLLER_STOP"
                        )
                    now = time.monotonic()
                    if self.analysis_feed is not None and not input_pending:
                        next_record = self.analysis_feed.take()
                        if next_record is not None:
                            input_pending = memoryview(next_record)
                            if not input_registered:
                                selector.register(self.process.stdin, selectors.EVENT_WRITE)
                                input_registered = True
                        elif self.analysis_feed.exhausted and not self.process.stdin.closed:
                            self.process.stdin.close()
                            self.phase_times["input_closed"] = now
                    if self.deadline_expired():
                        stage, api = "ANALYSIS_BUDGET", "time.monotonic"
                        raise ValueError("ZEEK_ANALYSIS_SESSION_DEADLINE")
                    if (
                        not self.file_input
                        and not self.stop_requested
                        and now - controller_checked >= 0.5
                    ):
                        try:
                            self._controller()
                        except (OSError, ValueError) as failure:
                            preserve_failure(
                                failure, "CONTROLLER_IDENTITY", "StreamProcess._controller"
                            )
                            controller_error = safe_code(failure)
                            requested = "CONTROLLER_STOP"
                            self.stop_requested = True
                        controller_checked = now
                    expired = time.monotonic() - started > self.plan.duration_seconds + 5
                    if (self.stop_requested or expired) and not stop_sent:
                        requested = requested or ("SESSION_TIMEOUT" if expired else "USER_STOP")
                        drain_started = time.monotonic()
                        stop_sent = True
                        cleanup_attempted = True
                        stop_future = stopper.submit(self._stop_container)
                    stage, api = "CONTAINER_STOP", "Future.result/StreamProcess._stop_container"
                    if stop_future and stop_future.done() and not stop_future.result():
                        raise ValueError("ZEEK_CONTAINER_STOP_UNVERIFIED")
                    if drain_started and time.monotonic() - drain_started > 10:
                        raise ValueError("ZEEK_STOP_DEADLINE_UNVERIFIED")
                    if time.monotonic() - started > self.plan.duration_seconds + 15:
                        raise ValueError("ZEEK_PROCESS_DEADLINE_EXCEEDED")
                    stage, api = "STREAM_WAIT", "selectors.select"
                    events = selector.select(0.1)
                    for key, _ in events:
                        if self.analysis_feed is not None and key.fileobj is self.process.stderr:
                            diagnostic = os.read(self.process.stderr.fileno(), 4096)
                            stderr_bytes += len(diagnostic)
                            if stderr_bytes > 8192:
                                raise ValueError("ZEEK_ANALYSIS_STDERR_BOUND")
                            if not diagnostic:
                                selector.unregister(self.process.stderr)
                            stderr_pending += diagnostic
                            while b"\n" in stderr_pending:
                                marker, stderr_pending = stderr_pending.split(b"\n", 1)
                                if marker == b"SOC_ZEEK_INIT":
                                    self.phase_times.setdefault("script_init", time.monotonic())
                                    self.phase_wall_ns.setdefault("script_init", time.time_ns())
                        if self.pcap_input is not None and key.fileobj is self.process.stdin:
                            stage, api = "PCAP_INPUT", "os.write"
                            try:
                                sent = os.write(self.process.stdin.fileno(), input_pending[:4096])
                            except BlockingIOError:
                                continue
                            if sent <= 0:
                                raise ValueError("ZEEK_PCAP_INPUT_WRITE")
                            input_pending = input_pending[sent:]
                            if not input_pending:
                                selector.unregister(self.process.stdin)
                                input_registered = False
                                if self.analysis_feed is None:
                                    self.process.stdin.close()
                    if not any(key.fileobj is self.process.stdout for key, _ in events):
                        if poll_owned() is not None:
                            # Drain the pipe even after process exit; EOF is the boundary.
                            continue
                        continue
                    stage, api = "STREAM_RECEIVE", "os.read"
                    chunk = os.read(self.process.stdout.fileno(), 16384)
                    if not chunk:
                        break
                    stage, api = "OUTPUT_BOUND", "StreamProcess.output_bytes"
                    self.output_bytes += len(chunk)
                    if self.output_bytes > self.plan.output_bytes:
                        raise ValueError("ZEEK_STREAM_OUTPUT_BUDGET")
                    pending += chunk
                    while b"\n" in pending:
                        line, pending = pending.split(b"\n", 1)
                        line += b"\n"
                        ledger_attempted = False
                        envelope = None
                        stage, api = "STREAM_DECODE", "live_stream.decode"
                        envelope = decode(line)
                        stage, api = "STREAM_SEQUENCE", "Envelope.sequence"
                        if envelope.sequence != sequence + 1 or closed:
                            raise ValueError("ZEEK_STREAM_SEQUENCE_INTEGRITY")
                        # Validate privacy and packet schema before host persistence.
                        from soc_agent.security_ai.collectors.live_stream import SUMMARY_FIELDS
                        from soc_agent.security_ai.collectors.packet_metadata import packet_metadata

                        stage, api = "STREAM_SCHEMA", "Packet.model_validate/summary_allowlist"
                        if envelope.kind in {"packet", "unsupported"}:
                            packet_metadata(envelope.kind, envelope.data)
                        elif envelope.kind in {"dns", "network"}:
                            if not set(envelope.data) <= SUMMARY_FIELDS:
                                raise ValueError("ZEEK_STREAM_PRIVACY_REJECTED")
                            nested = envelope.data.get("id", {})
                            if not isinstance(nested, dict) or not set(nested) <= {
                                "orig_h",
                                "orig_p",
                                "resp_h",
                                "resp_p",
                            }:
                                raise ValueError("ZEEK_STREAM_PRIVACY_REJECTED")
                        elif envelope.kind == "ready" and envelope.data:
                            raise ValueError("ZEEK_STREAM_PRIVACY_REJECTED")

                        stage, api = "STREAM_ACCOUNTING", "Ledger.accept"
                        ledger_attempted = True
                        ledger.accept(envelope, line)
                        stage, api = "STREAM_PERSIST", "stream.write"
                        output.write(line)
                        sequence = envelope.sequence
                        closed = envelope.kind == "closed"
                        if self.analysis_feed is not None and envelope.kind in {
                            "ready",
                            "counter",
                            "closed",
                        }:
                            self.phase_times[envelope.kind] = time.monotonic()
                            self.phase_wall_ns[envelope.kind] = time.time_ns()
                        if closed:
                            drain_started = drain_started or time.monotonic()
                        if on_line and adapter_failure is None:
                            try:
                                on_line(line)
                            except (OSError, ValueError) as exc:
                                preserve_failure(exc, "ADAPTER", "on_line")
                                adapter_failure = safe_code(exc)
                                failure_detail("ADAPTER", exc)
                                self.stop_requested = True
                                requested = "CONTROLLER_STOP"
                        elif on_line and adapter_failure is not None:
                            discarded_after_adapter_failure += 1
                    stage, api = "STREAM_RECORD_BOUND", "pending_record_length"
                    if len(pending) > 16384:
                        raise ValueError("ZEEK_STREAM_RECORD_BOUND")
            stage, api = "CONTAINER_EXIT", "ZeekProcess.wait/subprocess.wait"
            code = self.process.wait(timeout=5)
            stage, api = "CONTAINER_STOP", "Future.result/StreamProcess._stop_container"
            if stop_future and not stop_future.result(timeout=15):
                raise ValueError("ZEEK_CONTAINER_STOP_UNVERIFIED")
            if adapter_failure is not None:
                raise ValueError(adapter_failure)
            stage, api = "STREAM_FINALIZE", "PENDING_RECORD_VALIDATION"
            if input_pending:
                raise ValueError("ZEEK_PCAP_INPUT_INCOMPLETE")
            if pending:
                raise ValueError("ZEEK_PARTIAL_RECORD_ON_CLOSE")
            if controller_error:
                raise ValueError(controller_error)
            if self.deadline_expired():
                stage, api = "ANALYSIS_BUDGET", "time.monotonic"
                raise ValueError("ZEEK_ANALYSIS_SESSION_DEADLINE")
            stage, api = "STREAM_FINALIZE", "CLOSED_AND_EXIT_VALIDATION"
            if code not in {0, 124} or not closed:
                raise ValueError("ZEEK_CONTAINER_EXIT_UNVERIFIED")
            if not self.file_input:
                verify(self.plan, self.plan.identity)
            reason = termination_reason(ledger.closed, code, requested)
            if not self.file_input and reason == "INPUT_EXHAUSTED":
                reason = "ZEEK_RUNTIME_FAILURE"
                raise ValueError("ZEEK_NATIVE_UNREQUESTED_EXIT")
            stage, api = "CONTAINER_ABSENCE", "StreamProcess._absent"
            self.container_absent = self._absent()
            if not self.container_absent:
                raise ValueError("ZEEK_CONTAINER_CLEANUP_UNVERIFIED")
            self.cleanup_verified = True
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            preserve_failure(exc, stage, api)
            if not ledger_attempted:
                ledger.total_received += 1
                ledger.invalid += 1
                if envelope:
                    ledger.duplicate += int(envelope.sequence <= ledger.sequence)
                    ledger.sequence_gap += int(envelope.sequence > ledger.sequence + 1)
            code = poll_owned()
            error = error or safe_code(exc)
            reason = (
                "CONTROLLER_STOP"
                if controller_error
                else "DOCKER_FAILURE"
                if error in {"ZEEK_DOCKER_START_FAILED", "ZEEK_CONTAINER_CLEANUP_UNVERIFIED"}
                else "ZEEK_RUNTIME_FAILURE"
                if error == "ZEEK_CONTAINER_EXIT_UNVERIFIED"
                else "STREAM_PROTOCOL_FAILURE"
            )
            raise ValueError(error) from exc
        finally:
            selector.close()
            if self.process is not None:
                try:
                    if poll_owned() is None and not cleanup_attempted:
                        cleanup_attempted = True
                        self._stop_container()  # One owned cleanup attempt, never recapture.
                    if stop_future:
                        stop_future.result(timeout=15)
                    if self.supervisor is None and poll_owned() is None:
                        self.process.kill()  # Existing non-supervised subprocess ownership.
                        self.process.wait(timeout=5)
                except (OSError, ValueError, subprocess.SubprocessError) as exc:
                    failure_detail("STOP", exc)
                    error = error or safe_code(exc)
                finally:
                    try:
                        self.process.stdout.close()
                        if self.pcap_input is not None and not self.process.stdin.closed:
                            self.process.stdin.close()
                        if self.analysis_feed is not None:
                            self.process.stderr.close()
                    except OSError as exc:
                        failure_detail("PIPE_CLOSE", exc)
                        error = error or safe_code(exc)
            try:
                self.container_absent = self._absent() if self.process is not None else False
            except (OSError, ValueError, subprocess.SubprocessError) as exc:
                failure_detail("ABSENCE", exc)
                self.container_absent = False
            if self.process is not None and not self.container_absent and not cleanup_attempted:
                try:
                    cleanup_attempted = True
                    self._stop_container()
                    self.container_absent = self._absent()
                except (OSError, ValueError, subprocess.SubprocessError) as exc:
                    failure_detail("EXITED_CONTAINER_CLEANUP", exc)
                    self.container_absent = False
            stopper.shutdown(wait=True)
            # Cleanup proof is independent of stream/process success.
            self.cleanup_verified = self.container_absent
            if self.process is not None:
                code = poll_owned()
            cleanup_failed_late = error is None and not self.cleanup_verified
            if cleanup_failed_late:
                error, reason = "ZEEK_CONTAINER_CLEANUP_UNVERIFIED", "DOCKER_FAILURE"
            write_new(
                self.directory / "exit.json",
                dict(
                    plan_digest=self.plan.identity,
                    exit_code=code,
                    first_failure=first_failure,
                    stream_counters=ledger.diagnostics(),
                    error=error,
                    stream_sha256=file_digest(self.directory / "stream.jsonl"),
                    output_bytes=self.output_bytes,
                    sequence=sequence,
                    closed_observed=closed,
                    stopped=self.stop_requested,
                    elapsed_seconds=time.monotonic() - started,
                    cleanup_verified=self.cleanup_verified,
                    cleanup_failures=cleanup_failures,
                    adapter_failure=adapter_failure,
                    discarded_after_adapter_failure=discarded_after_adapter_failure,
                    container_absent=self.container_absent,
                    container_id=self.container_identity,
                    container_exit_source=(
                        "SUPERVISOR_DOCKER_ENGINE_OWNED_CONTAINER_EXIT_STATE"
                        if self.supervisor is not None
                        else "ATTACHED_DOCKER_RUN_EXIT_STATUS"
                    ),
                    termination_reason=reason,
                    stop_requested_reason=requested,
                    closed_detail=ledger.closed.model_dump(mode="json") if ledger.closed else None,
                    drain_seconds=time.monotonic() - drain_started if drain_started else None,
                    protocol_finalized=ledger.closed is not None and error is None,
                    capture_integrity="UNVERIFIED",
                    native_capture=not self.file_input,
                    analysis_copy_input=self.pcap_input is not None,
                    analysis_deadline_expired=self.deadline_expired(),
                    analysis_phase_times=self.phase_times,
                    analysis_phase_wall_ns=self.phase_wall_ns,
                    exit_digest_scope="PROCESS_AND_PROTOCOL_ONLY_NOT_CAPTURE_QUALITY",
                ),
            )
            if cleanup_failed_late:
                raise ValueError(error)


def rejection(directory: Path, error: object, plan=None):
    """Separate sidecar when the GUI cannot append audit; never rewrite existing evidence."""
    from uuid import uuid4

    from soc_agent.review.persistence.secure_storage import create_private_directory

    if directory.is_symlink() or directory.stat().st_uid != os.getuid():
        return
    if directory.stat().st_mode & 0o077:
        return
    failures = directory / "launcher-rejections"
    create_private_directory(failures)
    if len(list(failures.glob("*.json"))) >= 8:
        return  # Explicit bounded evidence policy; terminal still reports the reviewed code.
    value = dict(
        event="LAUNCHER_REJECTED",
        error=safe_code(error),
        automatic_retry=False,
        session_id=str(plan.session_id) if plan else None,
        plan_digest=plan.identity if plan else None,
        generation=str(plan.controller_generation) if plan else None,
    )
    write_new(failures / (uuid4().hex + ".json"), value)
    # Persist the failure certificate before stop publication can race the Controller.
    # A concurrent stop must never prevent the reviewed launch error from surviving.
    if plan and not (directory / "launch-failure.json").exists():
        write_new(directory / "launch-failure.json", value)
    if plan and not (directory / "stop.request").exists():
        write_new(
            directory / "stop.request",
            dict(
                reason="CONTROLLER_EXIT"
                if safe_code(error) == "ZEEK_CONTROLLER_NOT_RUNNING"
                else "LAUNCH_FAILED",
                session_id=str(plan.session_id),
                plan_digest=plan.identity,
                generation=str(plan.controller_generation),
                actor=process_identity(os.getpid()),
                at_monotonic_ns=time.monotonic_ns(),
            ),
        )


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--session", type=Path, required=True)
    parser.add_argument("--approve", required=True)
    args = parser.parse_args(argv)
    directory, plan = args.session.absolute(), None
    from soc_agent.runtime_lock import exclusive_runtime_lock
    from soc_agent.security_ai.research.environment import read_local

    try:
        try:
            plan = LivePlan.model_validate_json(read_local(directory / "plan.json", 8192))
        except (OSError, ValueError) as error:
            raise ValueError("ZEEK_CONTROLLER_IDENTITY_MISMATCH") from error
        verify(plan, args.approve)
        read_controller(directory, plan)
        if directory.is_symlink() or directory.stat().st_uid != os.getuid():
            raise ValueError("ZEEK_CONTROLLER_IDENTITY_MISMATCH")
        if directory.stat().st_mode & 0o077:
            raise ValueError("ZEEK_CONTROLLER_IDENTITY_MISMATCH")
        with exclusive_runtime_lock(directory / "launcher.lock"):
            if any((directory / name).exists() for name in ("process.json", "launch-failure.json")):
                raise ValueError("ZEEK_SESSION_REUSE_DENIED")
            print("USER-APPROVED ZEEK DIAGNOSTICS ONLY / NATIVE AI BLOCKED / NO AUTOMATIC RETRY")
            StreamProcess(directory, plan).run()
        return 0
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        try:
            rejection(directory, error, plan)
        except (OSError, ValueError):
            print("ZEEK_REJECTION_EVIDENCE_UNAVAILABLE", file=sys.stderr)
        raise ValueError(safe_code(error)) from error


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(safe_code(error), file=sys.stderr)
        raise SystemExit(1) from None
