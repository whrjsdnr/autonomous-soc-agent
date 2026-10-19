"""User-terminal launcher only. GUI never authenticates or starts this module.

Native output is diagnostics, not a capture-integrity attestation. Run only after
reviewing the per-session digest and explicit user approval. Offline fixtures never
call sudo or open an interface.
"""

import argparse
import concurrent.futures
import json
import os
import selectors
import subprocess
import sys
import time
from pathlib import Path

from soc_agent.review.persistence.secure_storage import create_private_file
from soc_agent.security_ai.collectors.finalization import Ledger, termination_reason
from soc_agent.security_ai.collectors.finalization import publish as write_new
from soc_agent.security_ai.collectors.handoff import (
    exchange,
    process_identity,
    read_controller,
    safe_code,
)
from soc_agent.security_ai.collectors.handoff import same_process as same_process
from soc_agent.security_ai.collectors.live_contract import LivePlan, docker_argv, verify
from soc_agent.security_ai.collectors.live_stream import decode
from soc_agent.security_ai.collectors.offline import OfflineZeek, file_digest


class StreamProcess:
    def __init__(self, directory: Path, plan: LivePlan, *, fixture: Path | None = None):
        self.directory, self.plan, self.fixture = directory, plan, fixture
        self.process = None
        self.output_bytes = 0
        self.stop_requested = False
        self.container_name = "soc-zeek-" + plan.session_id.hex
        self.cleanup_verified = False
        self.container_absent = False
        self.container_identity = None

    def stop(self):
        self.stop_requested = True

    def _docker(self, *args):
        prefix = [] if self.fixture else ["sudo", "-n", "--"]
        return subprocess.run(
            prefix + ["docker", *args],
            capture_output=True,
            timeout=7 if args[0] == "stop" else 2,
            check=False,
        )

    def _absent(self):
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

    def run(self, *, on_line=None):
        OfflineZeek().environment()
        argv = docker_argv(self.plan, Path(__file__).parent.absolute(), fixture=self.fixture)
        if not self.fixture:
            print(
                "TERMINAL AUTHENTICATION: scoped Zeek start/stop/cleanup; lo; 300s; "
                "CPU 1; RSS 512MiB; Native AI BLOCKED",
                flush=True,
            )
            verify(self.plan, self.plan.identity)
            self._controller("claim")
            # Terminal stdin/stderr inherited. No password PIPE, environment or storage.
            from soc_agent.cli import terminal_authenticate

            try:
                terminal_authenticate()
            except (OSError, ValueError, subprocess.SubprocessError) as error:
                raise ValueError("ZEEK_AUTH_DENIED_CANCELLED_OR_TIMEOUT") from error
            verify(self.plan, self.plan.identity)
            self._controller()
            argv = ["sudo", "-n", "--", *argv]
        identity = process_identity(os.getpid())
        write_new(
            self.directory / "process.json",
            dict(
                contract="soc-zeek-live-process:v1",
                plan_digest=self.plan.identity,
                generation=str(self.plan.controller_generation),
                launcher=identity,
                image=self.plan.image,
                native_capture=self.fixture is None,
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
        try:
            try:
                self.process = subprocess.Popen(
                    argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
                )
            except OSError as error:
                raise ValueError("ZEEK_DOCKER_START_FAILED") from error
            selector.register(self.process.stdout, selectors.EVENT_READ)
            pending = b""
            stop_sent = False
            controller_checked = 0.0
            with (self.directory / "stream.jsonl").open("ab", buffering=0) as output:
                while True:
                    if (self.directory / "stop.request").exists():
                        self.stop_requested = True
                        tombstone = json.loads((self.directory / "stop.request").read_text())
                        requested = (
                            "USER_STOP"
                            if tombstone.get("reason") == "USER_STOP"
                            else "CONTROLLER_STOP"
                        )
                    now = time.monotonic()
                    if (
                        not self.fixture
                        and not self.stop_requested
                        and now - controller_checked >= 0.5
                    ):
                        try:
                            self._controller()
                        except (OSError, ValueError) as failure:
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
                    if stop_future and stop_future.done() and not stop_future.result():
                        raise ValueError("ZEEK_CONTAINER_STOP_UNVERIFIED")
                    if drain_started and time.monotonic() - drain_started > 10:
                        raise ValueError("ZEEK_STOP_DEADLINE_UNVERIFIED")
                    if time.monotonic() - started > self.plan.duration_seconds + 15:
                        raise ValueError("ZEEK_PROCESS_DEADLINE_EXCEEDED")
                    if not selector.select(0.1):
                        if self.process.poll() is not None:
                            # Drain the pipe even after process exit; EOF is the boundary.
                            continue
                        continue
                    chunk = os.read(self.process.stdout.fileno(), 16384)
                    if not chunk:
                        break
                    self.output_bytes += len(chunk)
                    if self.output_bytes > self.plan.output_bytes:
                        raise ValueError("ZEEK_STREAM_OUTPUT_BUDGET")
                    pending += chunk
                    while b"\n" in pending:
                        line, pending = pending.split(b"\n", 1)
                        line += b"\n"
                        envelope = decode(line)
                        if envelope.sequence != sequence + 1 or closed:
                            raise ValueError("ZEEK_STREAM_SEQUENCE_INTEGRITY")
                        # Validate privacy and packet schema before host persistence.
                        from soc_agent.security_ai.collectors.live_stream import SUMMARY_FIELDS
                        from soc_agent.security_ai.collectors.packet_input import Packet

                        if envelope.kind == "packet":
                            Packet.model_validate(envelope.data)
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

                        ledger.accept(envelope, line)
                        output.write(line)
                        sequence = envelope.sequence
                        closed = envelope.kind == "closed"
                        if closed:
                            drain_started = drain_started or time.monotonic()
                        if on_line:
                            on_line(line)
                    if len(pending) > 16384:
                        raise ValueError("ZEEK_STREAM_RECORD_BOUND")
            code = self.process.wait(timeout=5)
            if stop_future and not stop_future.result(timeout=15):
                raise ValueError("ZEEK_CONTAINER_STOP_UNVERIFIED")
            if pending:
                raise ValueError("ZEEK_PARTIAL_RECORD_ON_CLOSE")
            if controller_error:
                raise ValueError(controller_error)
            if code not in {0, 124} or not closed:
                raise ValueError("ZEEK_CONTAINER_EXIT_UNVERIFIED")
            if not self.fixture:
                verify(self.plan, self.plan.identity)
            reason = termination_reason(ledger.closed, code, requested)
            if not self.fixture and reason == "INPUT_EXHAUSTED":
                reason = "ZEEK_RUNTIME_FAILURE"
                raise ValueError("ZEEK_NATIVE_UNREQUESTED_EXIT")
            self.container_absent = self._absent()
            if not self.container_absent:
                raise ValueError("ZEEK_CONTAINER_CLEANUP_UNVERIFIED")
            self.cleanup_verified = True
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            code = self.process.poll() if self.process else None
            error = safe_code(exc)
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
                if self.process.poll() is None:
                    try:
                        cleanup_attempted = True
                        stopped = (
                            stop_future.result(timeout=15)
                            if stop_future
                            else self._stop_container()
                        )
                    except (OSError, subprocess.SubprocessError):
                        stopped = False
                    finally:
                        if self.process.poll() is None:
                            self.process.kill()
                            self.process.wait(timeout=5)
                        self.process.stdout.close()
                    if not stopped:
                        error = "ZEEK_CONTAINER_STOP_UNVERIFIED"
                        self.cleanup_verified = False
                else:
                    self.process.stdout.close()
            try:
                self.container_absent = self._absent() if self.process is not None else False
            except (OSError, subprocess.SubprocessError):
                self.container_absent = False
            # An exited Docker client does not prove its container has stopped.
            if self.process is not None and not self.container_absent and not cleanup_attempted:
                try:
                    self._stop_container()  # One identity-checked cleanup attempt, never recapture.
                    self.container_absent = self._absent()
                except (OSError, subprocess.SubprocessError):
                    self.container_absent = False
            stopper.shutdown(wait=True)
            # Cleanup proof is independent of stream/process success.
            self.cleanup_verified = self.container_absent
            if self.process is not None:
                code = self.process.poll()
            cleanup_failed_late = error is None and not self.cleanup_verified
            if cleanup_failed_late:
                error, reason = "ZEEK_CONTAINER_CLEANUP_UNVERIFIED", "DOCKER_FAILURE"
            write_new(
                self.directory / "exit.json",
                dict(
                    plan_digest=self.plan.identity,
                    exit_code=code,
                    error=error,
                    stream_sha256=file_digest(self.directory / "stream.jsonl"),
                    output_bytes=self.output_bytes,
                    sequence=sequence,
                    closed_observed=closed,
                    stopped=self.stop_requested,
                    elapsed_seconds=time.monotonic() - started,
                    cleanup_verified=self.cleanup_verified,
                    container_absent=self.container_absent,
                    container_id=self.container_identity,
                    container_exit_source="ATTACHED_DOCKER_RUN_EXIT_STATUS",
                    termination_reason=reason,
                    stop_requested_reason=requested,
                    closed_detail=ledger.closed.model_dump(mode="json") if ledger.closed else None,
                    drain_seconds=time.monotonic() - drain_started if drain_started else None,
                    protocol_finalized=ledger.closed is not None and error is None,
                    capture_integrity="UNVERIFIED",
                    native_capture=self.fixture is None,
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
    if plan and not (directory / "launch-failure.json").exists():
        write_new(directory / "launch-failure.json", value)


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
