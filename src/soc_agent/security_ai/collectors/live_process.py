"""User-terminal launcher only. GUI never authenticates or starts this module.

Native output is diagnostics, not a capture-integrity attestation. Run only after
reviewing the per-session digest and explicit user approval. Offline fixtures never
call sudo or open an interface.
"""

import argparse
import json
import os
import selectors
import subprocess
import sys
import time
from pathlib import Path

from soc_agent.review.persistence.secure_storage import create_private_file
from soc_agent.security_ai.collectors.live_contract import LivePlan, docker_argv, verify
from soc_agent.security_ai.collectors.live_stream import decode
from soc_agent.security_ai.collectors.offline import OfflineZeek, file_digest
from soc_agent.security_ai.research.service import write_new


def process_identity(pid: int) -> dict:
    stat = Path(f"/proc/{pid}/stat").read_text()
    return dict(pid=pid, start_ticks=stat.rsplit(")", 1)[1].split()[19])


def same_process(identity: dict) -> bool:
    try:
        return process_identity(identity["pid"]) == identity
    except (OSError, ValueError, KeyError):
        return False


class StreamProcess:
    def __init__(self, directory: Path, plan: LivePlan, *, fixture: Path | None = None):
        self.directory, self.plan, self.fixture = directory, plan, fixture
        self.process = None
        self.output_bytes = 0
        self.stop_requested = False
        self.container_name = "soc-zeek-" + plan.session_id.hex
        self.cleanup_verified = False

    def stop(self):
        self.stop_requested = True

    def _stop_container(self):
        prefix = [] if self.fixture else ["sudo", "-n", "--"]
        p = subprocess.run(
            prefix + ["docker", "stop", "--time=2", self.container_name],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=8,
            check=False,
        )
        return p.returncode == 0

    def _controller(self):
        from soc_agent.security_ai.research.environment import read_local

        identity = json.loads(read_local(self.directory / "controller.json", 8192))
        if not same_process(identity) or (self.directory / "stop.request").exists():
            raise ValueError("ZEEK_CONTROLLER_NOT_READY_OR_SESSION_STOPPED")

    def run(self, *, on_line=None):
        OfflineZeek().environment()
        argv = docker_argv(self.plan, Path(__file__).parent.absolute(), fixture=self.fixture)
        if not self.fixture:
            verify(self.plan, self.plan.identity)
            self._controller()
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
                launcher=identity,
                image=self.plan.image,
                native_capture=self.fixture is None,
            ),
        )
        started = time.monotonic()
        create_private_file(self.directory / "stream.jsonl")
        error, sequence, closed, code = None, 0, False, None
        selector = selectors.DefaultSelector()
        try:
            self.process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            selector.register(self.process.stdout, selectors.EVENT_READ)
            pending = b""
            stop_sent = False
            with (self.directory / "stream.jsonl").open("ab", buffering=0) as output:
                while True:
                    if (self.directory / "stop.request").exists():
                        self.stop_requested = True
                    expired = time.monotonic() - started > self.plan.duration_seconds + 5
                    if (self.stop_requested or expired) and not stop_sent:
                        stop_sent = True
                        if not self._stop_container():
                            raise ValueError("ZEEK_CONTAINER_STOP_UNVERIFIED")
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
                        elif envelope.kind == "closed" and not set(envelope.data) <= {
                            "pkts_recvd",
                            "pkts_dropped",
                            "pkts_link",
                            "bytes_recvd",
                        }:
                            raise ValueError("ZEEK_STREAM_PRIVACY_REJECTED")
                        output.write(line)
                        sequence = envelope.sequence
                        closed = envelope.kind == "closed"
                        if on_line:
                            on_line(line)
                    if len(pending) > 16384:
                        raise ValueError("ZEEK_STREAM_RECORD_BOUND")
            code = self.process.wait(timeout=5)
            if pending:
                raise ValueError("ZEEK_PARTIAL_RECORD_ON_CLOSE")
            if code not in {0, 124} or not closed:
                raise ValueError("ZEEK_PROCESS_EXIT_OR_CLOSED_UNVERIFIED")
            if not self.fixture:
                verify(self.plan, self.plan.identity)
            self.cleanup_verified = True  # --rm exit; no automatic restart.
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            code = self.process.poll() if self.process else None
            error = str(exc) if str(exc).startswith("ZEEK_") else "ZEEK_PROCESS_FAILED"
            raise ValueError(error) from exc
        finally:
            selector.close()
            if self.process is not None:
                if self.process.poll() is None:
                    try:
                        stopped = self._stop_container()
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
                    capture_integrity="UNVERIFIED",
                    native_capture=self.fixture is None,
                    exit_digest_scope="PROCESS_AND_PROTOCOL_ONLY_NOT_CAPTURE_QUALITY",
                ),
            )


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--session", type=Path, required=True)
    parser.add_argument("--approve", required=True)
    args = parser.parse_args(argv)
    directory = args.session.absolute()
    from soc_agent.security_ai.research.environment import read_local

    plan = LivePlan.model_validate_json(read_local(directory / "plan.json", 8192))
    verify(plan, args.approve)
    from soc_agent.runtime_lock import exclusive_runtime_lock

    if directory.is_symlink() or directory.stat().st_uid != os.getuid():
        raise ValueError("ZEEK_SESSION_OWNER_INVALID")
    if directory.stat().st_mode & 0o077:
        raise ValueError("ZEEK_SESSION_PERMISSION_INVALID")
    with exclusive_runtime_lock(directory / "launcher.lock"):
        if any(
            (directory / name).exists()
            for name in ("process.json", "launch-failure.json", "stop.request")
        ):
            raise ValueError("ZEEK_SESSION_REUSE_DENIED")
        print("USER-APPROVED ZEEK DIAGNOSTICS ONLY / NATIVE AI BLOCKED / NO AUTOMATIC RETRY")
        try:
            StreamProcess(directory, plan).run()
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            code = str(error)
            import re

            if not re.fullmatch(r"ZEEK_[A-Z0-9_]{1,110}", code):
                code = "ZEEK_MANUAL_LAUNCH_FAILED"
            write_new(
                directory / "launch-failure.json",
                dict(
                    plan_digest=plan.identity,
                    error=code,
                    automatic_retry=False,
                ),
            )
            raise
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, subprocess.SubprocessError):
        print("ZEEK_MANUAL_LAUNCH_FAILED_CHECK_SESSION", file=sys.stderr)
        raise SystemExit(1) from None
