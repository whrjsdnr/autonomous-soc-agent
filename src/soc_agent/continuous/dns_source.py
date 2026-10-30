"""Continuous DNS adapter over the existing peer-verified, capability-dropped helper.

Preparing metadata never authorizes a helper. A reviewed launcher must enter the
target Namespace and start the fixed helper with temporary CAP_NET_RAW. Neither
this ordinary receiver nor the GUI can install, authenticate or start it.
"""

import asyncio
import hashlib
import json
import os
import select
import socket
import sys
import threading
import time
from pathlib import Path
from typing import Literal
from uuid import uuid4

from pydantic import Field

from soc_agent.review.persistence.secure_storage import (
    create_private_directory,
    create_private_file,
    validate_directory,
    validate_file,
)
from soc_agent.security_ai.external.models import content_digest_payload
from soc_agent.security_ai.operational.network_capture.capture import (
    CaptureUnavailable,
    interface_identity,
)
from soc_agent.security_ai.operational.network_capture.live_helper import process_start
from soc_agent.security_ai.operational.network_capture.stream_session import (
    StreamPolicy,
    StreamSession,
)
from soc_agent.security_ai.operational.network_capture.stream_transport import StreamMessage
from soc_agent.security_ai.operational.network_capture.total_transport import TotalCapture
from soc_agent.security_ai.research.environment import read_local

MODULE = "soc_agent.continuous.dns_helper"


class DNSPolicy(StreamPolicy):
    """Separate candidate; the Diagnostic/Total 300-second contract is unchanged."""

    contract: Literal["soc-continuous-dns-metadata-policy:v1"] = (
        "soc-continuous-dns-metadata-policy:v1"
    )
    seconds: int = Field(default=3600, ge=1, le=3600, strict=True)
    frames_per_second: Literal[16] = 16
    burst_frames: Literal[64] = 64
    transport_capacity: Literal[32] = 32


class DNSSession(StreamSession):
    contract: Literal["soc-continuous-dns-session:v1"] = "soc-continuous-dns-session:v1"
    policy: DNSPolicy
    namespace: str = Field(pattern=r"^net:\[[1-9][0-9]*\]$")


def bundle() -> dict[str, str]:
    root = Path(__file__).parents[1]
    files = [
        "continuous/dns_source.py",
        "continuous/dns_helper.py",
        "realtime/source_identity.py",
    ] + [
        "security_ai/operational/network_capture/" + name
        for name in (
            "stream_helper.py",
            "stream_session.py",
            "live_helper.py",
            "capture.py",
            "permissions.py",
            "parsing.py",
            "models.py",
            "helper_transport.py",
            "stream_transport.py",
            "total_transport.py",
        )
    ]
    return {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in files}


def expected_interface(namespace: str) -> str:
    """Expected identity only; load() must observe the actual approved target."""
    return content_digest_payload(
        dict(
            namespace=int(namespace[5:-1]),
            boot_digest=hashlib.sha256(
                Path("/proc/sys/kernel/random/boot_id").read_text().strip().encode()
            ).hexdigest(),
            interface="lo",
            ifindex=1,
            address_digest=hashlib.sha256(
                Path("/sys/class/net/lo/address").read_text().strip().encode()
            ).hexdigest(),
        )
    )


def prepare(directory: Path, *, namespace: str, python: Path, seconds: int = 3600) -> DNSSession:
    if os.getuid() == 0:
        raise ValueError("CONTINUOUS_DNS_PREPARE_REQUIRES_ORDINARY_USER")
    session = DNSSession(
        session_id=uuid4(),
        uid=os.getuid(),
        gid=os.getgid(),
        namespace=namespace,
        interface_id=expected_interface(namespace),
        policy=DNSPolicy(seconds=seconds),
        python=str(python.absolute()),
        python_sha256=hashlib.sha256(python.read_bytes()).hexdigest(),
        code_sha256=bundle(),
    )
    create_private_directory(directory, exist_ok=False)
    create_private_file(directory / "helper.lock")
    create_private_file(directory / "session.json")
    (directory / "session.json").write_text(session.model_dump_json())
    return session


def inspect(directory: Path, *, namespace: str, sha256: str | None = None) -> DNSSession:
    validate_directory(directory)
    validate_file(directory / "helper.lock")
    validate_file(directory / "session.json")
    body = read_local(directory / "session.json", 65536)
    if sha256 is not None and hashlib.sha256(body).hexdigest() != sha256:
        raise ValueError("CONTINUOUS_DNS_SESSION_SHA")
    session = DNSSession.model_validate_json(body)
    if (
        session.namespace != namespace
        or session.uid != os.getuid()
        or session.gid != os.getgid()
        or session.code_sha256 != bundle()
        or hashlib.sha256(Path(session.python).read_bytes()).hexdigest() != session.python_sha256
    ):
        raise ValueError("CONTINUOUS_DNS_SESSION_BINDING")
    return session


def load(directory: Path) -> DNSSession:
    namespace = os.readlink("/proc/self/ns/net")
    session = inspect(directory, namespace=namespace)
    if (
        interface_identity("lo") != session.interface_id
        or hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest() != session.python_sha256
    ):
        raise ValueError("CONTINUOUS_DNS_TARGET_OR_INTERPRETER_BINDING")
    return session


class DNSMessage(StreamMessage):
    elapsed_seconds: float | None = Field(default=None, ge=0, le=3602, allow_inf_nan=False)


def write_cleanup(directory: Path, value: dict) -> str:
    """Immutable receipt, acknowledged only after file and directory durability."""
    body = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    if len(body) > 65536:
        raise ValueError("CONTINUOUS_DNS_CLEANUP_EVIDENCE_BOUND")
    fd = os.open(
        directory / "cleanup.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
    )
    with os.fdopen(fd, "wb") as stream:
        stream.write(body)
        stream.flush()
        os.fsync(stream.fileno())
    parent = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)
    return hashlib.sha256(body).hexdigest()


class DNSCapture(TotalCapture):
    helper_module = MODULE

    def __init__(self, directory, session):
        super().__init__(directory, session)
        self.stop_requested_unix = None
        self.stop_send_error = None
        self.failure_stop_error = None
        self.failure_stop_elapsed_seconds = None
        self.quarantined_packets = 0
        self.stop_lock = threading.Lock()

    def process_observation(self):
        """PID existence is independent of heartbeat and is never an exit-code receipt."""
        ready = self.ready
        value = dict(
            observed_at_unix=time.time(),
            pid=ready.pid if ready else None,
            expected_start=ready.process_start if ready else None,
            state="NOT_OBSERVED",
            exit_code=None,
            namespace="UNKNOWN",
        )
        if ready is None or ready.pid is None or ready.process_start is None:
            return value
        try:
            start = process_start(ready.pid)
            value["observed_start"] = start
            if start != ready.process_start:
                value["state"] = "PID_REUSED_OR_IDENTITY_CHANGED"
                return value
            status = Path(f"/proc/{ready.pid}/stat").read_text().rsplit(")", 1)[1].split()[0]
            value["state"] = "EXITED_ZOMBIE" if status in {"Z", "X"} else "ALIVE"
            try:
                value["namespace"] = os.readlink(f"/proc/{ready.pid}/ns/net")
            except OSError:
                pass  # Observation unavailable, never a namespace identity grant.
        except FileNotFoundError:
            value["state"] = "EXITED"
        except (OSError, ValueError):
            value["state"] = "UNKNOWN"
        return value

    def request_stop(self):
        with self.stop_lock:
            if self.stop_send_error is not None:
                raise CaptureUnavailable(self.stop_send_error)
            if self.stop_requested_unix is None and self.channel is not None:
                # The reader can observe CLOSED before send() returns. Record
                # intent first; a failed send remains an explicit failed attempt.
                self.stop_requested_unix = time.time()
                try:
                    super().request_stop()
                except CaptureUnavailable as error:
                    self.stop_send_error = str(error)
                    raise

    def cleanup_ack_verified(self):
        """Only owned capture closure; a failed stream remains inadmissible."""
        end = self.terminal
        return bool(
            self.reader_error == "HELPER_HEARTBEAT_OR_PROCESS_STALE"
            and self.failure_stop_error is None
            and self.reader_diagnostic_error is None
            and self.counter_issue is None
            and end is not None
            and end.error is None
            and end.capabilities == self.ready.capabilities
            and end.counter_status == "COUNTER_VERIFIED"
            and end.capture_drops_total == 0
            and end.sent_packets == self.sequence
            and self.sequence == self.delivered + self.packets.qsize() + self.quarantined_packets
            and end.received_frames is not None
            and self.sequence <= end.received_frames <= self.session.max_packets
            and end.elapsed_seconds is not None
            and end.elapsed_seconds <= self.session.seconds
        )

    def shutdown_failed_reader(self):
        # A protocol/identity/counter violation still disconnects immediately.
        # After a liveness failure, STOP first and drain only closure evidence.
        # This is not a retry: no packet is delivered or capture reopened.
        if self.reader_error != "HELPER_HEARTBEAT_OR_PROCESS_STALE":
            return super().shutdown_failed_reader()
        began = time.monotonic()
        try:
            self.request_stop()
            deadline = time.monotonic() + 5
            records = 0
            while records < 64 and time.monotonic() < deadline:
                readable, _, _ = select.select([self.channel], [], [], 0.05)
                if not readable:
                    continue
                message = self.message()
                records += 1
                with self.reader_lock:
                    packet = self._receive_record(message)
                    if packet is not None:
                        self.quarantined_packets += 1
                        self.seals.pop()  # Validated sequence, never admitted/delivered.
                    if self.terminal is not None:
                        return
            self.failure_stop_error = "CONTINUOUS_DNS_FAILURE_STOP_ACK_MISSING"
        except (OSError, ValueError, RuntimeError):
            self.failure_stop_error = "CONTINUOUS_DNS_FAILURE_STOP_ACK_INVALID"
        finally:
            self.failure_stop_elapsed_seconds = time.monotonic() - began
            super().shutdown_failed_reader()

    def extra_metrics(self):
        return super().extra_metrics() | dict(
            stop_requested_unix=self.stop_requested_unix,
            stop_send_error=self.stop_send_error,
            failure_stop_error=self.failure_stop_error,
            failure_stop_elapsed_seconds=self.failure_stop_elapsed_seconds,
            quarantined_after_failure=self.quarantined_packets,
            helper_process=self.process_observation(),
            cleanup_scope="OWNED_DNS_CAPTURE_AND_TRANSPORT_NOT_GLOBAL_KERNEL",
            heartbeat_status=(
                "ENDED_AFTER_STREAM_FAILURE"
                if self.terminal is not None and self.reader_error
                else "ENDED_AUTHENTICATED_CLOSED"
                if self.terminal is not None
                else "FAILED_ADMISSION_CLEANUP_PENDING"
                if self.reader_error is not None
                else "NOT_STARTED"
                if self.ready is None
                else "DELAYED_NOT_PROOF_OF_PROCESS_EXIT"
                if self.last_heartbeat is None or time.monotonic() - self.last_heartbeat > 2
                else "CURRENT"
            ),
        )

    def message(self):
        body, _, flags, _ = self.channel.recvmsg(8192)
        if flags & socket.MSG_TRUNC or not body:
            raise CaptureUnavailable("HELPER_DISCONNECTED_OR_RECORD_LIMIT")
        value = DNSMessage.model_validate_json(body)
        if value.session_id != self.session.session_id:
            raise CaptureUnavailable("HELPER_SESSION_FORGERY")
        return value


class DNSProducer:
    def __init__(self, directory: Path, sha256: str):
        self.session = load(directory)
        inspect(directory, namespace=self.session.namespace, sha256=sha256)
        if any(
            (directory / name).exists()
            for name in (
                "verified-ready.json",
                "verified-closed.json",
                "transport-failure.json",
                "cleanup.json",
            )
        ):
            raise ValueError("CONTINUOUS_DNS_SESSION_ALREADY_ADMITTED_REVIEW_REQUIRED")
        self.capture = DNSCapture(directory, self.session)
        self.state = "WAITING_APPROVED_HELPER"
        self.received = 0
        self.cleanup = "NOT_STARTED"
        self.last_error = None
        self.last_error_observed_unix = None
        self.cleanup_error = None
        self.cleanup_evidence_sha256 = None
        self.cleanup_scope = "OWNED_DNS_CAPTURE_AND_TRANSPORT_NOT_GLOBAL_KERNEL"
        self.helper_cleanup = "UNVERIFIED"
        self.sequence = 0
        self._close_lock = asyncio.Lock()
        self._owner_stop_requested = False
        self._handshake_task = None

    @property
    def origin(self):
        return "REAL_NATIVE_DNS_METADATA" if self.capture.ready is not None else "UNVERIFIED"

    @property
    def policy_duration_completed(self) -> bool:
        """Allow a proved finite completion, without extending DNS authority.

        stream_helper reserves its final second for socket closure. Early exits,
        errors and missing durable owned-cleanup evidence remain failures.
        """
        terminal = self.capture.terminal
        return bool(
            terminal is not None
            and terminal.elapsed_seconds is not None
            and self.session.policy.seconds - 1
            <= terminal.elapsed_seconds
            <= self.session.policy.seconds + 2
            and terminal.error is None
            and self.capture.completion_verified()
            and self.state == "STOPPED"
            and self.cleanup == self.helper_cleanup == "VERIFIED"
            and self.cleanup_evidence_sha256 is not None
            and self.last_error is None
            and self.cleanup_error is None
        )

    @property
    def snapshot(self):
        return dict(
            state=self.state,
            origin=self.origin,
            policy_duration_completed=self.policy_duration_completed,
            namespace=self.session.namespace,
            session=str(self.session.session_id),
            packets=self.received,
            cleanup=self.cleanup,
            listener_ready=self.capture.listener_ready(),
            heartbeat_age_seconds=(
                time.monotonic() - self.capture.last_heartbeat
                if self.capture.last_heartbeat is not None
                else None
            ),
            last_error=self.last_error,
            last_error_observed_unix=self.last_error_observed_unix,
            cleanup_error=self.cleanup_error,
            cleanup_evidence_sha256=self.cleanup_evidence_sha256,
            dns9="INCOMPLETE_TRAINING_EXTRACTION_CONTRACT",
            names_retained=False,
            capture_quality="PEER_VERIFIED_AF_PACKET_METADATA_NOT_TCX_ATTESTATION",
            **self.capture.extra_metrics(),
        ) | dict(cleanup_scope=self.cleanup_scope, helper_cleanup=self.helper_cleanup)

    async def events(self):
        if self._owner_stop_requested:
            return
        handshake = asyncio.create_task(asyncio.to_thread(self.capture.handshake))
        self._handshake_task = handshake
        try:
            await asyncio.shield(handshake)
            self.capture.start_reader()
            self.state = "RUNNING"
            while True:
                packet = self.capture.receive()
                if packet is not None:
                    self.received += 1
                    self.sequence = self.capture.last_seal[0]
                    if 53 not in (packet.source_port, packet.destination_port):
                        raise ValueError("CONTINUOUS_DNS_NON_DNS_PACKET")
                    yield packet
                elif self.capture.terminal is not None and self.capture.packets.empty():
                    if not self.capture.completion_verified():
                        self.cleanup = "UNVERIFIED"
                        raise ValueError("CONTINUOUS_DNS_FINAL_COUNTERS_UNVERIFIED")
                    self.cleanup = "PENDING_OWNED_CLOSURE"
                    return
                else:
                    await asyncio.sleep(0.02)
        except (ValueError, OSError, RuntimeError) as error:
            if self._cancelled_handshake(error):
                return
            if self.last_error is None:
                self.last_error = type(error).__name__ + ":" + str(error)
                self.last_error_observed_unix = time.time()
            self.state = "FAILED"
            raise
        finally:
            try:
                await self.close()
            except (ValueError, OSError, RuntimeError) as error:
                self.cleanup = "UNVERIFIED"
                self.cleanup_error = type(error).__name__ + ":" + str(error)
                if self.last_error is None:
                    raise
            finally:
                await asyncio.gather(handshake, return_exceptions=True)

    async def request_stop(self):
        self._owner_stop_requested = True
        if self.capture.ready is None:
            await self.close()
            return
        if self.capture.terminal is None:
            self.capture.request_stop()
        deadline = time.monotonic() + 5
        while self.capture.terminal is None:
            if self.capture.reader_failed():
                thread = self.capture.reader_thread
                if self.capture.reader_error == "HELPER_HEARTBEAT_OR_PROCESS_STALE" and thread:
                    await asyncio.to_thread(thread.join, max(0, deadline - time.monotonic()))
                if self.capture.terminal is None:
                    raise ValueError("CONTINUOUS_DNS_STOP_ACK_MISSING")
                return
            if time.monotonic() >= deadline:
                raise ValueError("CONTINUOUS_DNS_STOP_ACK_MISSING")
            await asyncio.sleep(0.02)

    def _cancelled_handshake(self, error):
        return bool(
            self._owner_stop_requested
            and self.capture.closed.is_set()
            and self.capture.ready is None
            and isinstance(error, CaptureUnavailable)
            and str(error) == "HELPER_LISTENER_CLOSED"
        )

    async def close(self):
        async with self._close_lock:
            if self.capture.closed.is_set():
                return
            thread = self.capture.reader_thread
            if thread is not None and self.capture.reader_error is not None:
                # Do not destroy the transport while its bounded failure STOP is
                # collecting the final receipt. Never hold the event loop here.
                await asyncio.to_thread(thread.join, 5.1)
            protocol_closed = (
                self.capture.terminal is not None and self.capture.completion_verified()
            ) or self.capture.cleanup_ack_verified()
            self.cleanup = "UNVERIFIED"
            await asyncio.to_thread(self.capture.close, reason="CONTINUOUS_DNS_OWNER_STOP")
            handshake_error = None
            if self._handshake_task is not None:
                # Closing the listener unblocks accept. Join that owned handshake
                # before publishing cleanup, including a peer racing with Stop.
                outcome = await asyncio.wait_for(
                    asyncio.gather(self._handshake_task, return_exceptions=True), 2.1
                )
                if isinstance(outcome[0], BaseException):
                    handshake_error = outcome[0]
            cancelled_before_admission = bool(
                self._owner_stop_requested
                and self.capture.ready is None
                and self.capture.channel is None
                and self.capture.reader_error is None
                and self.last_error is None
                and (handshake_error is None or self._cancelled_handshake(handshake_error))
            )
            process = self.capture.process_observation()
            # CLOSED proves capture.close() returned in the pinned helper. Its
            # process exit is independently observed, without sending any signal.
            deadline = time.monotonic() + 1
            while protocol_closed and process["state"] == "ALIVE" and time.monotonic() < deadline:
                await asyncio.sleep(0.01)
                process = self.capture.process_observation()
            stopped = process["state"] in {
                "EXITED",
                "EXITED_ZOMBIE",
                "PID_REUSED_OR_IDENTITY_CHANGED",
            }
            local_closed = (
                self.capture.listener.fileno() == -1
                and (self.capture.channel is None or self.capture.channel.fileno() == -1)
                and (thread is None or not thread.is_alive())
            )
            verified = bool(
                local_closed
                and self.capture.stop_send_error is None
                and ((protocol_closed and stopped) or cancelled_before_admission)
            )
            if self.last_error is None and self.capture.reader_error:
                self.last_error = "CaptureUnavailable:" + self.capture.reader_error
                self.last_error_observed_unix = self.capture.reader_failure_observed_unix
            self.state = "FAILED" if self.last_error else "STOPPED"
            proof = dict(
                contract="soc-continuous-dns-owned-cleanup:v1",
                session=str(self.session.session_id),
                namespace=self.session.namespace,
                observed_at_unix=time.time(),
                first_error=self.last_error or self.capture.reader_error,
                capture_admission="DENIED_AFTER_FAILURE"
                if self.capture.reader_error
                else "UNCHANGED",
                stop_requested_unix=self.capture.stop_requested_unix,
                stop_send_error=self.capture.stop_send_error,
                closed_observed_unix=self.capture.terminal_observed_unix,
                authenticated_closed=bool(protocol_closed),
                stream_completion_verified=self.capture.completion_verified(),
                closed_sha256=(
                    hashlib.sha256(self.capture.terminal.model_dump_json().encode()).hexdigest()
                    if self.capture.terminal is not None
                    else None
                ),
                helper_process=process,
                listener_closed=self.capture.listener.fileno() == -1,
                channel_closed=self.capture.channel is None or self.capture.channel.fileno() == -1,
                reader_joined=thread is None or not thread.is_alive(),
                global_kernel_cleanup="UNKNOWN",
                cleanup_scope="LOCAL_DNS_LISTENER_ONLY_NO_AUTHENTICATED_HELPER"
                if cancelled_before_admission
                else "OWNED_DNS_CAPTURE_AND_TRANSPORT_NOT_GLOBAL_KERNEL",
                helper_cleanup="NOT_OBSERVED_NO_AUTHENTICATED_HELPER"
                if cancelled_before_admission
                else "VERIFIED"
                if protocol_closed and stopped
                else "UNVERIFIED",
                handshake_joined=self._handshake_task is None or self._handshake_task.done(),
                quarantined_packets=self.capture.quarantined_packets,
                failure_stop_error=self.capture.failure_stop_error,
                failure_stop_elapsed_seconds=self.capture.failure_stop_elapsed_seconds,
                transport_diagnostic_error=self.capture.reader_diagnostic_error,
                cleanup="VERIFIED" if verified else "UNVERIFIED",
            )
            commit = asyncio.create_task(
                asyncio.to_thread(write_cleanup, self.capture.directory, proof)
            )
            try:
                self.cleanup_evidence_sha256 = await asyncio.shield(commit)
            except asyncio.CancelledError:
                # Join the owned writer; cancellation cannot leave a late receipt
                # being published after its owner reports shutdown.
                await asyncio.gather(commit, return_exceptions=True)
                self.state = "FAILED"
                self.cleanup_error = "CANCELLED_DURING_CLEANUP_COMMIT"
                raise
            except (OSError, ValueError):
                self.state = "FAILED"
                raise
            self.cleanup = proof["cleanup"]
            self.cleanup_scope = proof["cleanup_scope"]
            self.helper_cleanup = proof["helper_cleanup"]
