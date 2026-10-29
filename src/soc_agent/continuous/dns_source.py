"""Continuous DNS adapter over the existing peer-verified, capability-dropped helper.

Preparing metadata never authorizes a helper. A reviewed launcher must enter the
target Namespace and start the fixed helper with temporary CAP_NET_RAW. Neither
this ordinary receiver nor the GUI can install, authenticate or start it.
"""

import asyncio
import hashlib
import os
import socket
import sys
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
from soc_agent.security_ai.operational.network_capture.capture import interface_identity
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
    files = ["continuous/dns_source.py", "continuous/dns_helper.py"] + [
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


class DNSCapture(TotalCapture):
    helper_module = MODULE

    def message(self):
        body, _, flags, _ = self.channel.recvmsg(8192)
        if flags & socket.MSG_TRUNC or not body:
            raise ValueError("HELPER_DISCONNECTED_OR_RECORD_LIMIT")
        value = DNSMessage.model_validate_json(body)
        if value.session_id != self.session.session_id:
            raise ValueError("HELPER_SESSION_FORGERY")
        return value


class DNSProducer:
    def __init__(self, directory: Path, sha256: str):
        self.session = load(directory)
        inspect(directory, namespace=self.session.namespace, sha256=sha256)
        self.capture = DNSCapture(directory, self.session)
        self.state = "WAITING_APPROVED_HELPER"
        self.received = 0
        self.cleanup = "NOT_STARTED"
        self.last_error = None
        self.cleanup_error = None
        self.sequence = 0
        self._close_lock = asyncio.Lock()

    @property
    def origin(self):
        return "REAL_NATIVE_DNS_METADATA" if self.capture.ready is not None else "UNVERIFIED"

    @property
    def snapshot(self):
        return dict(
            state=self.state,
            origin=self.origin,
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
            cleanup_error=self.cleanup_error,
            dns9="INCOMPLETE_TRAINING_EXTRACTION_CONTRACT",
            names_retained=False,
            capture_quality="PEER_VERIFIED_AF_PACKET_METADATA_NOT_TCX_ATTESTATION",
            **self.capture.extra_metrics(),
        )

    async def events(self):
        handshake = asyncio.create_task(asyncio.to_thread(self.capture.handshake))
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
                    self.cleanup = (
                        "VERIFIED" if self.capture.completion_verified() else "UNVERIFIED"
                    )
                    if self.cleanup != "VERIFIED":
                        raise ValueError("CONTINUOUS_DNS_FINAL_COUNTERS_UNVERIFIED")
                    return
                else:
                    await asyncio.sleep(0.02)
        except (ValueError, OSError, RuntimeError) as error:
            self.last_error = type(error).__name__ + ":" + str(error)
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
        if self.capture.ready is None:
            await self.close()
            return
        if self.capture.terminal is None:
            self.capture.request_stop()
        deadline = time.monotonic() + 5
        while self.capture.terminal is None:
            if self.capture.reader_failed() or time.monotonic() >= deadline:
                raise ValueError("CONTINUOUS_DNS_STOP_ACK_MISSING")
            await asyncio.sleep(0.02)

    async def close(self):
        async with self._close_lock:
            if self.capture.closed.is_set():
                return
            if self.capture.terminal is not None and self.capture.completion_verified():
                self.cleanup = "VERIFIED"
            await asyncio.to_thread(self.capture.close, reason="CONTINUOUS_DNS_OWNER_STOP")
            self.state = "FAILED" if self.last_error else "STOPPED"
