"""Opt-in ordinary-UID late DNS witness; never authenticates, attaches or retries.

The Supervisor owns the initial UDP/TCP Sidecar and normal STOP/Cleanup. This
module only schedules one additional fixed local UDP query after Sidecar CLOSED.
Scheduling is not capture/Flow/eligibility evidence. Legacy admission stays intact.
"""

import hashlib
import os
import socket
import struct
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field

from soc_agent.security_ai.ebpf_native.contracts import local_controller
from soc_agent.security_ai.ebpf_tc.reassessment import Artifact, Contract, Hash, Identity, held_json

SECOND = 1_000_000_000
QUESTION = b"\x0bnative-0516\x09localhost\x00\x00\x01\x00\x01"


class Scenario(Contract):
    namespace: Literal["net:[4026531833]"] = "net:[4026531833]"
    interface: Literal["lo"] = "lo"
    hook: Literal["INGRESS"] = "INGRESS"
    endpoint: Literal["127.0.0.53:53"] = "127.0.0.53:53"
    qname: Literal["native-0516.localhost."] = "native-0516.localhost."
    qtype: Literal["A"] = "A"
    udp_queries: Literal[2] = 2
    tcp_queries: Literal[1] = 1
    max_events: Literal[4096] = 4096
    duration_seconds: Literal[300] = 300
    queue: Literal[32] = 32
    address_space_mib: Literal[256] = 256
    cpu_seconds: Literal[20] = 20
    admission_ms: Literal[50] = 50
    reorder_ms: Literal[10] = 10
    checkpoint_bytes: Literal[16384] = 16384
    sidecar_seconds: Literal[10] = 10
    witness_delay_seconds: Literal[35] = 35
    stop_delay_seconds: Literal[45] = 45
    capture_plan_seconds: Literal[60] = 60


class TrafficReceipt(Contract):
    contract: Literal["SOC_R2_TRAFFIC_APPROVAL_V1"] = "SOC_R2_TRAFFIC_APPROVAL_V1"
    decision: Literal["APPROVED"]
    approver: Identity
    human_reference_sha: Hash
    session: Identity
    claim_path: Annotated[str, Field(min_length=1, max_length=4096)]
    artifact: Artifact
    scenario: Scenario
    implementation_sha: Hash
    issued_at: int = Field(ge=0)
    expires_at: int = Field(gt=0)
    attempts: Literal[1] = 1
    retries: Literal[0] = 0


@dataclass(frozen=True)
class LaunchApproval:
    receipt_file: Path
    receipt_sha: str
    session: str
    artifact: Artifact
    # Mandatory exclusive per-attempt claim file; never overwrite after failure.
    claim_file: Path
    campaign_directory: Path | None = None


class R2Launcher:
    def __init__(self, approval: LaunchApproval):
        self.approval = approval
        self.receipt = TrafficReceipt.model_validate(
            held_json(approval.receipt_file, approval.receipt_sha)
        )
        self._check()
        self.claimed = False
        self.started_ns: int | None = None
        self.previous_ns = -1
        self.tcp_closed_ns: int | None = None
        self.witness: dict | None = None
        self.attempted = False
        self.stop_reason: str | None = None

    def _check(self) -> None:
        receipt = self.receipt
        if (
            receipt.claim_path != str(self.approval.claim_file.absolute())
            or receipt.session != self.approval.session
            or receipt.artifact != self.approval.artifact
            or receipt.implementation_sha != hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
            or not receipt.issued_at <= time.time() < receipt.expires_at
        ):
            raise ValueError("R2_APPROVAL_BINDING_OR_EXPIRY")

    def start(self, attached_ns: int) -> None:
        self._check()
        if self.started_ns is not None or type(attached_ns) is not int or attached_ns < 0:
            raise ValueError("R2_START_STATE")
        if not self.claimed:
            self.claim()
        self.started_ns = attached_ns

    def claim(self) -> None:
        self._check()
        if self.claimed:
            raise ValueError("R2_CLAIM_ALREADY_USED")
        # Reserving before authentication is conservative: crash consumes the claim.
        descriptor = os.open(
            self.approval.claim_file,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
        )
        with os.fdopen(descriptor, "w") as stream:
            stream.write(self.approval.receipt_sha + "\n" + self.approval.session + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        self.claimed = True

    def advance(
        self,
        now_ns: int,
        *,
        tcp_closed_ns: int | None,
        sidecar_closed: bool,
        received: int,
        capture_closed: bool,
    ) -> bool:
        """Return True to request existing Supervisor normal STOP. Never declares eligible."""
        self._check()
        if (
            self.started_ns is None
            or type(now_ns) is not int
            or now_ns < max(self.previous_ns, self.started_ns)
            or type(received) is not int
            or not 0 <= received <= 4096
        ):
            raise ValueError("R2_CLOCK_OR_COUNTER")
        self.previous_ns = now_ns
        if self.stop_reason:
            return True
        if capture_closed or received == 4096 or now_ns >= self.started_ns + 60 * SECOND:
            self.stop_reason = "INCOMPLETE_CAPTURE_ENDED_OR_LIMIT"
            return True
        if tcp_closed_ns is None:
            return False
        if (
            type(tcp_closed_ns) is not int
            or not self.started_ns <= tcp_closed_ns <= now_ns
            or self.tcp_closed_ns not in (None, tcp_closed_ns)
        ):
            raise ValueError("R2_TCP_CLOSE_CLOCK")
        self.tcp_closed_ns = tcp_closed_ns
        if now_ns >= tcp_closed_ns + 45 * SECOND:
            self.stop_reason = "PLANNED_STOP" if self.witness else "INCOMPLETE_NO_WITNESS"
            return True
        if now_ns >= tcp_closed_ns + 35 * SECOND and not self.attempted:
            if not sidecar_closed:
                raise ValueError("R2_SIDECAR_NOT_CLOSED")
            self.attempted = True  # A send/response failure must never retry.
            self.witness = _udp_witness()
        return False

    def snapshot(self) -> dict:
        return dict(
            contract="SOC_R2_OBSERVATION_V1",
            receipt_sha=self.approval.receipt_sha,
            session=self.approval.session,
            attached_monotonic_ns=self.started_ns,
            tcp_closed_monotonic_ns=self.tcp_closed_ns,
            witness=self.witness,
            stop_reason=self.stop_reason,
            eligibility="NOT_ASSESSED_BY_LAUNCHER",
            kernel_timestamp="SEE_TCX_CAPTURE_EVIDENCE",
            automatic_retry=False,
        )


def _udp_witness() -> dict:
    local_controller()  # Ordinary UID, no effective/permitted/ambient capabilities.
    if os.readlink("/proc/self/ns/net") != Scenario().namespace:
        raise ValueError("R2_NAMESPACE")
    transaction = 0xC203
    message = struct.pack("!6H", transaction, 0x0100, 1, 0, 0, 0) + QUESTION
    sent = time.monotonic_ns()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as channel:
        channel.settimeout(1)
        channel.bind(("127.0.0.1", 0))
        channel.connect(("127.0.0.53", 53))
        if channel.send(message) != len(message):
            raise OSError("R2_PARTIAL_DATAGRAM")
        body = channel.recv(513)
        if not 12 + len(QUESTION) <= len(body) <= 512:
            raise ValueError("R2_RESPONSE_LENGTH")
        actual, flags, questions, *_ = struct.unpack("!6H", body[:12])
        if (
            actual != transaction
            or not flags & 0x8000
            or questions != 1
            or body[12 : 12 + len(QUESTION)] != QUESTION
        ):
            raise ValueError("R2_RESPONSE_IDENTITY")
        source = list(channel.getsockname())
    return dict(
        test_origin="CONTROLLED_R2_LATE_UDP_WITNESS",
        transaction_id=transaction,
        source=source,
        destination=["127.0.0.53", 53],
        qname="native-0516.localhost.",
        sent_monotonic_ns=sent,
        received_monotonic_ns=time.monotonic_ns(),
        response_sha256=hashlib.sha256(body).hexdigest(),
        response_bytes=len(body),
        rcode=flags & 15,
    )
