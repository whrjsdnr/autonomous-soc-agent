"""B-1 schemas remain authoritative; encode a small closed C ABI for Native admission."""

import struct
from typing import Literal, Self
from uuid import UUID

from pydantic import model_validator

from soc_agent.review.models import Hash
from soc_agent.security_ai.ebpf_broker.contracts import BrokerPlan, Command
from soc_agent.security_ai.research.models import Frozen

PLAN = struct.Struct("<IIIIQQIIIIIIII16s32s32s32s32s32s32s")
OWNER = struct.Struct("<QIIII8s16sQ")
REQUEST = struct.Struct("<IIQII32s56s")
assert PLAN.size == 272 and OWNER.size == 56 and REQUEST.size == 112


class NativePlan(Frozen):
    broker: BrokerPlan
    bootstrap_sha256: Hash
    native_broker_sha256: Hash
    loader_sha256: Hash
    program_sha256: Hash
    bundle_digest: Hash
    mode: Literal["B2A_NATIVE_BLOCKED", "B2D_TCX_BLOCKED"] = "B2A_NATIVE_BLOCKED"

    @model_validator(mode="after")
    def producer_identity(self) -> Self:
        if self.program_sha256 != self.broker.application.scope.program_sha256:
            raise ValueError("NATIVE_PROGRAM_IDENTITY_MISMATCH")
        return self

    def wire(self) -> bytes:
        base = self.broker.application
        scope = base.scope
        value = PLAN.pack(
            2 if self.mode == "B2D_TCX_BLOCKED" else 1,
            self.broker.uid,
            self.broker.gid,
            base.controller.pid,
            base.controller.start_ticks,
            int(scope.net_namespace[5:-1]),
            scope.ifindex,
            1 if scope.hook == "INGRESS" else 2,
            300,
            4096,
            32,
            256,
            20,
            0,
            base.application_session.bytes,
            bytes.fromhex(self.program_sha256),
            bytes.fromhex(self.loader_sha256),
            bytes.fromhex(self.bootstrap_sha256),
            bytes.fromhex(self.native_broker_sha256),
            bytes.fromhex(self.bundle_digest),
            bytes(32),
        )
        import hashlib

        return value[:-32] + hashlib.sha256(value).digest()

    @property
    def approval(self) -> str:
        return self.wire()[-32:].hex()


def request(command: Command) -> bytes:
    operations = ("PREPARE", "ATTACH", "STATUS", "DETACH", "STOP", "CLEANUP")
    reasons = (
        "USER_STOP",
        "GUI_CLOSE",
        "CONTROLLER_EXIT",
        "APPLICATION_EXIT",
        "TIMEOUT",
        "SIGINT",
        "SIGTERM",
    )
    generation = handle = reason = 0
    if command.run:
        generation = int.from_bytes(command.run.generation.bytes[:8], "little")
        handle = command.run.capture_session.int & 0xFFFFFFFF
        if not generation or not handle:
            raise ValueError("NATIVE_RUN_IDENTITY_INVALID")
    if command.ownership:
        # Fixture program IDs/tags are never promoted into a Native detach lease.
        raise ValueError("NATIVE_OWNERSHIP_EVIDENCE_REQUIRED")
    if command.reason:
        reason = reasons.index(command.reason) + 1
    return REQUEST.pack(
        operations.index(command.command) + 1,
        command.sequence,
        generation,
        handle,
        reason,
        bytes.fromhex(command.plan_digest),
        bytes(OWNER.size),
    )


def detach_request(
    sequence: int,
    approval: str,
    *,
    generation: int,
    program_id: int,
    ifindex: int,
    hook: int,
    handle: int,
    tag: bytes,
    application: UUID,
    namespace_inode: int,
) -> bytes:
    if not (
        0 < sequence <= 2048
        and generation > 0
        and program_id > 0
        and ifindex > 0
        and hook in {1, 2}
        and handle > 0
        and len(tag) == 8
        and namespace_inode > 0
    ):
        raise ValueError("NATIVE_OWNERSHIP_INVALID")
    owner = OWNER.pack(
        generation, program_id, ifindex, hook, handle, tag, application.bytes, namespace_inode
    )
    return REQUEST.pack(4, sequence, 0, 0, 0, bytes.fromhex(approval), owner)
