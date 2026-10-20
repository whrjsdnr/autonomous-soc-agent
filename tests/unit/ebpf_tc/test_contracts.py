"""Native ABI scope and command checks reuse B-1 models and never authorize Native."""

import hashlib
from uuid import uuid4

import pytest
from pydantic import ValidationError
from tests.ebpf_broker_support import plan, run

from soc_agent.security_ai.ebpf_broker.contracts import Command, Ownership
from soc_agent.security_ai.ebpf_tc.contracts import (
    PLAN,
    REQUEST,
    NativePlan,
    detach_request,
    request,
)


def native_plan():
    p = plan()
    return NativePlan(
        broker=p,
        bootstrap_sha256="1" * 64,
        native_broker_sha256="2" * 64,
        loader_sha256="3" * 64,
        program_sha256=p.application.scope.program_sha256,
        bundle_digest="4" * 64,
    )


def test_native_scope_binary_hash_binds_all_artifact_ids_and_identity():
    p = native_plan()
    wire = p.wire()
    assert len(wire) == 272
    assert wire[-32:] == hashlib.sha256(wire[:-32] + bytes(32)).digest()
    fields = PLAN.unpack(wire)
    assert fields[:4] == (1, p.broker.uid, p.broker.gid, p.broker.application.controller.pid)
    assert p.approval == wire[-32:].hex()
    for field in ("bootstrap_sha256", "native_broker_sha256", "loader_sha256", "bundle_digest"):
        q = p.model_copy(update={field: "9" * 64})
        assert q.approval != p.approval
    with pytest.raises(ValidationError, match="PROGRAM_IDENTITY"):
        NativePlan.model_validate(p.model_dump() | {"program_sha256": "f" * 64})


def test_b1_command_allowlist_and_closed_native_argument_schema():
    p = native_plan()
    cmd = Command(command="ATTACH", sequence=1, plan_digest=p.approval, run=run(p.broker))
    packed = request(cmd)
    fields = REQUEST.unpack(packed)
    assert fields[0:2] == (2, 1) and fields[2] > 0 and fields[3] > 0
    assert fields[5].hex() == p.approval
    assert fields[6] == bytes(56)
    with pytest.raises(ValidationError):
        Command(command="shell", sequence=1, plan_digest=p.approval, path="/tmp/untrusted")


def test_fixture_ownership_can_never_be_encoded_as_native_detach():
    p = native_plan()
    owner = Ownership(
        owner_session=uuid4(),
        capture_session=uuid4(),
        generation=uuid4(),
        namespace="net:[1]",
        ifindex=1,
        hook="INGRESS",
        handle=1,
        program_id=123,
        program_tag="a" * 16,
        program_sha256="a" * 64,
    )
    with pytest.raises(ValueError, match="NATIVE_OWNERSHIP_EVIDENCE_REQUIRED"):
        request(Command(command="DETACH", sequence=1, plan_digest=p.approval, ownership=owner))
    wire = detach_request(
        1,
        p.approval,
        generation=1,
        program_id=123,
        ifindex=1,
        hook=1,
        handle=1,
        tag=bytes(8),
        application=uuid4(),
        namespace_inode=1,
    )
    assert len(wire) == 112


@pytest.mark.parametrize(
    "changes",
    [{"hook": 3}, {"generation": 0}, {"tag": b"short"}, {"namespace_inode": 0}, {"program_id": 0}],
)
def test_native_detach_fields_are_validated(changes):
    fields = (
        dict(
            generation=1,
            program_id=123,
            ifindex=1,
            hook=1,
            handle=1,
            tag=bytes(8),
            application=uuid4(),
            namespace_inode=1,
        )
        | changes
    )
    with pytest.raises(ValueError, match="OWNERSHIP_INVALID"):
        detach_request(1, "a" * 64, **fields)
