"""A Native binary log can prove structural integrity, never restore authentication."""

import hashlib

import pytest

from soc_agent.security_ai.ebpf_tc.journal import ROW, recover_native


def row(approval, kind, ordinal, previous):
    raw = ROW.pack(
        bytes.fromhex(approval), kind.encode(), bytes(56), 1, ordinal, previous, bytes(32)
    )
    return raw[:-32] + hashlib.sha256(raw[:-32]).digest()


def test_native_claims_remain_unverified_after_structural_recovery(tmp_path):
    path = tmp_path / "native-journal"
    first = row("a" * 64, "BROKER_READY", 1, bytes(32))
    second = row("a" * 64, "CLEANUP_VERIFIED", 2, first[-32:])
    path.write_bytes(first + second)
    value = recover_native(path, "a" * 64)
    assert value["claimed_cleanup"] and value["process_exit"] == "UNKNOWN"
    assert not value["authentication_restored"] and not value["automatic_attach"]
    assert value["native_ai"] == "BLOCKED"
    with pytest.raises(ValueError, match="INTEGRITY"):
        recover_native(path, "b" * 64)
    path.write_bytes(first + second[:-1])
    with pytest.raises(ValueError, match="PARTIAL"):
        recover_native(path, "a" * 64)
