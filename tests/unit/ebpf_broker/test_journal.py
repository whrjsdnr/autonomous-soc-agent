"""Recovery proves only recorded fixture cleanup; it never restores authority."""

import json

import pytest

from soc_agent.security_ai.ebpf_broker.journal import Journal, recover


def test_hash_chain_closed_and_crash_recovery(tmp_path):
    p = tmp_path / "journal"
    j = Journal(p, "a" * 64, 1048576)
    j.record("BROKER_READY")
    j.record("ATTACH_REQUESTED")
    assert recover(p, "a" * 64)["cleanup_status"] == "CLEANUP_UNVERIFIED"
    j.record("CLEANUP_VERIFIED")
    j.record("BROKER_EXITED")
    j.close()
    result = recover(p, "a" * 64)
    assert result["cleanup_status"] == "FIXTURE_VERIFIED"
    assert not result["authentication_restored"] and not result["automatic_attach"]
    rows = p.read_text().splitlines()
    row = json.loads(rows[0])
    row["kind"] = "FORGED_AUTHENTICATION"
    rows[0] = json.dumps(row)
    p.write_text("\n".join(rows) + "\n")
    with pytest.raises(ValueError, match="INTEGRITY"):
        recover(p, "a" * 64)


def test_bounded_journal_no_overwrite_truncation_or_wrong_session(tmp_path):
    p = tmp_path / "journal"
    j = Journal(p, "a" * 64, 1024)
    j.record("BROKER_READY")
    with pytest.raises(FileExistsError):
        Journal(p, "a" * 64, 1024)
    with pytest.raises(ValueError, match="AUDIT_BUDGET"):
        j.record("TOO_LARGE", detail="x" * 2000)
    j.close()
    with pytest.raises(ValueError, match="INTEGRITY"):
        recover(p, "b" * 64)
    p.write_text(p.read_text()[:-1])
    with pytest.raises(ValueError, match="PARTIAL"):
        recover(p, "a" * 64)
