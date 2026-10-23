"""No privilege/capture: bounded snapshots, commit errors, durable completion."""

import errno
import threading

import pytest

from soc_agent.security_ai.ebpf.checkpoint import CheckpointFailure, CheckpointWriter


def test_full_writer_rejects_explicitly_without_dropping_or_reordering_submissions():
    started, release = threading.Event(), threading.Event()
    committed = []

    def persist(text, sha):
        started.set()
        assert release.wait(2)
        committed.append((text, sha))

    writer = CheckpointWriter(persist)
    try:
        writer.submit("first", "1")
        assert started.wait(1)
        writer.submit("second", "2")
        writer.submit("third", "3")
        with pytest.raises(CheckpointFailure, match="BACKPRESSURE"):
            writer.submit("rejected", "4")
        assert writer.snapshot()["outstanding"] == 3
        assert not writer.snapshot()["pending_is_durable"]
    finally:
        release.set()
        writer.close()
    assert committed == [("first", "1"), ("second", "2"), ("third", "3")]
    assert writer.rejected == 1 and writer.committed == 3


def test_commit_failure_stays_visible_and_does_not_claim_flush_success():
    def persist(*_):
        raise OSError(errno.EIO, "injected disk failure")

    writer = CheckpointWriter(persist)
    writer.submit("first", "1")
    with pytest.raises(CheckpointFailure, match="FLUSH_UNVERIFIED"):
        writer.flush()
    with pytest.raises(CheckpointFailure):
        writer.close()
    assert writer.committed == 0 and writer.failure["errno"] == errno.EIO
    assert not writer.worker.is_alive()


@pytest.mark.asyncio
async def test_large_candidate_receipts_preserve_digest_sqlite_audit_and_recovery(
    tmp_path, monkeypatch
):
    import copy
    import json

    from tests.ebpf_support import plan
    from tests.unit.ebpf_tc.test_phase_d import candidate_summary

    from soc_agent.security_ai.ebpf.checkpoint import decode_checkpoint, encode_checkpoint
    from soc_agent.security_ai.ebpf.collector import EBPFCollector
    from soc_agent.security_ai.ebpf.eligibility import candidate_rca
    from soc_agent.security_ai.research.models import digest

    collector = EBPFCollector(tmp_path / "session", plan())
    collector.prepare_metadata()
    value = collector._summary()
    candidates = candidate_summary()
    template = candidates["feature_tail"][0]
    candidates["feature_tail"] = [
        dict(copy.deepcopy(template), flow_id=f"flow-{n:064d}") for n in range(24)
    ]
    candidates["finalized_count"] = 24
    value["candidate_eligibility"] = candidate_rca(candidates)
    value["feature_tail"] = candidates["feature_tail"][-4:]
    value["finalized_count"] = 24
    assert len(json.dumps(value).encode()) > 16384  # Original Native failure boundary.
    monkeypatch.setattr(collector, "_summary", lambda: value)
    text, summary_digest = collector._checkpoint_text()
    assert text == encode_checkpoint(value) and summary_digest == digest(value)
    assert len(text.encode()) <= 16384
    restored = decode_checkpoint(text)
    assert restored == value and digest(restored) == digest(value)
    assert len(restored["candidate_eligibility"]) == 24
    writer = CheckpointWriter(collector._persist_checkpoint)
    writer.submit(text, digest(value))
    writer.close()
    assert writer.committed == 1 and writer.failure is None
    result = await EBPFCollector(collector.directory, collector.plan).recover()
    assert result["restored_evidence"] == value
    assert result["runtime_audit_integrity"] == collector.store.verify_audit()
    assert not any(row["eligible"] for row in restored["candidate_eligibility"])
    # Tamper within the factored context must still fail the original full-summary
    # digest/Audit binding, even if the encoding itself is structurally valid.
    encoded = json.loads(text)
    encoded["shared"]["eligible"] = True
    with collector.store.database.transaction() as db:
        db.execute("UPDATE ebpf_checkpoint SET value=?", (json.dumps(encoded),))
    with pytest.raises(ValueError, match="BINDING_FAILED"):
        await EBPFCollector(collector.directory, collector.plan).recover()


def test_checkpoint_encoding_retains_legacy_and_rejects_oversize_without_truncation():
    import json

    from soc_agent.security_ai.ebpf.checkpoint import decode_checkpoint, encode_checkpoint

    legacy = dict(accepted=3, plan=dict(generation=2**64 - 1), candidate_eligibility=[])
    text = json.dumps(legacy)
    assert encode_checkpoint(legacy) == text and decode_checkpoint(text) == legacy
    with pytest.raises(ValueError, match="CHECKPOINT_SIZE"):
        encode_checkpoint(dict(candidate_eligibility=[], extra="x" * 17000))
    with pytest.raises(CheckpointFailure, match="CHECKPOINT_SIZE"):
        writer = CheckpointWriter(lambda *_: None)
        try:
            writer.submit("x" * 16385, "not-admitted")
        finally:
            writer.close()
    assert writer.submitted == writer.committed == 0


@pytest.mark.parametrize("mutation", ["version", "overlap", "rows", "expansion"])
def test_checkpoint_encoding_malformed_or_oversized_expansion_fails_closed(mutation):
    import json

    from soc_agent.security_ai.ebpf.checkpoint import decode_checkpoint

    value = dict(
        checkpoint_encoding="SHARED_RCA_V1", summary={}, shared={"eligible": False}, rows=[{}]
    )
    if mutation == "version":
        value["checkpoint_encoding"] = "UNREVIEWED_V2"
    elif mutation == "overlap":
        value["rows"] = [{"eligible": True}]
    elif mutation == "rows":
        value["rows"] = [{}] * 1025
    else:
        value["shared"] = {"diagnostic": "x" * 8300}
        value["rows"] = [{}] * 1024
    with pytest.raises(ValueError, match="EBPF_CHECKPOINT_(ENCODING|SIZE)"):
        decode_checkpoint(json.dumps(value, separators=(",", ":")))
