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
    assert decode_checkpoint(text) == legacy  # Existing unsorted JSON remains readable.
    assert encode_checkpoint(legacy) == json.dumps(
        legacy, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
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


@pytest.mark.parametrize("count", [0, 1, 1024])
def test_checkpoint_empty_single_max_duplicate_receipts_preserved(count):
    import copy

    from soc_agent.security_ai.ebpf.checkpoint import decode_checkpoint, encode_checkpoint
    from soc_agent.security_ai.research.models import digest

    receipt = dict(
        flow_id="a" * 64,
        values_digest="b" * 64,
        eligible=False,
        provenance="合成証拠 / Synthetic; not Native",
    )
    value = dict(candidate_eligibility=[copy.deepcopy(receipt) for _ in range(count)])
    before = copy.deepcopy(value)
    text = encode_checkpoint(value)
    restored = decode_checkpoint(text)
    assert restored == value == before and digest(restored) == digest(before)
    assert len(restored["candidate_eligibility"]) == count
    assert len(text.encode("utf-8")) <= 16384


def test_checkpoint_dictionary_order_canonical_but_receipt_order_never_rewritten():
    from soc_agent.security_ai.ebpf.checkpoint import decode_checkpoint, encode_checkpoint
    from soc_agent.security_ai.research.models import digest

    a = dict(
        candidate_eligibility=[
            dict(flow_id=f"flow-{n}", eligible=False, context="x" * 800) for n in range(24)
        ],
        diagnostic="Unicode / 한글",
    )
    b = {
        key: (
            [dict(reversed(list(row.items()))) for row in value]
            if key == "candidate_eligibility"
            else value
        )
        for key, value in reversed(list(a.items()))
    }
    assert encode_checkpoint(a) == encode_checkpoint(b) == encode_checkpoint(a)
    assert digest(decode_checkpoint(encode_checkpoint(a))) == digest(a)
    c = a | dict(candidate_eligibility=list(reversed(a["candidate_eligibility"])))
    assert encode_checkpoint(c) != encode_checkpoint(a)
    assert decode_checkpoint(encode_checkpoint(c)) == c


@pytest.mark.parametrize("unicode", [False, True])
def test_checkpoint_actual_utf8_exact_16k_boundary_and_one_byte_overflow(unicode):
    from soc_agent.security_ai.ebpf.checkpoint import decode_checkpoint, encode_checkpoint

    value = dict(candidate_eligibility=[], diagnostic="")
    budget = 16384 - len(encode_checkpoint(value).encode("utf-8"))
    value["diagnostic"] = "한" * (budget // 3) + "x" * (budget % 3) if unicode else "x" * budget
    text = encode_checkpoint(value)
    assert len(text.encode("utf-8")) == 16384
    assert decode_checkpoint(text) == value
    with pytest.raises(ValueError, match="EBPF_CHECKPOINT_SIZE"):
        encode_checkpoint(value | dict(diagnostic=value["diagnostic"] + "x"))


def test_unique_maximum_and_low_repetition_fail_explicitly_without_deleting_receipts():
    import copy
    import hashlib

    from soc_agent.security_ai.ebpf.checkpoint import encode_checkpoint

    for count, context in [(1024, False), (32, True)]:
        rows = [
            dict(
                flow_id=hashlib.sha256(str(n).encode()).hexdigest(),
                values_digest=hashlib.sha256(f"vector-{n}".encode()).hexdigest(),
                provenance=(str(n) * 600 if context else "synthetic"),
            )
            for n in range(count)
        ]
        value = dict(candidate_eligibility=rows)
        before = copy.deepcopy(value)
        with pytest.raises(ValueError, match="EBPF_CHECKPOINT_SIZE"):
            encode_checkpoint(value)
        assert value == before and len(rows) == count


@pytest.mark.parametrize(
    "value",
    [
        [],
        None,
        {"candidate_eligibility": "wrong"},
        {"candidate_eligibility": [None]},
        {"candidate_eligibility": [{}] * 1025},
        {"diagnostic": float("nan")},
        {"diagnostic": float("inf")},
    ],
)
def test_malformed_or_nonfinite_small_summary_is_rejected_before_persistence(value):
    from soc_agent.security_ai.ebpf.checkpoint import encode_checkpoint

    with pytest.raises(ValueError, match="EBPF_CHECKPOINT_(ENCODING|SIZE)"):
        encode_checkpoint(value)


@pytest.mark.parametrize("text", ['{"a":1,"a":2}', '{"x":NaN}', '{"candidate_eligibility":[null]}'])
def test_ambiguous_or_nonfinite_legacy_json_is_rejected(text):
    from soc_agent.security_ai.ebpf.checkpoint import decode_checkpoint

    with pytest.raises(ValueError, match="EBPF_CHECKPOINT_ENCODING"):
        decode_checkpoint(text)


@pytest.mark.asyncio
async def test_failed_final_checkpoint_transaction_preserves_prior_row_and_audit(
    tmp_path, monkeypatch
):
    from tests.ebpf_support import plan

    from soc_agent.security_ai.ebpf.collector import EBPFCollector

    collector = EBPFCollector(tmp_path / "session", plan())
    collector.prepare_metadata()
    with collector.store.database.transaction(write=False) as db:
        before = db.execute("SELECT value,digest FROM ebpf_checkpoint").fetchone()
    before_audit = collector.store.verify_audit()
    collector.state = "STOPPED"

    def failed_audit(*_args):
        raise OSError(errno.EIO, "injected final Audit failure")

    monkeypatch.setattr(collector.store, "_audit", failed_audit)
    writer = CheckpointWriter(collector._persist_checkpoint)
    try:
        collector.checkpoint_writer = writer
        assert collector.request_checkpoint() == "PENDING"
        with pytest.raises(CheckpointFailure, match="FLUSH_UNVERIFIED"):
            writer.flush()
    finally:
        with pytest.raises(CheckpointFailure, match="FLUSH_UNVERIFIED"):
            writer.close()
    assert writer.failure["errno"] == errno.EIO and writer.committed == 0
    assert not writer.worker.is_alive()
    with collector.store.database.transaction(write=False) as db:
        assert db.execute("SELECT value,digest FROM ebpf_checkpoint").fetchone() == before
    assert collector.store.verify_audit() == before_audit
    restored = await EBPFCollector(collector.directory, collector.plan).recover()
    assert restored["restored_evidence"]["state"] == "NATIVE_HOOK_PENDING"
