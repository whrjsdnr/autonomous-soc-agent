"""Conservative Native input states; no inference, capture or gate changes."""

import copy

import pytest
from tests.unit.ebpf_tc.test_phase_d import candidate_summary

from soc_agent.security_ai.ebpf.eligibility import candidate_rca


@pytest.mark.parametrize("bad", [None, float("nan"), float("inf"), 1e100, True])
def test_invalid_feature_values_are_invalid_not_missing_imputed_defaults(bad):
    summary = candidate_summary()
    summary["feature_tail"][0]["values"][0] = bad
    row = candidate_rca(summary)[0]
    assert row["input_state"] == "INVALID"
    assert not row["eligible"] and row["native_ai"] == "BLOCKED"
    assert "MODEL_INPUT_CONTRACT_OR_DIGEST_INVALID" in row["reasons"]


def test_missing_vector_unknown_incomplete_flow_incomplete_and_timeout_not_native_eligible():
    summary = candidate_summary()
    assert candidate_rca(summary)[0]["input_state"] == "INCOMPLETE"
    del summary["feature_tail"][0]["values"]
    assert candidate_rca(summary)[0]["input_state"] == "UNKNOWN"
    complete = candidate_summary("IDLE_TIMEOUT")
    complete["feature_tail"][0]["flow_completeness"] = "CANDIDATE_TIMEOUT"
    complete["cpu_sequence"]["unrepresented_attempts"] = 0
    complete["queue_discarded"] = 0
    complete["last_error"] = None
    row = candidate_rca(complete)[0]
    assert row["input_state"] == "UNKNOWN" and not row["eligible"]
    assert "NATIVE_GOLDEN_PARITY_UNKNOWN" in row["reasons"]


def test_full_retained_rca_is_not_truncated_to_four_vectors_by_final_counter_projection():
    summary = candidate_summary()
    template = summary["feature_tail"][0]
    summary["feature_tail"] = [dict(copy.deepcopy(template), flow_id=f"flow-{i}") for i in range(8)]
    summary["finalized_count"] = 8
    summary["candidate_eligibility"] = candidate_rca(summary)
    summary["feature_tail"] = summary["feature_tail"][-4:]
    transport = dict(
        counter_evidence=dict(
            retrieval="SUCCESS", delivered=8, totals=dict(emitted=8, ring_reservation_failures=0)
        )
    )
    rows = candidate_rca(summary, transport)
    assert [r["flow_id"] for r in rows] == [f"flow-{i}" for i in range(8)]
    assert len(rows) == 8 and all(r["ring_reservation_failures"] == 0 for r in rows)
    assert all("RING_LOSS_UNKNOWN" not in r["reasons"] for r in rows)
    assert all(not r["eligible"] for r in rows)
    assert all(r["vector_validation_source"] == "CHECKPOINT_RECEIPT" for r in rows[:4])
    assert all(r["vector_validation_source"] == "VALUES" for r in rows[4:])
    assert all("RAW_VECTOR_NOT_RETAINED_CHECKPOINT_RECEIPT_ONLY" in r["reasons"] for r in rows[:4])


def test_unretained_historical_candidates_remain_unknown_and_bad_digest_stays_invalid():
    summary = candidate_summary()
    summary["finalized_count"] = 3
    rows = candidate_rca(summary)
    assert rows[-1]["unretained_candidates"] == 2
    assert rows[-1]["input_state"] == "UNKNOWN" and rows[-1]["flow_id"] is None
    summary["feature_tail"][0]["values_digest"] = "0" * 64
    assert candidate_rca(summary)[0]["input_state"] == "INVALID"
