"""Strict fixture-provider contract, never evidence of an actual Native handle."""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from soc_agent.security_ai.collectors.capture_attestation import (
    CaptureSample,
    CaptureScope,
    validate_fixture,
)
from soc_agent.security_ai.collectors.dns_visibility import DNSStages, closed_data, diagnose


@pytest.fixture
def scope():
    return CaptureScope(
        session_id=uuid4(),
        collector_identity="a" * 64,
        image_digest="b" * 64,
        interface="lo",
        interface_identity="e" * 64,
        net_namespace="net:[1]",
        handle_identity="c" * 64,
        handle_generation=uuid4(),
        provider_digest="d" * 64,
        counter_source="LIBPCAP_SAME_HANDLE_PROPOSED",
        semantics="CUMULATIVE",
        counter_bits=32,
    )


def sample(scope, i, received=0, dropped=0, **change):
    return CaptureSample.model_validate(
        dict(
            scope=scope,
            sequence=i,
            phase="START" if i == 1 else "END",
            retrieval="SUCCESS",
            monotonic_ns=(i - 1) * 1000,
            observed_at=datetime.now(UTC),
            received=received,
            dropped=dropped,
            **change,
        )
    )


def verify(scope, rows, **change):
    args = dict(
        first_delivery_ns=10,
        last_delivery_ns=999,
        gaps=0,
        process_verified=True,
        stream_verified=True,
    )
    return validate_fixture(scope, tuple(rows), **(args | change))


def test_success_zero_drop_does_not_authorize_native(scope):
    v = verify(scope, [sample(scope, 1), sample(scope, 2, 12)])
    assert v["status"] == "VERIFIED" and v["counter_delta"] == 12 and v["drop_count"] == 0
    assert v["same_handle"] == "FIXTURE_DECLARATION_ONLY" and v["native_ai"] == "BLOCKED"
    assert "NOT_NATIVE_PROOF" in v["scope"]


@pytest.mark.parametrize("status", ["FAILED", "UNSUPPORTED", "UNKNOWN"])
def test_retrieval_failure_unsupported_and_unknown_never_zero(scope, status):
    end = sample(scope, 2).model_copy(update=dict(retrieval=status, received=None, dropped=None))
    v = verify(scope, [sample(scope, 1), end])
    assert v["status"] != "VERIFIED" and v["drop_count"] is None and v["counter_delta"] is None
    with pytest.raises(ValueError, match="UNKNOWN_IS_NOT_ZERO"):
        CaptureSample.model_validate(end.model_dump() | dict(received=0))


@pytest.mark.parametrize(
    "field,value",
    [
        ("handle_identity", "e" * 64),
        ("handle_generation", uuid4()),
        ("session_id", uuid4()),
        ("interface_identity", "f" * 64),
        ("net_namespace", "net:[2]"),
        ("image_digest", "f" * 64),
        ("collector_identity", "f" * 64),
        ("provider_digest", "f" * 64),
    ],
)
def test_foreign_handle_scope_rejected(scope, field, value):
    end = sample(scope.model_copy(update={field: value}), 2, 12)
    assert verify(scope, [sample(scope, 1), end])["reason"] == "HANDLE_SCOPE_OR_SEQUENCE_MISMATCH"


@pytest.mark.parametrize("start,end", [(100, 0), (2**32 - 2, 1)])
def test_reset_or_wrap_is_not_silently_repaired(scope, start, end):
    assert (
        verify(scope, [sample(scope, 1, start), sample(scope, 2, end)])["reason"]
        == "RESET_OR_WRAP_UNATTESTED"
    )


def test_reset_on_read_sums_intervals_without_double_counting(scope):
    s = scope.model_copy(update=dict(semantics="RESET_ON_READ"))
    assert verify(s, [sample(s, 1, 3), sample(s, 2, 5)])["counter_delta"] == 8


@pytest.mark.parametrize("gaps", [None, 1])
def test_gap_unknown_or_loss_blocks_even_zero_drops(scope, gaps):
    assert (
        verify(scope, [sample(scope, 1), sample(scope, 2, 12)], gaps=gaps)["status"] != "VERIFIED"
    )


def test_drops_initial_and_final_are_not_hidden(scope):
    v = verify(scope, [sample(scope, 1, 4, 1), sample(scope, 2, 8, 1)])
    assert v["status"] == "FAILED" and v["drop_count"] == 1


@pytest.mark.parametrize(
    "change",
    [
        dict(first_delivery_ns=-1),
        dict(last_delivery_ns=1001),
        dict(process_verified=False),
        dict(stream_verified=False),
    ],
)
def test_whole_window_process_and_stream_are_required(scope, change):
    assert verify(scope, [sample(scope, 1), sample(scope, 2, 12)], **change)["status"] != "VERIFIED"


def test_missing_counter_sequence_and_monotonic_regression(scope):
    assert verify(scope, [])["status"] == "UNVERIFIED"
    assert verify(scope, [sample(scope, 1), sample(scope, 3, 12)])["status"] == "FAILED"
    end = sample(scope, 2, 12).model_copy(update={"monotonic_ns": -1})
    assert verify(scope, [sample(scope, 1), end])["reason"] == "PROCESS_TIME_REGRESSION"


def test_utc_adjustment_is_not_monotonic_window_time(scope):
    start = sample(scope, 1)
    end = sample(scope, 2, 12).model_copy(
        update={"observed_at": start.observed_at - timedelta(seconds=1)}
    )
    assert verify(scope, [start, end])["status"] == "VERIFIED"


def stages(**change):
    fields = [
        "candidate_udp",
        "candidate_tcp",
        "header_validated",
        "header_invalid",
        "analyzer_dispatch",
        "query_parsed",
        "response_parsed",
        "transaction_matched",
        "event_emitted",
        "parse_failed",
        "response_missing_metadata",
        "transaction_ambiguous",
    ]
    return DNSStages.model_validate(
        dict(
            contract="soc-zeek-dns-stages:v1", diagnostic_truncated=False, **{n: 0 for n in fields}
        )
        | change
    )


@pytest.mark.parametrize(
    "values,expected",
    [
        ({"header_invalid": 1}, "DNS_HEADER_INVALID"),
        ({"parse_failed": 1}, "DNS_PARSE_FAILED"),
        ({"transaction_ambiguous": 1}, "DNS_TRANSACTION_AMBIGUOUS"),
        ({"analyzer_attached": False}, "DNS_ANALYZER_NOT_ATTACHED"),
        ({"non_dns_confirmed": 1}, "PORT53_NON_DNS"),
        ({"query_parsed": 1}, "DNS_EVENT_NOT_EMITTED"),
        ({"event_emitted": 1, "response_missing_metadata": 1}, "DNS_RESPONSE_MISSING"),
    ],
)
def test_failure_classification_requires_specific_evidence(values, expected):
    assert (
        diagnose(stages(**values), candidates=1, accepted=0, rejected=0)["classification"]
        == expected
    )


def test_missing_legacy_diagnostics_is_unknown_not_zero_and_encrypted_visibility_not_proven():
    assert closed_data({"pkts_dropped": 0}) == ({"pkts_dropped": 0}, None)
    v = diagnose(None, candidates=68, accepted=0, rejected=0)
    assert v["classification"] == "DNS_VISIBILITY_UNKNOWN" and v["stage_counters"] is None
    assert (
        diagnose(stages(), candidates=None, accepted=0, rejected=0)["classification"]
        == "DNS_VISIBILITY_UNKNOWN"
    )
    assert (
        diagnose(stages(), candidates=0, accepted=0, rejected=0)["classification"]
        == "NO_DNS_TRAFFIC_OBSERVED"
    )


def test_adapter_rejection_truncation_and_boundaries():
    v = diagnose(None, candidates=1, accepted=0, rejected=1)
    assert v["classification"] == "DNS_ADAPTER_REJECTED" and v["adapter_rejected"] == 1
    assert (
        diagnose(
            stages(header_invalid=1, diagnostic_truncated=True),
            candidates=1,
            accepted=0,
            rejected=0,
        )["classification"]
        == "DNS_VISIBILITY_UNKNOWN"
    )
    with pytest.raises(ValueError):
        stages(query_parsed=65537)
    with pytest.raises(ValueError):
        stages(header_validated=1)
    with pytest.raises(ValueError):
        stages(payload="forbidden")


def test_adapter_schema_rejection_count_and_missing_timestamp_are_fail_closed():
    from uuid import uuid4

    from soc_agent.security_ai.collectors.live_stream import Envelope, Stream
    from soc_agent.security_ai.collectors.models import Source

    stream = Stream(
        Source(session_id=uuid4(), source_digest="a" * 64, origin="SYNTHETIC_ZEEK_JSON")
    )
    stream.accept(Envelope(sequence=1, kind="ready", data={}))
    row = dict(
        ts=1800000000,
        uid="test",
        proto="invalid",
        id=dict(orig_h="192.0.2.1", orig_p=1000, resp_h="192.0.2.2", resp_p=53),
    )
    with pytest.raises(ValueError, match="ZEEK_RECORD_SCHEMA_REJECTED"):
        stream.accept(Envelope(sequence=2, kind="dns", data=row))
    assert stream.dns_adapter_rejected == 1 and stream.dns_count == 0
    del row["ts"]
    with pytest.raises(ValueError, match="ZEEK_STREAM_TIMESTAMP_INVALID"):
        stream.accept(Envelope(sequence=2, kind="dns", data=row))
    assert stream.sequence == 1 and stream.dns_adapter_rejected == 2
