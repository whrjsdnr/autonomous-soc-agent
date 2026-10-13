"""Declared query and artificial feature rows; no producer parity or model inference."""

import json
from uuid import UUID

import numpy as np
import pytest
from dns_security_ai import DNSFeatureContract
from tests.unit.operational_features.test_auth_source_store import INCIDENT, admit, store
from tests.unit.operational_features.test_raw_sources import dns
from tests.unit.security_ai.external.conftest import case as case

from soc_agent._json import canonical_json_object
from soc_agent.security_ai.external import ExternalEvidenceAdapter
from soc_agent.security_ai.operational.dns_records import (
    DNSRowRejected,
    ReportedDNSFeatures,
    compare_dns_rows,
    validate_reported_dns,
)


def row(source=None, changes=None):
    source = source or dns()
    c = DNSFeatureContract()
    values = {n: float(i + 1) for i, n in enumerate(c.names)}
    if changes:
        values.update(changes)
    return ReportedDNSFeatures(
        incident_id=INCIDENT,
        source=source.header.source,
        source_event_id=source.header.event_id,
        source_content_digest=source.content_digest,
        reported_producer_name="fixture-not-a-producer",
        reported_producer_version="unverified",
        feature_schema_version=c.schema_version,
        ordered_features=c.names,
        feature_names_digest=c.digest,
        feature_values_json=canonical_json_object(values),
    )


def validate(s, r, source=None, **changes):
    source = source or dns()
    args = dict(
        source=source,
        store=s,
        expected_incident=INCIDENT,
        expected_source_digest=source.content_digest,
        expected_row_digest=r.content_digest,
    )
    return validate_reported_dns(r, **(args | changes))


def compare(s, a, b):
    source = dns()
    return compare_dns_rows(
        a,
        b,
        source=source,
        store=s,
        expected_incident=INCIDENT,
        expected_source_digest=source.content_digest,
        expected_reference_digest=a.content_digest,
        expected_candidate_digest=b.content_digest,
    )


def test_official_contract_source_link_and_unverified_rules(tmp_path):
    s = store(tmp_path)
    source = dns()
    admit(s, source)
    r = row()
    result = validate(s, r)
    assert tuple(f.name for f in result.rules) == DNSFeatureContract.names
    assert all(f.calculation_status == "UNVERIFIED" for f in result.rules)
    assert result.inference_status == "NOT_INFERABLE"
    assert result.write_disposition == "WRITE_DENIED"
    assert result.source_assurance == "DECLARED_UNATTESTED"
    matrix = DNSFeatureContract().matrix(json.loads(r.feature_values_json))
    import hashlib

    assert (
        result.float32_matrix_digest == hashlib.sha256(matrix.astype("<f4").tobytes()).hexdigest()
    )
    assert result.model_validate_json(result.model_dump_json()) == result


@pytest.mark.parametrize("bad", [None, True, "1", [], {}, -1, 1e100])
def test_bad_numeric_input_rejected(tmp_path, bad):
    s = store(tmp_path)
    admit(s, dns())
    with pytest.raises(ValueError):
        validate(s, row(changes={"entropy": bad}))


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), float("-inf")])
def test_nonfinite_cannot_serialize(bad):
    with pytest.raises(ValueError):
        row(changes={"entropy": bad})


@pytest.mark.parametrize(
    "change",
    [
        {"feature_schema_version": "unknown"},
        {"feature_names_digest": "0" * 64},
        {"ordered_features": tuple(reversed(DNSFeatureContract.names))},
        {"source_event_id": "other-event"},
        {"source_content_digest": "0" * 64},
        {"incident_id": UUID(int=333)},
    ],
)
def test_identity_and_schema_conflicts_fail_closed(tmp_path, change):
    s = store(tmp_path)
    admit(s, dns())
    r = ReportedDNSFeatures.model_validate(row().model_dump() | change)
    with pytest.raises(DNSRowRejected):
        validate(s, r)


def test_explicit_digest_and_incident_pins(tmp_path):
    s = store(tmp_path)
    admit(s, dns())
    for change in (
        {"expected_source_digest": "0" * 64},
        {"expected_row_digest": "0" * 64},
        {"expected_incident": UUID(int=333)},
    ):
        with pytest.raises(DNSRowRejected):
            validate(s, row(), **change)


def test_missing_and_corrupt_stored_source_rejected(tmp_path):
    s = store(tmp_path)
    with pytest.raises(ValueError):
        validate(s, row())
    admit(s, dns())
    with s.database.transaction() as c:
        c.execute("UPDATE operational_sources SET digest=?", ("0" * 64,))
    with pytest.raises(ValueError):
        validate(s, row())


def test_numeric_comparison_never_a_training_pass(tmp_path):
    s = store(tmp_path)
    admit(s, dns())
    same = compare(s, row(), row())
    assert same.numerical_status == "PASS"
    assert same.training_parity_status == "INCONCLUSIVE"
    assert same.inference_status == "NOT_INFERABLE"
    changed = compare(s, row(), row(changes={"FQDN_count": 1.00000001}))
    assert changed.numerical_status == "FAIL"
    f = changed.features[0]
    assert f.absolute_error == "1E-8" and f.float32_equal
    changed = compare(
        s, row(), row(changes={"FQDN_count": float(np.nextafter(np.float32(1), np.float32(2)))})
    )
    assert not changed.features[0].float32_equal


def test_missing_extra_field_or_forged_authority_rejected(tmp_path):
    s = store(tmp_path)
    admit(s, dns())
    for field in ("synthetic", "inference_status", "approved"):
        with pytest.raises(ValueError):
            ReportedDNSFeatures.model_validate(row().model_dump() | {field: True})
    values = json.loads(row().feature_values_json)
    values.pop("len")
    r = ReportedDNSFeatures.model_validate(
        row().model_dump() | {"feature_values_json": canonical_json_object(values)}
    )
    with pytest.raises(DNSRowRejected):
        validate(s, r)


def test_operational_receipt_does_not_enter_v2(tmp_path, case):
    s = store(tmp_path)
    admit(s, dns())
    receipt = validate(s, row())
    _, kwargs = case()
    for payload in (receipt, receipt.model_dump(mode="json")):
        outcome = ExternalEvidenceAdapter().adapt(payload, **kwargs)
        assert outcome.validation.status == "INVALID"
        assert outcome.result is None


def test_other_source_identity_cannot_link_even_with_rehashed_row(tmp_path):
    from soc_agent.realtime.models import SourceIdentity

    s = store(tmp_path)
    admit(s, dns())
    r = ReportedDNSFeatures.model_validate(
        row().model_dump()
        | {
            "source": SourceIdentity(namespace="other-source", generation="v1", record="other"),
        }
    )
    with pytest.raises(DNSRowRejected, match="SOURCE_OR_INCIDENT"):
        validate(s, r)


def test_source_time_or_query_change_invalidates_retained_digest(tmp_path):
    from datetime import timedelta

    s = store(tmp_path)
    original = dns()
    admit(s, original)
    changed = original.model_copy(update={"query_name": "another.example"})
    with pytest.raises(DNSRowRejected, match="CONTENT_DIGEST"):
        validate(s, row(), source=changed, expected_source_digest=original.content_digest)
    changed = original.model_copy(
        update={
            "header": original.header.model_copy(
                update={
                    "observed_at": original.header.observed_at + timedelta(seconds=1),
                }
            )
        }
    )
    with pytest.raises(DNSRowRejected, match="CONTENT_DIGEST"):
        validate(s, row(), source=changed, expected_source_digest=original.content_digest)


def test_wrong_input_type_and_noncanonical_serialization_rejected(tmp_path):
    s = store(tmp_path)
    admit(s, dns())
    with pytest.raises(DNSRowRejected, match="UNSUPPORTED"):
        validate_reported_dns(
            row(),
            source=object(),
            store=s,
            expected_incident=INCIDENT,
            expected_source_digest=dns().content_digest,
            expected_row_digest=row().content_digest,
        )
    with pytest.raises(ValueError):
        ReportedDNSFeatures.model_validate(
            row().model_dump() | {"feature_values_json": '{"len":1,"len":2}'}
        )
