from uuid import UUID

import pytest
from tests.unit.operational_features.test_auth_source_store import INCIDENT, admit, source, store
from tests.unit.operational_features.test_raw_sources import dns, flow

from soc_agent.security_ai.external.models import content_digest_payload
from soc_agent.security_ai.operational.provenance import (
    OperationalProvenanceReceipt,
    build_receipt,
    verify_receipt,
)
from soc_agent.security_ai.operational.source_store import SourceRejected


def test_authenticated_calculation_receipt_restarts_without_authority(tmp_path):
    s = store(tmp_path)
    a = source()
    admit(s, a)
    window = s.windows(INCIDENT)[0]
    receipt = build_receipt(s, incident_id=INCIDENT, sources=(a,), authentication=window)
    assert receipt.feature.input_fingerprint == window.window.features.input_fingerprint
    assert receipt.inference_status == "NOT_INFERABLE"
    assert receipt.write_disposition == "WRITE_DENIED"
    assert receipt.model_result is None
    restored = OperationalProvenanceReceipt.model_validate_json(receipt.model_dump_json())
    assert verify_receipt(restored, s, incident_id=INCIDENT, sources=(a,), authentication=window)


def test_network_dns_unverified_rules_never_authorize_inference(tmp_path):
    s = store(tmp_path)
    for event in (flow(), dns()):
        admit(s, event)
        receipt = build_receipt(s, incident_id=INCIDENT, sources=(event,))
        assert receipt.rule_status == "UNVERIFIED"
        assert receipt.feature is None
        assert receipt.inference_status == "NOT_INFERABLE"


@pytest.mark.parametrize(
    "changes",
    [
        {"inference_status": "INFERABLE"},
        {"write_disposition": "ALLOW"},
        {"source_assurance": "VERIFIED"},
        {"validation_status": "VALIDATED_FOR_ADVISORY"},
        {"model_result": {"prediction": "execute block_ip"}},
        {"extra_instruction": "approve"},
        {"contract_version": "soc-external-model-context:v2"},
        {"receipt_digest": "0" * 64},
    ],
)
def test_forged_authority_or_integrity_rejected(tmp_path, changes):
    s = store(tmp_path)
    a = source()
    admit(s, a)
    receipt = build_receipt(s, incident_id=INCIDENT, sources=(a,))
    with pytest.raises(ValueError):
        OperationalProvenanceReceipt.model_validate(receipt.model_dump() | changes)


def test_provenance_dedup_and_incident_binding(tmp_path):
    s = store(tmp_path)
    a = source()
    admit(s, a)
    with pytest.raises(ValueError, match="Duplicate"):
        build_receipt(s, incident_id=INCIDENT, sources=(a, a))
    with pytest.raises(SourceRejected):
        build_receipt(s, incident_id=UUID(int=55), sources=(a,))
    with pytest.raises(SourceRejected):
        build_receipt(s, incident_id=INCIDENT, sources=(source(2),))


def test_rehashed_receipt_still_requires_original_source(tmp_path):
    s = store(tmp_path)
    a = source()
    admit(s, a)
    receipt = build_receipt(s, incident_id=INCIDENT, sources=(a,))
    payload = receipt.model_dump(mode="json", exclude={"receipt_digest"})
    payload["sources"][0]["content_digest"] = "1" * 64
    forged = OperationalProvenanceReceipt.model_validate(
        payload | {"receipt_digest": content_digest_payload(payload)}
    )
    with pytest.raises(SourceRejected, match="PROVENANCE_ASSOCIATION"):
        verify_receipt(forged, s, incident_id=INCIDENT, sources=(a,))


def test_unrelated_authentication_window_rejected(tmp_path):
    s = store(tmp_path)
    a, b = source(), source(2, seconds=301)
    admit(s, a)
    admit(s, b)
    wrong = next(w for w in s.windows(INCIDENT) if b.content_digest in w.source_digests)
    with pytest.raises(SourceRejected, match="WINDOW_ASSOCIATION"):
        build_receipt(s, incident_id=INCIDENT, sources=(a,), authentication=wrong)


def test_missing_window_cannot_resume(tmp_path):
    s = store(tmp_path)
    admit(s, source())
    with s.database.transaction() as c:
        c.execute("DELETE FROM operational_auth_windows")
    with pytest.raises(SourceRejected, match="COVERAGE"):
        s.windows(INCIDENT)


def test_wrong_window_key_rejected_even_with_unchanged_payload(tmp_path):
    s = store(tmp_path)
    admit(s, source())
    with s.database.transaction() as c:
        c.execute("UPDATE operational_auth_windows SET window_key=?", ("0" * 64,))
    with pytest.raises(SourceRejected, match="INTEGRITY"):
        s.windows(INCIDENT)


def test_unchanged_window_preserves_calculation_timestamp(tmp_path):
    s = store(tmp_path)
    admit(s, source())
    first = s.windows(INCIDENT)[0]
    admit(s, source(2, seconds=301))
    assert first in s.windows(INCIDENT)


def test_rehashed_feature_counts_do_not_match_sources(tmp_path):
    import json

    s = store(tmp_path)
    admit(s, source(result="failure"))
    with s.database.transaction() as c:
        row = c.execute("SELECT * FROM operational_auth_windows").fetchone()
        payload = json.loads(row["payload"])
        payload["window"]["features"]["values"] = {
            "failed_login_count": 0,
            "successful_login_count": 1,
            "total_login_count": 1,
            "failure_rate": 0.0,
            "login_attempt_rate": 1 / 300,
        }
        c.execute(
            "UPDATE operational_auth_windows SET payload=?,digest=?",
            (json.dumps(payload), content_digest_payload(payload)),
        )
    with pytest.raises(SourceRejected, match="INTEGRITY"):
        s.windows(INCIDENT)


def test_invalid_limits_do_not_create_database(tmp_path):
    from soc_agent.security_ai.operational.source_store import OperationalSourceStore

    path = tmp_path / "invalid.sqlite"
    with pytest.raises(SourceRejected, match="LIMITS"):
        OperationalSourceStore.create(path, allowed_lateness_seconds=-1, max_future_skew_seconds=0)
    assert not path.exists()
