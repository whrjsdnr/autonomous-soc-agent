"""Feature contracts, exact source binding, and reproducible input identities."""

from datetime import UTC, datetime, timedelta, timezone
from uuid import uuid4

import pytest
from pydantic import ValidationError

from soc_agent.security_ai.features import (
    AuthenticationSummaryExtractor,
    DatasetRecordReference,
    DatasetSchema,
    FeatureDefinition,
    FeatureExtractionError,
    FeatureProvenanceError,
    FeatureSchema,
    FeatureSet,
    SecurityRecord,
    SourceReference,
    create_feature_set,
    record_from_evidence,
)
from soc_agent.state import Evidence, IncidentState
from soc_agent.state.evidence import utc_now


@pytest.fixture
def record():
    return SecurityRecord(
        record_type="authentication_summary",
        record_schema_version="1.0.0",
        source="fixture",
        source_reference=SourceReference(
            source_type="stream", source_name="fixture", source_version="1", record_id="event-42"
        ),
        observed_at=utc_now(),
        fields={
            "failed_login_count": 40,
            "successful_login_count": 2,
            "unique_accounts": 8,
            "window_seconds": 60,
        },
    )


@pytest.fixture
def features(record):
    return AuthenticationSummaryExtractor().extract(record)


def test_expected_payload_and_roundtrip(features):
    assert features.feature_names == (
        "failed_login_count",
        "unique_accounts",
        "failure_rate",
        "login_velocity",
    )
    assert features.feature_values == (40, 8, 40 / 42, 0.7)
    assert features.provenance.extractor_name == "auth_summary"
    assert (
        features.provenance.extractor_version == features.feature_schema.schema_version == "1.0.0"
    )
    assert features.provenance.source_evidence_ids == ()
    assert features.created_at.utcoffset() == timedelta(0)
    assert FeatureSet.model_validate_json(features.model_dump_json()) == features
    assert len(features.input_fingerprint) == 64


@pytest.mark.parametrize(
    "change",
    [
        {"schema_version": ""},
        {"schema_version": "latest"},
        {"schema_version": "-1"},
        {"schema_version": 1},
        {"features": ()},
        {"extra": "forbidden"},
    ],
)
def test_invalid_schema(features, change):
    with pytest.raises(ValidationError):
        FeatureSchema.model_validate(features.feature_schema.model_dump() | change)


def test_duplicate_definition(features):
    schema = features.feature_schema
    with pytest.raises(ValidationError):
        FeatureSchema.model_validate(schema.model_dump() | {"features": schema.features * 2})


@pytest.mark.parametrize("kind", ["int", "float", "bool", "str"])
def test_strict_scalar_types(record, kind):
    schema = FeatureSchema(
        schema_name="scalars",
        schema_version="1",
        features=(FeatureDefinition(name="x", data_type=kind, description="Fixture scalar"),),
    )
    good = {"int": 43, "float": 43.0, "bool": True, "str": "43"}
    for value in [43, 43.0, True, "43", None, [], {}]:
        if type(value) is type(good[kind]):
            actual = create_feature_set(
                feature_schema=schema,
                values={"x": value},
                records=(record,),
                extractor_name="fixture",
                extractor_version="1",
            )
            assert type(actual.feature_values[0]) is type(value)
        else:
            with pytest.raises(FeatureExtractionError):
                create_feature_set(
                    feature_schema=schema,
                    values={"x": value},
                    records=(record,),
                    extractor_name="fixture",
                    extractor_version="1",
                )


def test_explicit_null_not_missing(record):
    schema = FeatureSchema(
        schema_name="nullable",
        schema_version="1",
        features=(
            FeatureDefinition(
                name="x", data_type="float", nullable=True, description="Optional value"
            ),
        ),
    )
    result = create_feature_set(
        feature_schema=schema,
        values={"x": None},
        records=(record,),
        extractor_name="fixture",
        extractor_version="1",
    )
    assert result.feature_values == (None,)
    with pytest.raises(FeatureExtractionError):
        create_feature_set(
            feature_schema=schema,
            values={},
            records=(record,),
            extractor_name="fixture",
            extractor_version="1",
        )


@pytest.mark.parametrize("value", [float("nan"), float("inf"), -float("inf")])
def test_nonfinite_rejected(record, features, value):
    with pytest.raises(ValidationError):
        SecurityRecord.model_validate(record.model_dump() | {"fields": {"x": value}})
    with pytest.raises(ValidationError):
        FeatureSet.model_validate(
            features.model_dump()
            | {
                "values": features.input_payload()
                | {
                    "failure_rate": value,
                }
            }
        )


@pytest.mark.parametrize(
    "change",
    [
        {"window_seconds": 0},
        {"window_seconds": -1},
        {"window_seconds": 60.0},
        {"failed_login_count": "40"},
        {"failed_login_count": True},
        {"failed_login_count": -1},
        {"unique_accounts": None},
        {"extra": 1},
        {"label": "attack"},
        {"failed_login_count": 0, "successful_login_count": 0},
    ],
)
def test_invalid_source(record, change):
    record = SecurityRecord.model_validate(
        record.model_dump() | {"fields": record.payload() | change}
    )
    with pytest.raises(FeatureExtractionError):
        AuthenticationSummaryExtractor().extract(record)


def test_missing_source_and_unsupported_contract(record):
    payload = record.payload()
    del payload["unique_accounts"]
    for change in (
        {"fields": payload},
        {"record_type": "network_flow"},
        {"record_schema_version": "2"},
    ):
        invalid = SecurityRecord.model_validate(record.model_dump() | change)
        with pytest.raises(FeatureExtractionError):
            AuthenticationSummaryExtractor().extract(invalid)


def test_immutable_snapshots(record, features):
    for obj, field in [
        (record, "fields"),
        (features, "values"),
        (features.feature_schema, "features"),
        (features.feature_schema.features[0], "name"),
        (features.provenance, "sources"),
    ]:
        with pytest.raises(ValidationError):
            setattr(obj, field, None)
    original = record.fields
    record.payload()["new"] = [1, 2]
    assert record.fields == original
    features.input_payload()["failed_login_count"] = 999
    assert features.feature_values[0] == 40


@pytest.mark.parametrize(
    "change",
    [
        {"created_at": datetime(2026, 1, 1)},
        {"extra": True},
        {"values": {}},
        {"values": {"label": "attack"}},
    ],
)
def test_invalid_feature_set(features, change):
    with pytest.raises(ValidationError):
        FeatureSet.model_validate(features.model_dump() | change)


def test_utc(features):
    value = datetime(2026, 1, 1, 9, tzinfo=timezone(timedelta(hours=9)))
    result = FeatureSet.model_validate(features.model_dump() | {"created_at": value})
    assert result.created_at == datetime(2026, 1, 1, tzinfo=UTC)


def test_determinism_and_source_independence(record, features):
    other = SecurityRecord.model_validate(
        record.model_dump()
        | {
            "record_id": uuid4(),
            "source": "other fixture",
            "fields": dict(reversed(list(record.payload().items()))),
        }
    )
    second = AuthenticationSummaryExtractor().extract(other)
    assert features.feature_set_id != second.feature_set_id
    assert features.values == second.values
    assert features.input_fingerprint == second.input_fingerprint
    assert features.provenance != second.provenance
    later = FeatureSet.model_validate(
        features.model_dump()
        | {
            "created_at": features.created_at + timedelta(days=1),
            "feature_set_id": uuid4(),
        }
    )
    assert later.input_fingerprint == features.input_fingerprint


@pytest.mark.parametrize(
    "kind",
    ["value", "order", "schema_version", "extractor_version", "schema_name", "extractor_name"],
)
def test_fingerprint_changes(features, kind):
    data = features.model_dump()
    if kind == "value":
        data["values"] = features.input_payload() | {"failed_login_count": 41}
    elif kind == "order":
        data["feature_schema"]["features"] = tuple(reversed(data["feature_schema"]["features"]))
    elif kind.startswith("schema_"):
        data["feature_schema"][kind] = "2" if kind.endswith("version") else "new_schema"
    else:
        data["provenance"][kind] = "2" if kind.endswith("version") else "new_extractor"
    result = FeatureSet.model_validate(data)
    assert result.input_fingerprint != features.input_fingerprint


def evidence_state(record):
    state = IncidentState()
    evidence = Evidence(
        incident_id=state.incident_id,
        source=record.source,
        summary="Authentication summary",
        raw_data=record.fields,
        observed_at=record.observed_at,
    )
    return state.add_evidence(evidence), evidence


def test_evidence_binding_and_same_input_other_evidence(record):
    first, evidence = evidence_state(record)
    second, other = evidence_state(record)
    results = []
    for state, item in [(first, evidence), (second, other)]:
        before = state.model_dump_json()
        source = record_from_evidence(
            state=state,
            evidence_id=item.evidence_id,
            record_type="authentication_summary",
            record_schema_version="1.0.0",
        )
        result = AuthenticationSummaryExtractor().extract(source, state=state)
        assert result.provenance.incident_id == state.incident_id
        assert result.provenance.source_evidence_ids == (item.evidence_id,)
        assert result.provenance.source_record_ids == (source.record_id,)
        assert state.model_dump_json() == before
        results.append(result)
    assert results[0].input_fingerprint == results[1].input_fingerprint


@pytest.mark.parametrize(
    "kind",
    [
        "cross_incident",
        "unknown",
        "tampered_fields",
        "source",
        "observed_at",
        "no_state",
        "corrupt_state",
    ],
)
def test_bad_evidence_binding(record, kind):
    state, evidence = evidence_state(record)
    source = record_from_evidence(
        state=state,
        evidence_id=evidence.evidence_id,
        record_type="authentication_summary",
        record_schema_version="1.0.0",
    )
    if kind == "cross_incident":
        state = IncidentState()
    elif kind == "unknown":
        source = source.model_copy(update={"source_evidence_id": uuid4()})
    elif kind == "tampered_fields":
        source = source.model_copy(update={"fields": '{"forged":true}'})
    elif kind == "source":
        source = source.model_copy(update={"source": "forged"})
    elif kind == "observed_at":
        source = source.model_copy(update={"observed_at": utc_now()})
    elif kind == "no_state":
        state = None
    else:
        state = state.model_copy(
            update={"evidence": (evidence.model_copy(update={"incident_id": uuid4()}),)}
        )
    with pytest.raises(FeatureProvenanceError):
        AuthenticationSummaryExtractor().extract(source, state=state)


def test_unknown_evidence_and_non_json(record):
    state, evidence = evidence_state(record)
    with pytest.raises(FeatureProvenanceError):
        record_from_evidence(
            state=state, evidence_id=uuid4(), record_type="auth", record_schema_version="1"
        )
    state = IncidentState.model_validate(
        state.model_dump()
        | {"evidence": (evidence.model_copy(update={"raw_data": "SECRET_UNSTRUCTURED_LOG"}),)}
    )
    with pytest.raises(FeatureExtractionError) as error:
        record_from_evidence(
            state=state,
            evidence_id=evidence.evidence_id,
            record_type="auth",
            record_schema_version="1",
        )
    assert "SECRET_UNSTRUCTURED_LOG" not in str(error.value)


def test_duplicate_and_multiple_sources(record, features):
    kwargs = dict(
        feature_schema=features.feature_schema,
        values=features.input_payload(),
        extractor_name="fixture",
        extractor_version="1",
    )
    with pytest.raises(FeatureExtractionError):
        create_feature_set(records=(record, record), **kwargs)
    other = SecurityRecord.model_validate(
        record.model_dump()
        | {
            "record_id": uuid4(),
            "source_reference": record.source_reference.model_dump() | {"record_id": "event-43"},
        }
    )
    result = create_feature_set(records=(record, other), **kwargs)
    assert result.provenance.source_record_ids == (record.record_id, other.record_id)
    state, evidence = evidence_state(record)
    source = record_from_evidence(
        state=state,
        evidence_id=evidence.evidence_id,
        record_type="authentication_summary",
        record_schema_version="1.0.0",
    )
    duplicate = SecurityRecord.model_validate(source.model_dump() | {"record_id": uuid4()})
    with pytest.raises(FeatureExtractionError):
        create_feature_set(records=(source, duplicate), state=state, **kwargs)


def test_dataset_label_exclusion_and_duplicate_row(record, features):
    ref = DatasetRecordReference(
        dataset=DatasetSchema(
            dataset_name="fixture_network",
            dataset_version="1",
            record_schema_version="1.0.0",
            label_field="label",
        ),
        record_id="row-42",
    )
    record = SecurityRecord.model_validate(
        record.model_dump()
        | {
            "fields": record.payload() | {"label": "attack"},
            "dataset_reference": ref,
            "source_reference": SourceReference(
                source_type="dataset",
                source_name="fixture_network",
                source_version="1",
                record_id="row-42",
            ),
        }
    )
    result = AuthenticationSummaryExtractor().extract(record)
    assert result.input_fingerprint == features.input_fingerprint
    assert result.provenance.sources[0].dataset_reference == ref
    assert "label" not in result.input_payload()
    assert "attack" not in result.model_dump_json()
    duplicate = SecurityRecord.model_validate(record.model_dump() | {"record_id": uuid4()})
    with pytest.raises(FeatureExtractionError):
        create_feature_set(
            feature_schema=features.feature_schema,
            values=features.input_payload(),
            records=(record, duplicate),
            extractor_name="fixture",
            extractor_version="1",
        )
    schema = FeatureSchema(
        schema_name="leaking",
        schema_version="1",
        features=(
            FeatureDefinition(name="label", data_type="str", description="Should be rejected"),
        ),
    )
    with pytest.raises(FeatureExtractionError):
        create_feature_set(
            feature_schema=schema,
            values={"label": "attack"},
            records=(record,),
            extractor_name="fixture",
            extractor_version="1",
        )


def test_revalidate_bypassed_objects(record, features):
    broken = record.model_copy(update={"fields": '{"x":NaN}'})
    with pytest.raises(FeatureProvenanceError):
        AuthenticationSummaryExtractor().extract(broken)
    schema = features.feature_schema.model_copy(update={"schema_version": "invalid"})
    with pytest.raises(FeatureExtractionError):
        create_feature_set(
            feature_schema=schema,
            values=features.input_payload(),
            records=(record,),
            extractor_name="fixture",
            extractor_version="1",
        )


@pytest.mark.parametrize(
    "change",
    [
        {"source_type": "kafka"},
        {"source_name": ""},
        {"source_version": "latest"},
        {"record_id": ""},
        {"topic": "secret"},
        {"consumer_group": "worker"},
        {"queue_offset": 42},
        {"socket": "endpoint"},
        {"broker_connection": "secret"},
    ],
)
def test_invalid_or_transport_source_metadata(record, change):
    with pytest.raises(ValidationError):
        SourceReference.model_validate(record.source_reference.model_dump() | change)


@pytest.mark.parametrize(
    "change",
    [
        {"source_evidence_id": uuid4()},
        {"record_schema_version": ""},
        {"observed_at": datetime(2026, 1, 1)},
        {"extra": "forbidden"},
    ],
)
def test_invalid_record_contract(record, change):
    with pytest.raises(ValidationError):
        SecurityRecord.model_validate(record.model_dump() | change)


def test_source_content_detached_and_digest_tracks_raw_changes(record, features):
    payload = record.payload() | {"nested": {"items": [1]}}
    snapshot = SecurityRecord.model_validate(record.model_dump() | {"fields": payload})
    payload["nested"]["items"].append(2)
    assert snapshot.payload()["nested"]["items"] == [1]
    # Source content changes remain detectable even if an adapter reuses a record ID.
    other = SecurityRecord.model_validate(
        record.model_dump()
        | {
            "fields": record.payload() | {"successful_login_count": 3},
        }
    )
    output = AuthenticationSummaryExtractor().extract(other)
    assert (
        output.provenance.sources[0].content_digest != features.provenance.sources[0].content_digest
    )


def test_empty_and_mixed_sources_rejected(record, features):
    state, evidence = evidence_state(record)
    bound = record_from_evidence(
        state=state,
        evidence_id=evidence.evidence_id,
        record_type="authentication_summary",
        record_schema_version="1.0.0",
    )
    kwargs = dict(
        feature_schema=features.feature_schema,
        values=features.input_payload(),
        extractor_name="fixture",
        extractor_version="1",
    )
    for records in ((), (record, bound)):
        with pytest.raises(FeatureProvenanceError):
            create_feature_set(records=records, state=state, **kwargs)


def test_duplicate_stream_reference_with_different_internal_ids(record, features):
    duplicate = SecurityRecord.model_validate(record.model_dump() | {"record_id": uuid4()})
    with pytest.raises(FeatureExtractionError):
        create_feature_set(
            feature_schema=features.feature_schema,
            values=features.input_payload(),
            records=(record, duplicate),
            extractor_name="fixture",
            extractor_version="1",
        )


def test_dataset_schema_binding(record):
    dataset = DatasetSchema(
        dataset_name="fixture",
        dataset_version="1",
        record_schema_version="1.0.0",
        label_field="label",
    )
    data = record.model_dump() | {
        "source_reference": {
            "source_type": "dataset",
            "source_name": "fixture",
            "source_version": "1",
            "record_id": "row-42",
        },
        "dataset_reference": DatasetRecordReference(dataset=dataset, record_id="row-42"),
        "fields": record.payload() | {"label": "attack"},
    }
    valid = SecurityRecord.model_validate(data)
    for change in (
        {"record_schema_version": "2"},
        {"fields": record.payload()},
        {"source_reference": record.source_reference},
    ):
        with pytest.raises(ValidationError):
            SecurityRecord.model_validate(valid.model_dump() | change)


def test_huge_derived_numeric_rejected(record):
    record = SecurityRecord.model_validate(
        record.model_dump()
        | {
            "fields": record.payload()
            | {
                "failed_login_count": 10**400,
            }
        }
    )
    with pytest.raises(FeatureExtractionError):
        AuthenticationSummaryExtractor().extract(record)
