import json
from datetime import UTC, datetime, timedelta, timezone

import numpy as np
import pytest
from pydantic import ValidationError
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from tests.authentication_support import fixture_examples, record

from soc_agent.security_ai.authentication import (
    AnomalyTrainingConfig,
    AuthenticationEvent,
    AuthenticationExample,
    AuthenticationWindowExtractor,
    authentication_record,
    split_authentication,
    train_authentication,
)
from soc_agent.security_ai.authentication.anomaly import feature_matrix
from soc_agent.security_ai.features import FeatureSet, SourceReference


@pytest.fixture(scope="module")
def examples():
    return fixture_examples()


@pytest.fixture(scope="module")
def trained(examples):
    return train_authentication(examples, config=AnomalyTrainingConfig(n_estimators=8))


@pytest.mark.parametrize(
    "change",
    [
        {"authentication_result": "unknown"},
        {"event_id": " "},
        {"account_id": ""},
        {"source_identifier": ""},
        {"event_time": datetime(2026, 1, 1)},
        {"label": "attack"},
    ],
)
def test_invalid_event(change):
    with pytest.raises(ValueError):
        AuthenticationEvent.model_validate(record().payload() | change)


@pytest.mark.parametrize("duplicate", ["same", "other_source", "other_account"])
def test_duplicate_event(duplicate):
    first = record()
    second = (
        first
        if duplicate == "same"
        else record(account="bob" if duplicate == "other_account" else "alice", kind="stream")
    )
    with pytest.raises(ValueError, match="Duplicate"):
        AuthenticationWindowExtractor().extract((first, second))


def test_boundaries_accounts_and_order():
    records = (
        record("a", seconds=299.999999),
        record("b", seconds=300),
        record("c", account="bob"),
        record("d", result="success"),
    )
    forward = AuthenticationWindowExtractor().extract(records)
    reverse = AuthenticationWindowExtractor().extract(tuple(reversed(records)))
    assert len(forward) == 3
    assert forward[0].event_ids == ("d", "a")
    assert forward[1].event_ids == ("b",)
    assert forward[2].account_id == "bob"
    for a, b in zip(forward, reverse, strict=True):
        assert a.features.input_fingerprint == b.features.input_fingerprint
        assert a.features.provenance == b.features.provenance
    assert forward[0].features.feature_values == (1, 1, 2, 0.5, 2 / 300)
    assert forward[0].ended_at == forward[1].started_at
    assert AuthenticationWindowExtractor().extract(()) == ()


def test_timezone_normalized():
    event = AuthenticationEvent.model_validate(
        record().payload()
        | {"event_time": datetime(2026, 1, 1, 9, tzinfo=timezone(timedelta(hours=9)))}
    )
    source = SourceReference(source_type="stream", source_name="auth", record_id="a")
    window = AuthenticationWindowExtractor().extract(
        (authentication_record(event, source=source),)
    )[0]
    assert window.started_at == datetime(2026, 1, 1, tzinfo=UTC)


def test_identifiers_excluded_and_provenance():
    a = AuthenticationWindowExtractor().extract((record(),))[0].features
    b = (
        AuthenticationWindowExtractor()
        .extract((record("other", account="bob", kind="stream"),))[0]
        .features
    )
    assert a.input_fingerprint == b.input_fingerprint
    assert a.provenance != b.provenance
    assert a.feature_names == (
        "failed_login_count",
        "successful_login_count",
        "total_login_count",
        "failure_rate",
        "login_attempt_rate",
    )
    assert a.feature_schema.schema_name == "authentication_behavior_features"
    assert a.feature_schema.schema_version == "1.0.0"
    assert a.provenance.sources[0].source_reference.record_id == "e1"
    with pytest.raises(ValidationError):
        a.provenance.extractor_version = "2"


@pytest.mark.parametrize("change", [{"label": "normal"}, {"authentication_result": "pending"}])
def test_raw_extra_unknown_rejected(change):
    r = record()
    r = r.model_copy(update={"fields": json.dumps(r.payload() | change)})
    with pytest.raises(ValueError):
        AuthenticationWindowExtractor().extract((r,))


def test_training_split_and_train_only_fit(examples, monkeypatch):
    old_scaler, old_forest = StandardScaler.fit, IsolationForest.fit
    captured = {}

    def scaler(self, x, y=None, **kwargs):
        assert y is None
        captured["scaler"] = x.copy()
        return old_scaler(self, x, y, **kwargs)

    def forest(self, x, y=None, **kwargs):
        assert y is None
        captured["forest"] = x.copy()
        return old_forest(self, x, y, **kwargs)

    monkeypatch.setattr(StandardScaler, "fit", scaler)
    monkeypatch.setattr(IsolationForest, "fit", forest)
    result = train_authentication(examples, config=AnomalyTrainingConfig(n_estimators=8))
    split = result.metadata.split
    assert split == split_authentication(examples)
    assert len(split.train) == 18 and len(split.validation) == len(split.test) == 6
    for field in ("group_id",):
        sets = [
            {getattr(examples[i], field) for i in part}
            for part in (split.train, split.validation, split.test)
        ]
        assert not sets[0] & sets[1] and not sets[0] & sets[2] and not sets[1] & sets[2]
    baseline = result.metadata.baseline_indices
    assert all(examples[i].label == "normal" for i in baseline)
    assert set(baseline) <= set(split.train)
    expected = feature_matrix(tuple(examples[i].features for i in baseline)).astype(np.float64)
    np.testing.assert_array_equal(captured["scaler"], expected)
    np.testing.assert_array_equal(
        captured["forest"], result.detector.profile.scaler.transform(expected)
    )
    np.testing.assert_allclose(result.detector.profile.scaler.mean, expected.mean(axis=0))
    assert captured["scaler"].shape == (9, 5)


def test_deterministic_fixed_runtime(examples, trained, monkeypatch):
    other = train_authentication(examples, config=AnomalyTrainingConfig(n_estimators=8))
    assert other.metadata == trained.metadata

    def forbidden(*args, **kwargs):
        pytest.fail("runtime fitted a model")

    monkeypatch.setattr(StandardScaler, "fit", forbidden)
    monkeypatch.setattr(IsolationForest, "fit", forbidden)
    before = trained.detector.profile.model_dump_json()
    first = trained.detector.predict(examples[0].features)
    for e in reversed(examples):
        p = trained.detector.predict(e.features)
        assert p == other.detector.predict(e.features)
        assert 0 <= p.anomaly_score <= 1
        assert p.is_anomaly == (p.anomaly_score >= p.threshold)
        assert p.raw_anomaly_measure == -p.raw_score
        assert p.feature_fingerprint == e.features.input_fingerprint
        assert p.behavior.model_dump() == e.features.input_payload()
    assert first == trained.detector.predict(examples[0].features)
    assert before == trained.detector.profile.model_dump_json()
    with pytest.raises(ValidationError):
        first.threshold = 0.1


@pytest.mark.parametrize(
    "kind",
    [
        "name",
        "version",
        "order",
        "missing",
        "extra",
        "extractor",
        "nan",
        "inf",
        "negative",
        "rate",
        "zero",
    ],
)
def test_runtime_fail_closed(kind, examples, trained):
    f = examples[0].features
    data = f.model_dump()
    if kind in {"name", "version"}:
        data["feature_schema"]["schema_" + kind] = "other" if kind == "name" else "2"
    elif kind == "order":
        data["feature_schema"]["features"] = tuple(reversed(data["feature_schema"]["features"]))
    elif kind == "extractor":
        data["provenance"]["extractor_version"] = "2"
    else:
        values = f.input_payload()
        if kind == "missing":
            del values["total_login_count"]
        elif kind == "extra":
            values["account_id"] = "secret"
        elif kind == "rate":
            values["failure_rate"] = 0.9
        elif kind == "zero":
            values["total_login_count"] = 0
        else:
            values["failure_rate"] = {"nan": float("nan"), "inf": float("inf"), "negative": -1.0}[
                kind
            ]
        data["values"] = values
    with pytest.raises(ValueError):
        trained.detector.predict(FeatureSet.model_validate(data))


def test_impossible_split_no_fallback(examples):
    with pytest.raises(ValueError, match="five independent"):
        split_authentication(examples[:4])
    with pytest.raises(ValueError):
        train_authentication(tuple(e.model_copy(update={"label": "unknown"}) for e in examples))
    with pytest.raises(ValueError, match="multiple training windows"):
        split_authentication(examples + (examples[0],))


def test_duplicate_fingerprint_unions_accounts(examples):
    # A new account with the same measurements must join the original account's partition.
    windows = AuthenticationWindowExtractor().extract(
        tuple(record(f"clone-{i}", account="clone", result="success") for i in range(4))
    )
    clone = AuthenticationExample(window=windows[0], label="normal")
    extended = examples + (clone,)
    split = split_authentication(extended)
    assert split.groups[0] == split.groups[-1]
    for part in (split.train, split.validation, split.test):
        assert (0 in part) == (len(examples) in part)
    with pytest.raises(ValueError, match="conflicting labels"):
        split_authentication(examples + (clone.model_copy(update={"label": "anomalous"}),))


@pytest.mark.parametrize("kind", ["width", "alignment", "count", "duplicate", "source_time"])
def test_window_invariants(kind, examples):
    from soc_agent.security_ai.authentication import AuthenticationWindow

    data = examples[0].window.model_dump()
    if kind == "width":
        data["ended_at"] += timedelta(seconds=1)
    elif kind == "alignment":
        data["started_at"] += timedelta(seconds=1)
        data["ended_at"] += timedelta(seconds=1)
    elif kind == "count":
        data["event_ids"] = data["event_ids"][:-1]
    elif kind == "duplicate":
        data["event_ids"] = (data["event_ids"][0],) * len(data["event_ids"])
    else:
        data["features"]["provenance"]["sources"][0]["observed_at"] += timedelta(hours=1)
    with pytest.raises(ValueError):
        AuthenticationWindow.model_validate(data)


@pytest.mark.parametrize("kind", ["threshold", "scaler", "population", "max_samples"])
def test_profile_binding(kind, trained):
    from soc_agent.security_ai.authentication.anomaly import AuthenticationInferenceProfile

    data = trained.detector.profile.model_dump()
    if kind == "threshold":
        data["normalization"]["threshold"] = 0.1
    elif kind == "scaler":
        data["scaler"]["mean"] = (1.0,)
    elif kind == "population":
        data["scaler"]["samples"] = 100
    else:
        data["fitted_max_samples"] = 100
    with pytest.raises(ValueError):
        AuthenticationInferenceProfile.model_validate(data)


def test_evidence_binding_without_state_mutation():
    from soc_agent.security_ai.features import record_from_evidence
    from soc_agent.state import Evidence, IncidentState

    state = IncidentState()
    raw = record()
    evidence = Evidence(
        incident_id=state.incident_id,
        source="auth_log",
        summary="Failed login",
        raw_data=raw.fields,
        observed_at=raw.observed_at,
    )
    state = state.add_evidence(evidence)
    before = state.model_dump_json()
    source = record_from_evidence(
        state=state,
        evidence_id=evidence.evidence_id,
        record_type="authentication_event",
        record_schema_version="1.0.0",
    )
    window = AuthenticationWindowExtractor().extract((source,), state=state)[0]
    assert window.features.provenance.source_evidence_ids == (evidence.evidence_id,)
    assert state.model_dump_json() == before
    with pytest.raises(ValueError):
        AuthenticationWindowExtractor().extract((source,), state=IncidentState())
    with pytest.raises(ValueError):
        AuthenticationWindowExtractor().extract(
            (source,), state=state.model_copy(update={"evidence": ()})
        )


def test_late_events_recompute_finite_batch():
    extractor = AuthenticationWindowExtractor()
    initial = extractor.extract((record("later", seconds=299, result="success"),))
    updated = extractor.extract(
        (record("later", seconds=299, result="success"), record("late", seconds=1))
    )
    assert initial[0].features.feature_values == (0, 1, 1, 0.0, 1 / 300)
    assert updated[0].event_ids == ("late", "later")
    assert updated[0].features.feature_values == (1, 1, 2, 0.5, 2 / 300)
    assert initial[0].features.input_fingerprint != updated[0].features.input_fingerprint


def test_empty_or_normal_only_training_rejected(examples):
    with pytest.raises(ValueError):
        train_authentication(())
    with pytest.raises(ValueError, match="five independent"):
        train_authentication(tuple(e for e in examples if e.label == "normal"))


def test_no_auth_dependency_on_network():
    import ast
    from pathlib import Path

    import soc_agent.security_ai.authentication as package

    for path in Path(package.__file__).parent.glob("*.py"):
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.ImportFrom):
                assert not (node.module or "").startswith("soc_agent.security_ai.network")
