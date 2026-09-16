import hashlib
import json
from pathlib import Path

import pytest

from soc_agent.security_ai.features import FeatureSet
from soc_agent.security_ai.network.artifacts import load_artifact, save_artifact
from soc_agent.security_ai.network.dataset import PreparedDataset
from soc_agent.security_ai.network.training import TrainingConfig, evaluate, split_dataset, train


def test_split_reproducibility_and_isolation(dataset: PreparedDataset) -> None:
    first = split_dataset(dataset)
    assert first == split_dataset(dataset)
    assert first != split_dataset(dataset, seed=123)
    for a, b in (
        (first.train, first.validation),
        (first.train, first.test),
        (first.validation, first.test),
    ):
        assert not set(a) & set(b)
        assert not {first.groups[i] for i in a} & {first.groups[i] for i in b}
        assert not {first.fingerprints[i] for i in a} & {first.fingerprints[i] for i in b}
    for part in (first.train, first.validation, first.test):
        assert {dataset.examples[i].label for i in part} == {
            "BENIGN",
            "BruteForce",
            "DoS",
            "PortScan",
        }


def test_rare_or_unseparable_groups_fail(dataset: PreparedDataset) -> None:
    for examples in (
        dataset.examples[:3],
        tuple(e.model_copy(update={"group_id": "one-day"}) for e in dataset.examples),
    ):
        with pytest.raises(ValueError):
            split_dataset(dataset.model_copy(update={"examples": examples}))


def test_duplicate_inputs_grouped_and_conflicting_labels_fail(dataset: PreparedDataset) -> None:
    duplicate = dataset.examples[0].model_copy(update={"row_id": "duplicate:1", "group_id": "new"})
    expanded = dataset.model_copy(update={"examples": (*dataset.examples, duplicate)})
    split = split_dataset(expanded)
    assert split.groups[0] == split.groups[-1]
    corrupted = duplicate.model_copy(update={"label": "conflicting"})
    with pytest.raises(ValueError, match="conflicting labels"):
        split_dataset(dataset.model_copy(update={"examples": (*dataset.examples, corrupted)}))


def test_evaluation_known_values() -> None:
    metrics = evaluate([0, 0, 1, 1], [0, 1, 1, 1], ("A", "B"))
    assert metrics.accuracy == 0.75
    assert metrics.confusion_matrix == ((1, 1), (0, 2))
    assert metrics.macro_recall == 0.75
    assert metrics.macro_precision == pytest.approx((1 + 2 / 3) / 2)
    assert metrics.macro_f1 == pytest.approx((2 / 3 + 0.8) / 2)
    assert metrics.weighted_f1 == metrics.macro_f1


def test_train_predict_artifact(dataset: PreparedDataset, tmp_path: Path) -> None:
    config = TrainingConfig(n_estimators=5, max_depth=2)
    result = train(dataset, config=config)
    parameters = json.loads(result.metadata.hyperparameters)
    assert parameters["objective"] == "multi:softprob"
    assert parameters["device"] == "cpu" and parameters["nthread"] == 1
    feature = dataset.examples[0].features
    prediction = result.classifier.predict(feature)
    assert result.metadata.contract.classes == ("BENIGN", "BruteForce", "DoS", "PortScan")
    assert {p.label for p in prediction.class_probabilities} == set(
        result.metadata.contract.classes
    )
    assert sum(p.probability for p in prediction.class_probabilities) == pytest.approx(1, abs=1e-5)
    assert 0 <= prediction.confidence <= 1
    assert len(result.metadata.test.confusion_matrix) == 4
    assert sum(p.support for p in result.metadata.test.per_class) == len(result.metadata.split.test)
    path = save_artifact(result, tmp_path)
    expected = hashlib.sha256((path / "manifest.json").read_bytes()).hexdigest()
    loaded = load_artifact(path, expected_manifest_digest=expected)
    assert loaded.metadata == result.metadata
    assert loaded.classifier.predict(feature) == prediction
    with pytest.raises(FileExistsError):
        save_artifact(result, tmp_path)
    repeated = train(dataset, config=config)
    assert repeated.metadata == result.metadata
    assert repeated.classifier.predict(feature) == prediction
    repeated_path = save_artifact(repeated, tmp_path / "repeated")
    assert (repeated_path / "manifest.json").read_bytes() == (path / "manifest.json").read_bytes()


@pytest.mark.parametrize("kind", ["schema_name", "schema_version", "order", "extractor", "missing"])
def test_runtime_contract_mismatch(dataset: PreparedDataset, kind: str) -> None:
    result = train(dataset, config=TrainingConfig(n_estimators=2))
    data = dataset.examples[0].features.model_dump()
    if kind == "schema_name":
        data["feature_schema"]["schema_name"] = "another_schema"
    elif kind == "schema_version":
        data["feature_schema"]["schema_version"] = "2"
    elif kind == "order":
        data["feature_schema"]["features"] = tuple(reversed(data["feature_schema"]["features"]))
    elif kind == "extractor":
        data["provenance"]["extractor_version"] = "2"
    else:
        data["values"] = "{}"
    with pytest.raises(ValueError):
        result.classifier.predict(FeatureSet.model_validate(data))


@pytest.mark.parametrize("file", ["model.json", "metadata.json", "manifest.json"])
def test_artifact_tampering(dataset: PreparedDataset, tmp_path: Path, file: str) -> None:
    path = save_artifact(train(dataset, config=TrainingConfig(n_estimators=2)), tmp_path)
    original = hashlib.sha256((path / "manifest.json").read_bytes()).hexdigest()
    with (path / file).open("ab") as stream:
        stream.write(b"tampered")
    with pytest.raises(ValueError, match="artifact"):
        load_artifact(path, expected_manifest_digest=original)


def test_metadata_rehash_still_bound_to_model(dataset: PreparedDataset, tmp_path: Path) -> None:
    path = save_artifact(train(dataset, config=TrainingConfig(n_estimators=2)), tmp_path)
    data = json.loads((path / "metadata.json").read_text())
    data["config"]["seed"] = 123
    parameters = json.loads(data["hyperparameters"])
    parameters["seed"] = 123
    data["hyperparameters"] = json.dumps(parameters)
    payload = json.dumps(data).encode()
    (path / "metadata.json").write_bytes(payload)
    manifest = json.loads((path / "manifest.json").read_text())
    manifest["metadata_sha256"] = hashlib.sha256(payload).hexdigest()
    (path / "manifest.json").write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="artifact"):
        load_artifact(path)
