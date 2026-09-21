import json
import shutil
from dataclasses import replace

import numpy as np
import pytest

from soc_agent.security_ai.packaging import load_package
from soc_agent.security_ai.packaging.files import MAX_FILE_BYTES, sha256
from soc_agent.security_ai.packaging.forest import NumericForest

KINDS = ("network_classifier", "network_anomaly", "authentication_anomaly")


@pytest.mark.parametrize("kind", KINDS)
def test_roundtrip_all_development_rows(packages, kind):
    selection, rows, _, _, loaded = packages[kind]
    assert loaded.manifest.selection_digest == selection.freeze_digest
    assert loaded.manifest.model_id == selection.report.model_name
    assert loaded.manifest.model_version == selection.report.model_version
    for row in rows:
        expected = selection.selected_model.predict(row.features)
        actual = loaded.predict(row.features)
        if kind == "network_classifier":
            assert actual == expected
        else:
            assert actual.raw_anomaly_measure == expected.raw_anomaly_measure
            assert actual.anomaly_score == expected.anomaly_score
            assert actual.is_anomaly == expected.is_anomaly
            assert (
                loaded.operating_decision(actual)
                == selection.point.decisions(
                    (expected.raw_anomaly_measure,), (expected.anomaly_score,)
                )[0]
            )


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize(
    "name", ("manifest.json", "metadata.json", "model/model.json", "preprocessing/profile.json")
)
def test_file_tampering(packages, tmp_path, kind, name):
    _, _, path, pin, _ = packages[kind]
    target = tmp_path / "package"
    shutil.copytree(path, target)
    with (target / name).open("ab") as stream:
        stream.write(b" ")
    with pytest.raises(ValueError, match="digest"):
        load_package(target, expected_manifest_digest=pin)


def repin(target, name, data):
    (target / name).write_text(json.dumps(data))
    manifest = json.loads((target / "manifest.json").read_text())
    for item in manifest["file_hashes"]:
        if item["path"] == name:
            item["sha256"] = sha256((target / name).read_bytes())
    (target / "manifest.json").write_text(json.dumps(manifest))
    return sha256((target / "manifest.json").read_bytes())


@pytest.mark.parametrize(
    "change",
    (
        "order",
        "class",
        "scaler",
        "reference",
        "threshold",
        "dimension",
        "tree_index",
        "tree_type",
        "tree_length",
    ),
)
def test_semantic_validation_even_with_rehashed_inventory(packages, tmp_path, change):
    kind = "network_classifier" if change in {"order", "class", "dimension"} else "network_anomaly"
    target = tmp_path / "package"
    shutil.copytree(packages[kind][2], target)
    name = (
        "model/model.json"
        if change.startswith("tree") or change == "dimension"
        else "preprocessing/profile.json"
    )
    data = json.loads((target / name).read_text())
    if change == "order":
        data["feature_schema"]["features"].reverse()
    elif change == "class":
        data["classes"] = ["A", "B", "C", "D"]
    elif change == "scaler":
        data["scaler"]["mean"][0] += 1
    elif change == "reference":
        data["normalization"]["sorted_measures"][0] -= 0.01
    elif change == "threshold":
        data["normalization"]["threshold"] = 0.8
    elif change == "dimension":
        data["learner"]["learner_model_param"]["num_class"] = "3"
    elif change == "tree_index":
        data["trees"][0]["left"][0] = 999999
    elif change == "tree_type":
        data["trees"][0]["left"][0] = 1.5
    elif change == "tree_length":
        data["trees"][0]["samples"].pop()
    pin = repin(target, name, data)
    with pytest.raises(ValueError):
        load_package(target, expected_manifest_digest=pin)


@pytest.mark.parametrize(
    "change",
    (
        "missing",
        "extra",
        "nested_extra",
        "symlink",
        "directory_symlink",
        "oversized",
        "traversal",
        "absolute",
        "duplicate",
        "format",
        "json_duplicate",
        "fifo",
    ),
)
def test_inventory_rejection(packages, tmp_path, change):
    target = tmp_path / "package"
    shutil.copytree(packages["network_anomaly"][2], target)
    pin = packages["network_anomaly"][3]
    if change == "missing":
        (target / "metadata.json").unlink()
    elif change == "extra":
        (target / "extra.json").write_text("{}")
    elif change == "nested_extra":
        (target / "model/extra.json").write_text("{}")
    elif change == "symlink":
        (target / "metadata.json").unlink()
        (target / "metadata.json").symlink_to(packages["network_anomaly"][2] / "metadata.json")
    elif change == "directory_symlink":
        shutil.rmtree(target / "model")
        (target / "model").symlink_to(
            packages["network_anomaly"][2] / "model", target_is_directory=True
        )
    elif change == "oversized":
        with (target / "metadata.json").open("wb") as stream:
            stream.truncate(MAX_FILE_BYTES + 1)
    elif change == "fifo":
        import os

        (target / "metadata.json").unlink()
        os.mkfifo(target / "metadata.json")
    elif change == "json_duplicate":
        (target / "manifest.json").write_text('{"model_id":"a","model_id":"b"}')
        pin = sha256((target / "manifest.json").read_bytes())
    else:
        data = json.loads((target / "manifest.json").read_text())
        if change == "traversal":
            data["file_hashes"][0]["path"] = "../metadata.json"
        elif change == "absolute":
            data["file_hashes"][0]["path"] = "/tmp/metadata.json"
        elif change == "duplicate":
            data["file_hashes"][1] = data["file_hashes"][0]
        elif change == "format":
            data["file_hashes"][0]["path"] = "model/model.pkl"
        (target / "manifest.json").write_text(json.dumps(data))
        pin = sha256((target / "manifest.json").read_bytes())
    with pytest.raises(ValueError):
        load_package(target, expected_manifest_digest=pin)


@pytest.mark.parametrize("kind", ("network_anomaly", "authentication_anomaly"))
def test_forest_split_boundaries_and_ties(packages, kind):
    selection, rows, _, _, loaded = packages[kind]
    model = selection.selected_model._model
    forest = loaded.model
    # In scaled model space: exact thresholds and adjacent float32 values.
    inputs = [np.zeros(forest.n_features), np.full(forest.n_features, 1e8)]
    for tree in forest.trees[:4]:
        for feature, threshold in zip(tree.feature, tree.threshold, strict=True):
            if feature < 0:
                continue
            for value in (
                np.float32(threshold),
                np.nextafter(np.float32(threshold), np.float32(-np.inf)),
                np.nextafter(np.float32(threshold), np.float32(np.inf)),
            ):
                row = np.zeros(forest.n_features)
                row[feature] = value
                inputs.append(row)
    matrix = np.asarray(inputs)
    np.testing.assert_array_equal(forest.score_samples(matrix), model.score_samples(matrix))
    prediction = loaded.predict(rows[0].features)
    from soc_agent.security_ai.evaluation.metrics import OperatingPoint

    equal = replace(
        loaded,
        manifest=loaded.manifest.model_copy(
            update={
                "operating_point": OperatingPoint(
                    space="raw", threshold=prediction.raw_anomaly_measure
                )
            }
        ),
    )
    assert equal.operating_decision(prediction)
    above = replace(
        loaded,
        manifest=loaded.manifest.model_copy(
            update={
                "operating_point": OperatingPoint(
                    space="raw",
                    threshold=float(np.nextafter(prediction.raw_anomaly_measure, np.inf)),
                )
            }
        ),
    )
    assert not above.operating_decision(prediction)
    reference = loaded.profile.normalization
    tied = reference.model_copy(update={"sorted_measures": (prediction.raw_anomaly_measure,) * 4})
    assert tied.normalize(prediction.raw_anomaly_measure) == 0.5
    assert reference.normalize(
        reference.sorted_measures[0]
    ) == selection.selected_model.profile.normalization.normalize(reference.sorted_measures[0])


def test_invalid_numeric_forest():
    from soc_agent.security_ai.packaging.forest import NumericTree

    leaf = NumericTree(left=(-1,), right=(-1,), feature=(-2,), threshold=(-2.0,), samples=(2,))
    forest = NumericForest(n_features=1, max_samples=2, trees=(leaf,))
    np.testing.assert_array_equal(forest.score_samples(np.array([[0.0], [1.0]])), [-0.5, -0.5])
    with pytest.raises(ValueError):
        forest.score_samples(np.array([[float("nan")]]))


@pytest.mark.parametrize("kind", KINDS)
def test_load_never_fits_and_save_never_overwrites(packages, kind, monkeypatch):
    import xgboost
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler

    from soc_agent.security_ai.packaging import save_package

    selection, rows, path, pin, _ = packages[kind]

    def forbidden(*args, **kwargs):
        pytest.fail("Load attempted fitting")

    monkeypatch.setattr(IsolationForest, "fit", forbidden)
    monkeypatch.setattr(StandardScaler, "fit", forbidden)
    monkeypatch.setattr(xgboost, "train", forbidden)
    loaded = load_package(path, expected_manifest_digest=pin)
    loaded.predict(rows[0].features)
    before = (path / "manifest.json").read_bytes()
    with pytest.raises(FileExistsError):
        save_package(selection, path)
    assert (path / "manifest.json").read_bytes() == before


@pytest.mark.parametrize(
    "change", ("cycle", "unreachable", "shared", "feature", "samples", "nan", "string", "extra")
)
def test_tree_structure_rejected(change):
    data = {
        "n_features": 1,
        "max_samples": 2,
        "trees": [
            {
                "left": [1, -1, -1],
                "right": [2, -1, -1],
                "feature": [0, -2, -2],
                "threshold": [0.5, -2.0, -2.0],
                "samples": [2, 1, 1],
            }
        ],
    }
    tree = data["trees"][0]
    if change == "cycle":
        tree["left"][0] = 0
    elif change == "unreachable":
        data["max_samples"] = 3
        tree["samples"][0] = 3
        for name, value in (
            ("left", -1),
            ("right", -1),
            ("feature", -2),
            ("threshold", -2.0),
            ("samples", 1),
        ):
            tree[name].append(value)
    elif change == "shared":
        tree["right"][0] = 1
    elif change == "feature":
        tree["feature"][0] = 1
    elif change == "samples":
        tree["samples"][1] = 0
    elif change == "nan":
        tree["threshold"][0] = float("nan")
    elif change == "string":
        tree["threshold"][0] = "0.5"
    elif change == "extra":
        tree["callable"] = "untrusted"
    with pytest.raises(ValueError):
        NumericForest.model_validate(data)


def test_parent_symlink_rejected(packages, tmp_path):
    link = tmp_path / "parent-link"
    link.symlink_to(packages["network_anomaly"][2].parent, target_is_directory=True)
    with pytest.raises(ValueError):
        load_package(
            link / "network_anomaly", expected_manifest_digest=packages["network_anomaly"][3]
        )


def test_reference_ties_and_normalized_boundary_roundtrip():
    from soc_agent.security_ai.anomaly_common import AnomalyScoreReference

    reference = AnomalyScoreReference(
        sorted_measures=(0.2, 0.5, 0.5, 0.8), threshold=0.5, sklearn_offset=-0.5
    )
    restored = AnomalyScoreReference.model_validate_json(reference.model_dump_json())
    assert restored == reference
    for raw, expected in ((0.1, 0), (0.5, 0.5), (0.9, 1)):
        assert restored.normalize(raw) == reference.normalize(raw) == expected
        assert (restored.normalize(raw) >= restored.threshold) == (expected >= 0.5)
