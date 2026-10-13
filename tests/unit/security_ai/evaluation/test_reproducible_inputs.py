"""Pinned synthetic input and explicitly versioned offline probabilities."""

import hashlib
import json
from dataclasses import replace
from decimal import ROUND_DOWN, localcontext
from pathlib import Path

import numpy as np
import pytest
from tests import evaluation_support as support

from soc_agent.security_ai.evaluation import partitions, select_classifier
from soc_agent.security_ai.evaluation.reference_probability import (
    REFERENCE_SOFTMAX,
    reference_softmax,
)
from soc_agent.security_ai.network.classifier import ModelContract
from soc_agent.security_ai.network.preprocessing import feature_matrix
from soc_agent.security_ai.network.training import TrainingConfig
from soc_agent.security_ai.packaging import save_package


def test_pinned_draws_do_not_execute_native_rng_and_preserve_historical_audit(
    tmp_path, monkeypatch
):
    def forbidden(*args, **kwargs):
        raise AssertionError("Native RNG used for pinned input")

    monkeypatch.setattr(np.random, "default_rng", forbidden)
    rows, _ = support.network_rows(tmp_path / "development.csv")
    train, _, _, _ = partitions(
        rows, dataset_name="synthetic-network-development", dataset_version="1"
    )
    report = json.loads(Path("docs/evaluation/synthetic-phase3-5.json").read_text(encoding="utf-8"))
    for kind in ("network_classifier", "network_anomaly"):
        assert (
            train.content_digest == report["experiments"][kind]["selection"]["audits"][0]["digest"]
        )
    matrix = feature_matrix(
        tuple(r.features for r in train.rows),
        ModelContract(classes=("BENIGN", "BruteForce", "DoS", "PortScan")),
    )
    assert matrix.dtype == np.float32 and matrix.shape == (240, 5)
    # Pinned binary32 matrix independent of file location and native lognormal.
    assert hashlib.sha256(matrix.astype("<f4").tobytes()).hexdigest() == MATRIX_SHA256


MATRIX_SHA256 = "30395f1da7ff8e42390bb5862eaee8c298ec6fb62863801f3a796cb3a2d4be92"


def test_fixture_tampering_and_capacity_fail_closed(tmp_path, monkeypatch):
    path = tmp_path / "draws.json"
    path.write_bytes(support.DRAW_FIXTURE.read_bytes() + b" ")
    monkeypatch.setattr(support, "DRAW_FIXTURE", path)
    with pytest.raises(ValueError, match="integrity"):
        support.fixed_network_draws(3501, 400)
    monkeypatch.undo()
    with pytest.raises(ValueError, match="capacity"):
        support.fixed_network_draws(3501, 401)


MARGIN_HEX = (
    "-0x1.21400c0000000p+0",
    "-0x1.1f29120000000p+0",
    "-0x1.d97c7e0000000p-1",
    "0x1.5f8f060000000p+0",
)
PROBABILITY_HEX = (
    "0x1.08feb5015ce09p-4",
    "0x1.0b2abf4b8bfcbp-4",
    "0x1.455281f72c7edp-4",
    "0x1.94d081377d548p-1",
)


def test_identical_margin_has_exact_reference_probabilities_and_brier():
    margin = np.asarray([[float.fromhex(v) for v in MARGIN_HEX]], dtype=np.float32)
    first = reference_softmax(margin)
    with localcontext() as context:
        context.prec = 5
        context.rounding = ROUND_DOWN
        repeated = reference_softmax(margin)
    assert first.dtype == np.float64
    assert tuple(v.hex() for v in first[0]) == PROBABILITY_HEX
    assert np.array_equal(first, repeated)
    target = np.asarray([[0, 0, 0, 1]])
    assert np.mean(np.sum((first - target) ** 2, axis=1)) == np.mean(
        np.sum((repeated - target) ** 2, axis=1)
    )


@pytest.mark.parametrize(
    "margin",
    [
        np.array([[np.nan, 0.0]]),
        np.array([[np.inf, 0.0]]),
        np.array([1.0, 2.0]),
        np.array([[1, 2]]),
    ],
)
def test_reference_probability_rejects_invalid_margins(margin):
    with pytest.raises(ValueError):
        reference_softmax(margin)


def test_reference_mode_repeats_and_cannot_masquerade_as_native_package(tmp_path):
    rows, _ = support.network_rows(tmp_path / "development.csv", count=10)
    train, validation, _, _ = partitions(rows, dataset_name="synthetic-repro", dataset_version="1")
    options = {"configs": (TrainingConfig(n_estimators=8),)}
    native = select_classifier(train, validation, **options)
    reference = select_classifier(
        train, validation, probability_transform=REFERENCE_SOFTMAX, **options
    )
    repeated = select_classifier(
        train, validation, probability_transform=REFERENCE_SOFTMAX, **options
    )
    assert reference.freeze_digest == repeated.freeze_digest
    assert reference.freeze_digest != native.freeze_digest
    assert reference.report.selected_candidate == native.report.selected_candidate
    assert (
        reference.report.candidates[0].validation.classification
        == native.report.candidates[0].validation.classification
    )
    assert (
        json.loads(reference.report.selected_binding)["evaluation_probability_transform"]
        == REFERENCE_SOFTMAX
    )
    with pytest.raises(ValueError, match="binding"):
        save_package(reference, tmp_path / "must-not-exist")
    assert not (tmp_path / "must-not-exist").exists()
    with pytest.raises(ValueError, match="Frozen model/configuration"):
        replace(reference, probability_transform="native")
