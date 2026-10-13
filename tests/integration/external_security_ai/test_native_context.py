"""Explicit native backend environment; no fake predictor is completion evidence."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


def test_three_native_models_adapter_and_source_bound_context(tmp_path):
    root = os.environ.get("SOC_EXTERNAL_ARTIFACT_ROOT")
    interpreter = os.environ.get("SOC_EXTERNAL_INFERENCE_PYTHON", sys.executable)
    if not root:
        pytest.skip(
            "Native external artifact root not configured; run documented explicit validation"
        )
    output = tmp_path / "native-context.json"
    process = subprocess.run(
        [
            interpreter,
            "-m",
            "tests.diagnose_external_context",
            "--artifact-root",
            root,
            "--output",
            str(output),
        ],
        env={**os.environ, "PYTHONPATH": str(Path("src").resolve()), "RUN_LIVE_LLM_TESTS": "0"},
        capture_output=True,
        timeout=180,
        check=False,
    )
    # Do not dump backend output, model contents or raw source data on failure.
    assert process.returncode == 0, "Native external context smoke failed; no fallback"
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["native_inference_calls"] == 3
    assert report["provider_calls"] == report["database_writes"] == report["action_calls"] == 0
    context = report["context"]
    assert len(context["results"]) == 3
    assert len(context["correlation_groups"]) == 2
    assert not context["unlinked_results"]
    assert all(r["validation"]["status"] == "VALIDATED_FOR_ADVISORY" for r in context["results"])
    assert context["uncertainty"] == "UNKNOWN"
    # Exclusive output creation must refuse a collision before another inference run.
    collision = subprocess.run(
        [
            interpreter,
            "-m",
            "tests.diagnose_external_context",
            "--artifact-root",
            root,
            "--output",
            str(output),
        ],
        env={**os.environ, "PYTHONPATH": str(Path("src").resolve())},
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert collision.returncode != 0
    assert json.loads(output.read_text(encoding="utf-8")) == report
