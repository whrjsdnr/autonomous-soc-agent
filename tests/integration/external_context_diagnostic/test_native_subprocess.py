"""Native backends are explicitly configured; no fake predictor proves native integration."""

import os
import subprocess
import sys
from pathlib import Path

import pytest


def test_native_models_core_components_and_receipts():
    if not os.environ.get("SOC_EXTERNAL_ARTIFACT_ROOT"):
        pytest.skip("External native artifact root not configured; explicit validation required")
    interpreter = os.environ.get("SOC_EXTERNAL_INFERENCE_PYTHON", sys.executable)
    result = subprocess.run(
        [
            interpreter,
            "-m",
            "pytest",
            "-q",
            "tests/native_external_decision_checks.py",
            "--tb=short",
        ],
        env={**os.environ, "PYTHONPATH": str(Path("src").resolve()), "RUN_LIVE_LLM_TESTS": "0"},
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=180,
        check=False,
    )
    assert result.returncode == 0, (
        "Native component/receipt validation failed; no fallback or raw backend dump"
    )
    assert "4 passed" in result.stdout
