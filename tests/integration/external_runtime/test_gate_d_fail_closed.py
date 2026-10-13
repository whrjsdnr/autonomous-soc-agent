"""Failure diagnostics never reveal source content or change original model files."""

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest
from tests.integration.external_runtime.test_gate_c_entrypoints import inputs

from soc_agent.external_runtime import CODE_PIN, CONTRACT
from soc_agent.security_ai.external.metadata import reviewed_binding
from soc_agent.security_ai.external.runtime_store import RuntimeGovernanceStore


@pytest.mark.parametrize(
    "fault", ("feature-count", "missing-artifact", "sha-mismatch", "database", "native-python")
)
def test_cli_configuration_and_storage_fail_closed(tmp_path, fault):
    events, features = inputs(tmp_path)
    artifacts = Path(
        os.environ.get("SOC_EXTERNAL_ARTIFACT_ROOT", "/tmp/soc-gate-b-artifacts-20261012")
    )
    native = Path(
        os.environ.get(
            "SOC_EXTERNAL_INFERENCE_PYTHON", "/tmp/security-ai-artifact-validation/bin/python"
        )
    )
    profile = "DESKTOP" if os.name == "nt" else "SERVER"
    data = tmp_path / "failed runtime"
    if fault == "feature-count":
        rows = [json.loads(line) for line in features.read_text(encoding="utf-8").splitlines()]
        value = json.loads(rows[0]["observation"]["feature_payload"])
        value.pop(next(iter(value)))
        rows[0]["observation"]["feature_payload"] = json.dumps(value)
        features.write_text("\n".join(json.dumps(row) for row in rows), encoding="utf-8")
    elif fault == "missing-artifact":
        artifacts = tmp_path / "no artifacts"
    elif fault == "sha-mismatch":
        binding = reviewed_binding(
            "litert", expected_code_identity=CODE_PIN, runtime_contract_digest=CONTRACT
        )
        target = tmp_path / "tampered copy"
        for file in binding.artifact_identity.files:
            destination = target / file.path
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(artifacts / file.path, destination)
        model = target / "dns/model/dnn_int8.tflite"
        with model.open("r+b") as stream:
            original = stream.read(1)
            stream.seek(0)
            stream.write(bytes((original[0] ^ 1,)))
        artifacts = target
        # Only DNS is requested so rejection must inspect the corrupted DNS files.
        features.write_text(features.read_text(encoding="utf-8").splitlines()[1], encoding="utf-8")
    elif fault == "database":
        # Desktop's descriptor is intentionally initialized through its real public factory.
        if profile == "DESKTOP":
            from soc_agent.desktop import initialize

            store = initialize(data, external_artifacts=artifacts).service.store
        else:
            store = RuntimeGovernanceStore.create_isolated(data)
        store.database.path.write_bytes(b"SENSITIVE_TEST_ONLY_CORRUPT_DATABASE")
    else:
        native = tmp_path / "missing-native-python"
    command = [sys.executable, "-m", "soc_agent.external_runtime"]
    for name, value in (
        ("directory", data),
        ("input", events),
        ("external-features", features),
        ("artifacts", artifacts),
        ("native-python", native),
        ("profile", profile),
    ):
        command += ["--" + name, str(value)]
    env = dict(os.environ, RUN_LIVE_LLM_TESTS="0")
    env["PYTHONPATH"] = str(Path(__file__).parents[3] / "src")
    result = subprocess.run(command, env=env, capture_output=True, timeout=180)
    assert result.returncode != 0
    assert b"no fallback" in result.stdout
    assert b"Traceback" not in result.stderr
    assert b"SENSITIVE_TEST_ONLY" not in result.stdout + result.stderr
    assert not (data / "desktop-writer.lock").exists()


def test_actual_duplicate_cli_process_is_denied_and_lock_released(tmp_path):
    events, features = inputs(tmp_path)
    artifacts = os.environ.get("SOC_EXTERNAL_ARTIFACT_ROOT", "/tmp/soc-gate-b-artifacts-20261012")
    native = os.environ.get(
        "SOC_EXTERNAL_INFERENCE_PYTHON", "/tmp/security-ai-artifact-validation/bin/python"
    )
    data = tmp_path / "actual concurrent CLI"
    command = [sys.executable, "-m", "soc_agent.external_runtime"]
    for name, value in (
        ("directory", data),
        ("input", events),
        ("external-features", features),
        ("artifacts", artifacts),
        ("native-python", native),
        ("profile", "DESKTOP"),
    ):
        command += ["--" + name, str(value)]
    env = dict(os.environ, RUN_LIVE_LLM_TESTS="0")
    env["PYTHONPATH"] = str(Path(__file__).parents[3] / "src")
    first = subprocess.Popen(command, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        deadline = time.monotonic() + 30
        lock = data / "desktop-writer.lock"
        while not lock.exists() and first.poll() is None and time.monotonic() < deadline:
            time.sleep(0.02)
        assert first.poll() is None and lock.exists(), "Actual first writer must be active"
        duplicate = subprocess.run(command, env=env, capture_output=True, timeout=30)
        assert duplicate.returncode != 0 and b"no fallback" in duplicate.stdout
        output, _ = first.communicate(timeout=180)
        assert first.returncode == 0 and json.loads(output)["human_boundary"]
        assert not lock.exists()
    finally:
        if first.poll() is None:
            first.terminate()
            first.communicate(timeout=30)
