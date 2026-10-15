"""No model execution: local identity/receipt, missing state and concurrency guards."""

import asyncio
import json
import sys
from pathlib import Path

import pytest

from soc_agent.gui import environment
from soc_agent.gui.backend import Backend, GUIConfig


@pytest.fixture
def prepared(tmp_path, monkeypatch):
    project = tmp_path / "project"
    project.mkdir(mode=0o700)
    monkeypatch.setattr(environment, "project_root", lambda: project)
    root = environment.environment_root()
    root.mkdir(mode=0o700)
    (root / "inference/bin").mkdir(parents=True)
    (root / "inference/bin/python").symlink_to(Path(sys.executable).resolve())
    (root / "artifacts").mkdir()
    (root / "artifacts/model").write_text("fixture-bytes-not-a-model")
    site = root / "inference/lib/python3.12/site-packages"
    site.mkdir(parents=True)
    shared = [
        project.parent / "ML/.venv/lib/python3.12/site-packages",
        project / ".venv/lib/python3.12/site-packages",
    ]
    for p in shared:
        p.mkdir(parents=True)
    (site / "reused-readonly-environments.pth").write_text("\n".join(map(str, shared)) + "\n")
    (site / "_virtualenv.pth").write_text("import _virtualenv\n")
    (site / "_virtualenv.py").write_text("# fixture never executed\n")
    receipt = root / "receipt.json"
    receipt.write_text(
        json.dumps(
            {
                "version": "soc-gui-native-demo:v1",
                "files": environment._inventory(root),
                "shared_startup": environment._shared_startup(root),
            }
        )
    )
    receipt.chmod(0o600)
    return root


def test_valid_paths_and_read_only_receipt(prepared):
    before = {p: p.read_bytes() for p in prepared.rglob("*") if p.is_file() and not p.is_symlink()}
    python, artifacts = environment.verified_paths()
    assert python == prepared / "inference/bin/python" and artifacts == prepared / "artifacts"
    assert before == {p: p.read_bytes() for p in before}


@pytest.mark.parametrize(
    "target",
    ["artifacts/model", "inference/pyvenv.cfg", "inference/lib/python3.12/site-packages/evil.pth"],
)
def test_environment_tampering_rejected(prepared, target):
    (prepared / target).write_text("tampered")
    with pytest.raises(ValueError):
        environment.verified_paths()


def test_external_executable_never_accepted(prepared, tmp_path):
    executable = prepared / "inference/bin/python"
    executable.unlink()
    fake = tmp_path / "evil"
    fake.write_text("do not execute")
    executable.symlink_to(fake)
    with pytest.raises(ValueError, match="UNTRUSTED_NATIVE_EXECUTABLE"):
        environment.verified_paths()


def test_receipt_paths_do_not_select_executable(prepared):
    receipt = prepared / "receipt.json"
    data = json.loads(receipt.read_text())
    data["interpreter"] = "/bin/sh"
    receipt.write_text(json.dumps(data))
    with pytest.raises(ValueError):
        environment.verified_paths()


def test_symlink_artifact_and_world_writable_root_rejected(prepared, tmp_path):
    file = prepared / "artifacts/model"
    file.unlink()
    file.symlink_to(tmp_path / "external")
    with pytest.raises(ValueError):
        environment.verified_paths()
    prepared.chmod(0o777)
    with pytest.raises(ValueError):
        environment.verified_paths()


@pytest.mark.asyncio
async def test_no_setup_does_not_infer_or_adopt_external_python(tmp_path, monkeypatch):
    monkeypatch.setattr(environment, "environment_root", lambda: tmp_path / "absent")
    monkeypatch.setenv("SOC_EXTERNAL_INFERENCE_PYTHON", "/bin/sh")
    backend = Backend(GUIConfig(data_directory=tmp_path / "gui"))
    status = await backend.models()
    assert status["environment"]["status"] == "SETUP_REQUIRED"
    assert backend.model_paths == (None, None)
    assert (await backend.fixture_probe())["status"] == "BLOCKED"
    assert all(p["demo_inference"] == "UNKNOWN" for p in status["packages"])


@pytest.mark.asyncio
async def test_parallel_probe_rejected_and_failure_unblocks_retry(tmp_path, monkeypatch):
    backend = Backend(GUIConfig(data_directory=tmp_path / "gui"))
    gate = asyncio.Event()

    async def wait():
        await gate.wait()
        raise ValueError("SANITIZED_FAILURE")

    monkeypatch.setattr(backend, "models", wait)
    first = asyncio.create_task(backend.fixture_probe())
    await asyncio.sleep(0)
    with pytest.raises(ValueError, match="ALREADY_RUNNING"):
        await backend.fixture_probe()
    gate.set()
    with pytest.raises(ValueError, match="SANITIZED_FAILURE"):
        await first
    assert not backend.busy_probe


def test_shared_pth_cannot_redirect_to_arbitrary_path(prepared):
    pth = prepared / "inference/lib/python3.12/site-packages/reused-readonly-environments.pth"
    pth.write_text("/tmp/unknown-packages\n")
    with pytest.raises(ValueError):
        environment.verified_paths()


def test_existing_environment_not_overwritten(prepared):
    with pytest.raises(ValueError, match="FRESH"):
        environment.prepare(Path("/must-not-read"))
    assert (prepared / "receipt.json").is_file()


def test_receipt_oversized_rejected(prepared):
    (prepared / "receipt.json").write_text("x" * (512 * 1024 + 1))
    with pytest.raises(ValueError, match="OVERSIZED"):
        environment.verified_paths()
