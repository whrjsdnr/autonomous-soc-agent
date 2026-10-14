"""Status checks, not native inference; injected failures never become demo evidence."""

import importlib.metadata
from pathlib import Path

import pytest
from tests.unit.security_ai.external.conftest import case as case

from soc_agent.security_ai.external import package_status as status
from soc_agent.security_ai.external.inference import InferenceUnavailable, ModelRun
from soc_agent.security_ai.external.service import ModelInput


def test_inventory_never_infers_or_grants_authority(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Inventory must not infer")

    monkeypatch.setattr(status, "infer", forbidden)
    result = status.inspect_packages()
    assert len(result.packages) == 3
    assert {len(p.feature_names) for p in result.packages} == {9, 40}
    assert all(p.contract == "VERIFIED" for p in result.packages)
    assert all(p.demo_inference == "UNKNOWN" and p.artifact == "UNKNOWN" for p in result.packages)
    assert all(p.operational_input == "NOT_INFERABLE" for p in result.packages)
    assert result.write_disposition == "WRITE_DENIED"
    assert result.execution_authority is False
    assert result.authentication.current_runtime_validation == "NOT_QUERIED"
    assert "site-packages" not in result.model_dump_json()


def test_missing_package_is_unavailable(monkeypatch):
    original = status.importlib.metadata.version

    def version(name):
        if name == "dns-security-ai":
            raise importlib.metadata.PackageNotFoundError(name)
        return original(name)

    monkeypatch.setattr(status.importlib.metadata, "version", version)
    dns = status.inspect_packages().packages[2]
    assert dns.installed == "UNAVAILABLE" and dns.overall == "UNAVAILABLE"
    assert dns.contract == "BLOCKED" and dns.version is None


def test_failed_import_sanitized(monkeypatch):
    original = status.importlib.import_module

    def importing(name):
        if name == "dns_security_ai":
            raise ImportError("credential-do-not-emit")
        return original(name)

    monkeypatch.setattr(status.importlib, "import_module", importing)
    value = status.inspect_packages()
    assert value.packages[2].package_import == "UNAVAILABLE"
    assert "credential-do-not-emit" not in value.model_dump_json()


def test_changed_reviewed_contract_blocked(monkeypatch):
    def invalid(*args, **kwargs):
        raise ValueError("private-path-do-not-emit")

    monkeypatch.setattr(status, "reviewed_binding", invalid)
    result = status.inspect_packages()
    assert all(p.contract == "BLOCKED" and p.overall == "BLOCKED" for p in result.packages)
    assert "private-path-do-not-emit" not in result.model_dump_json()


@pytest.mark.parametrize("symlink", [False, True])
def test_missing_or_symlink_artifacts_blocked_without_path_leak(tmp_path, symlink):
    root = tmp_path / "private-artifact-root"
    if symlink:
        root.symlink_to(tmp_path, target_is_directory=True)
    value = status.inspect_packages(artifact_root=root)
    assert all(p.artifact == "BLOCKED" for p in value.packages)
    assert str(tmp_path) not in value.model_dump_json()
    assert all(p.demo_inference == "UNKNOWN" for p in value.packages)


def test_dependency_metadata_is_not_inference(monkeypatch):
    original = status.importlib.metadata.version
    backends = {"lightgbm", "torch", "joblib", "scikit-learn", "ai-edge-litert", "pandas"}
    monkeypatch.setattr(
        status.importlib.metadata,
        "version",
        lambda name: "0.0" if name in backends else original(name),
    )
    result = status.inspect_packages()
    assert all(p.backend_dependencies == "VERIFIED" for p in result.packages)
    assert all(p.demo_inference == "UNKNOWN" for p in result.packages)


def test_explicit_probe_requires_unique_inputs(case, tmp_path):
    _, data = case()
    item = ModelInput(binding=data["binding"], observation=data["observation"])
    for inputs in [(), (item, item)]:
        with pytest.raises(ValueError, match="EXPLICIT_UNIQUE"):
            status.verify_fixture_demo(
                artifact_root=tmp_path, inputs=inputs, incident=data["incident"]
            )


def test_probe_does_not_fallback_when_environment_missing(case, tmp_path, monkeypatch):
    _, data = case()

    def forbidden(*args, **kwargs):
        pytest.fail("Inference must not run on unverified installation")

    monkeypatch.setattr(status, "infer", forbidden)
    with pytest.raises(InferenceUnavailable, match="DEMO_ENVIRONMENT_NOT_VERIFIED"):
        status.verify_fixture_demo(
            artifact_root=tmp_path,
            inputs=(ModelInput(binding=data["binding"], observation=data["observation"]),),
            incident=data["incident"],
        )


@pytest.mark.parametrize("unlinked", [False, True])
def test_supplied_result_unit_probe_revalidates_advisory_source(case, monkeypatch, unlinked):
    # Supplied synthetic prediction tests projection plumbing only, not native inference.
    from soc_agent.security_ai.external.adapters import ExternalEvidenceAdapter

    envelope, data = case()
    result = ExternalEvidenceAdapter().adapt(envelope, **data).result
    assert result is not None
    inventory = status.inspect_packages()
    prepared = inventory.model_copy(
        update={
            "packages": tuple(
                p.model_copy(
                    update={
                        "contract": "VERIFIED",
                        "artifact": "VERIFIED",
                        "backend_dependencies": "VERIFIED",
                    }
                )
                for p in inventory.packages
            )
        }
    )
    monkeypatch.setattr(status, "inspect_packages", lambda **kwargs: prepared)
    monkeypatch.setattr(
        status,
        "infer",
        lambda *args, **kwargs: ModelRun(
            binding=data["binding"],
            required=True,
            status="AVAILABLE",
            code="OK",
            result=result,
        ),
    )
    incident = data["incident"]
    if unlinked:
        incident = incident.model_copy(
            update={"state": incident.state.model_copy(update={"evidence": ()})}
        )
        with pytest.raises(ValueError):
            status.verify_fixture_demo(
                artifact_root=Path("."),
                inputs=(ModelInput(binding=data["binding"], observation=data["observation"]),),
                incident=incident,
            )
    else:
        probed = status.verify_fixture_demo(
            artifact_root=Path("."),
            inputs=(ModelInput(binding=data["binding"], observation=data["observation"]),),
            incident=incident,
        )
        assert probed.context_digest and probed.projection_digest
        assert probed.packages[0].demo_inference == "VERIFIED"
        assert probed.packages[0].operational_input == "NOT_INFERABLE"
        assert probed.packages[0].overall == "ADVISORY_ONLY"
        assert probed.input_origin == "SYNTHETIC_PRECOMPUTED_FEATURE_FIXTURE"
        assert probed.packages[1].demo_inference == "UNKNOWN"
        assert not probed.execution_authority


def test_status_cannot_be_used_as_authority():
    from pydantic import ValidationError

    value = status.inspect_packages().model_dump()
    value["execution_authority"] = True
    with pytest.raises(ValidationError):
        status.IntegrationStatus.model_validate(value)


def test_operational_data_cannot_be_disguised_as_v2(case):
    from pydantic import ValidationError

    _, data = case()
    payload = data["observation"].model_dump()
    payload["synthetic"] = False
    with pytest.raises(ValidationError):
        ModelInput.model_validate({"binding": data["binding"], "observation": payload})


def test_readonly_artifact_verification_detects_replacement(case, tmp_path, monkeypatch):
    import security_ai.artifacts

    _, data = case()
    binding = data["binding"]
    calls = []

    def inventory(root, supplied):
        assert supplied == binding
        calls.append(root)
        return ((len(calls),),)

    monkeypatch.setattr(status, "_inventory", inventory)
    monkeypatch.setattr(security_ai.artifacts, "verify_install", lambda *args, **kwargs: None)
    assert status._verify_artifact(tmp_path, binding) == "BLOCKED"
    assert len(calls) == 2


def test_artifact_mismatch_never_returns_verified(case, tmp_path, monkeypatch):
    import security_ai.artifacts

    _, data = case()
    monkeypatch.setattr(status, "_inventory", lambda *args: ())

    def tampered(*args, **kwargs):
        raise security_ai.artifacts.ArtifactIntegrityError("private-location-do-not-emit")

    monkeypatch.setattr(security_ai.artifacts, "verify_install", tampered)
    result = status.inspect_packages(artifact_root=tmp_path)
    assert all(p.artifact == "BLOCKED" for p in result.packages)
    assert "private-location-do-not-emit" not in result.model_dump_json()
