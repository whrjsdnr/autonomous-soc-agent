"""Isolation tests use real receipt schemas with synthetic predictions, not native models."""

import pytest
from pydantic import ValidationError
from tests.unit.security_ai.external.conftest import case

from soc_agent.security_ai.external.adapters import ExternalEvidenceAdapter
from soc_agent.security_ai.external.assembly import ExternalModelContext, assemble
from soc_agent.security_ai.external.inference import InferenceUnavailable, ModelRun, infer


def run(profile="detection_quality"):
    values = case.__wrapped__()(profile)
    envelope, kwargs = values
    result = ExternalEvidenceAdapter().adapt(envelope, **kwargs).result
    assert result is not None
    return ModelRun(
        binding=kwargs["binding"], required=True, status="AVAILABLE", code="OK", result=result
    ), kwargs


def test_linked_context_roundtrip():
    model, kwargs = run()
    context = assemble((model,), incident=kwargs["incident"])
    assert len(context.results) == 1
    assert not context.unlinked_results
    assert context.input_snapshot == kwargs["incident"].anchor
    assert context.uncertainty == "UNKNOWN"
    assert ExternalModelContext.model_validate_json(context.model_dump_json()) == context


def test_unlinked_results_excluded_from_incident_inputs():
    envelope, kwargs = case.__wrapped__()()
    kwargs["incident"] = None
    result = ExternalEvidenceAdapter().adapt(envelope, **kwargs).result
    model = ModelRun(
        binding=kwargs["binding"], required=True, status="AVAILABLE", code="OK", result=result
    )
    context = assemble((model,))
    assert not context.results and len(context.unlinked_results) == 1
    assert context.correlation_groups[0].correlation_status == "UNLINKED"


def test_quality_edge_same_observation():
    quality, kwargs = run()
    edge, _ = run("edge")
    context = assemble((quality, edge), incident=kwargs["incident"])
    assert len(context.correlation_groups) == 1
    assert len(context.correlation_groups[0].result_digests) == 2
    assert len(context.results) == 2


def test_duplicate_and_required_failure():
    model, kwargs = run()
    with pytest.raises(ValueError, match="DUPLICATE_MODEL_RESULT"):
        assemble((model, model), incident=kwargs["incident"])
    failed = ModelRun(binding=model.binding, required=True, status="UNAVAILABLE", code="NO_BACKEND")
    with pytest.raises(ValueError, match="REQUIRED_MODEL_UNAVAILABLE"):
        assemble((failed,))
    optional = failed.model_copy(update={"required": False})
    context = assemble((optional,))
    assert context.coverage[0].status == "UNAVAILABLE" and not context.results


def test_digest_tamper_rejected():
    model, kwargs = run()
    context = assemble((model,), incident=kwargs["incident"])
    with pytest.raises(ValidationError):
        ExternalModelContext.model_validate(context.model_copy(update={"context_digest": "0" * 64}))
    with pytest.raises(ValueError):
        assemble((model,), incident=None)


@pytest.mark.parametrize("profile", ["detection_quality", "edge", "litert"])
@pytest.mark.parametrize("required", [True, False])
def test_missing_artifact_or_backend_no_fallback(tmp_path, profile, required):
    _, kwargs = case.__wrapped__()(profile)
    if required:
        with pytest.raises(InferenceUnavailable):
            infer(tmp_path, kwargs["binding"], kwargs["observation"])
    else:
        result = infer(tmp_path, kwargs["binding"], kwargs["observation"], required=False)
        assert result.status == "UNAVAILABLE" and result.result is None


@pytest.mark.parametrize("profile", ["detection_quality", "edge", "litert"])
def test_untrusted_binding_rejected_before_prediction(tmp_path, profile):
    _, kwargs = case.__wrapped__()(profile)
    binding = kwargs["binding"].model_copy(update={"model_version": "unreviewed"})
    with pytest.raises(InferenceUnavailable):
        infer(tmp_path, binding, kwargs["observation"])


def test_observation_collision_rejected():
    from soc_agent._json import canonical_json_object
    from soc_agent.review.identity import content_digest
    from soc_agent.security_ai.external.validation import feature_input_digest

    quality, _ = run()
    envelope, kwargs = case.__wrapped__()("edge")
    source = kwargs["observation"].model_copy(
        update={
            "association": None,
            "feature_payload": canonical_json_object(
                dict.fromkeys(kwargs["binding"].feature_identity.ordered_names, 2.0)
            ),
        }
    )
    provenance = kwargs["provenance"].model_copy(
        update={
            "observation_digest": content_digest(source),
            "feature_input_digest": feature_input_digest(source, kwargs["binding"]),
        }
    )
    kwargs.update(observation=source, provenance=provenance, incident=None)
    edge_result = ExternalEvidenceAdapter().adapt(envelope, **kwargs).result
    edge = ModelRun(
        binding=kwargs["binding"], required=True, status="AVAILABLE", code="OK", result=edge_result
    )
    # First result is unlinked too; do not confuse association rejection with collision.
    envelope, values = case.__wrapped__()()
    values["incident"] = None
    first = ExternalEvidenceAdapter().adapt(envelope, **values).result
    quality = quality.model_copy(update={"result": first})
    with pytest.raises(ValueError, match="OBSERVATION_IDENTITY_COLLISION"):
        assemble((quality, edge))


def test_inventory_rejects_link(tmp_path):
    from soc_agent.security_ai.external.inference import _inventory

    _, kwargs = case.__wrapped__()()
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "link"
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError as error:
        if getattr(error, "winerror", None) == 1314:
            pytest.skip(
                "Windows symlink creation privilege unavailable; native reparse tests remain"
            )
        raise
    with pytest.raises(InferenceUnavailable, match="UNSAFE_ARTIFACT_PATH"):
        _inventory(link, kwargs["binding"])


@pytest.mark.parametrize("profile", ["detection_quality", "edge", "litert"])
@pytest.mark.parametrize("required", [True, False])
def test_artifact_verification_failure_never_predicts(tmp_path, monkeypatch, profile, required):
    import security_ai.artifacts as artifacts
    from security_ai.artifacts import ArtifactIntegrityError

    import soc_agent.security_ai.external.inference as module

    _, kwargs = case.__wrapped__()(profile)
    monkeypatch.setattr(module, "_environment", lambda binding: "a" * 64)
    monkeypatch.setattr(module, "_inventory", lambda root, binding: ())

    def corrupted(*args, **kwargs):
        raise ArtifactIntegrityError("sensitive message intentionally not propagated")

    monkeypatch.setattr(artifacts, "verify_install", corrupted)
    if required:
        with pytest.raises(InferenceUnavailable, match="^ARTIFACT_OR_BACKEND_UNAVAILABLE$"):
            infer(tmp_path, kwargs["binding"], kwargs["observation"])
    else:
        model = infer(tmp_path, kwargs["binding"], kwargs["observation"], required=False)
        assert model.code == "ARTIFACT_OR_BACKEND_UNAVAILABLE" and model.result is None


@pytest.mark.parametrize("profile", ["detection_quality", "edge", "litert"])
def test_invalid_feature_rejected_before_loading(tmp_path, profile):
    from soc_agent._json import canonical_json_object

    _, kwargs = case.__wrapped__()(profile)
    source = kwargs["observation"].model_copy(
        update={"feature_payload": canonical_json_object({"bad": 1})}
    )
    with pytest.raises(InferenceUnavailable):
        infer(tmp_path, kwargs["binding"], source)


def test_assembly_revalidates_original_prediction():
    model, kwargs = run()
    from soc_agent.review.identity import content_digest
    from soc_agent.security_ai.external.models import ExternalModelResultContent

    # Rehashing a valid shape must not let altered metadata bypass original receipt validation.
    content = ExternalModelResultContent.model_validate(
        model.result.model_dump(exclude={"result_digest"})
    )
    content = content.model_copy(
        update={"score_semantics": "dns_uncalibrated_malicious_probability"}
    )
    result = type(model.result)(**content.model_dump(), result_digest=content_digest(content))
    with pytest.raises(ValueError, match="RESULT_REVALIDATION_FAILED"):
        assemble((model.model_copy(update={"result": result}),), incident=kwargs["incident"])
