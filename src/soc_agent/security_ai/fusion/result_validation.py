"""Revalidate retained fusion artifacts using the original signal and aggregation rules."""

from soc_agent.security_ai.features.models import FeatureExtractionProvenance
from soc_agent.security_ai.fusion.engine import MultiModelFusionEngine, _ValidatedSignal
from soc_agent.security_ai.fusion.errors import FusionValidationError
from soc_agent.security_ai.fusion.models import FusionResult, ModelAvailability
from soc_agent.security_ai.fusion.validation import validated_signal


def validate_fusion_result(value: FusionResult) -> FusionResult:
    """Check structure and lineage, not publisher identity or original feature values."""
    try:
        if type(value) is not FusionResult or any(
            (
                len(value.signals) > 128,
                len(value.contributions) > 128,
                len(value.model_references) > 16,
                len(value.correlation_groups) > 128,
                sum(len(c.signal_ids) for c in value.contributions) > 128,
            )
        ):
            raise FusionValidationError("Bounded FusionResult required")
        result = FusionResult.model_validate(value.model_dump(warnings=False))
        engine = MultiModelFusionEngine(result.model_references, result.expected_models)
        bindings = {b.manifest_digest: b for b in engine.bindings}
        signals = {s.signal_id: s for s in result.signals}
        validated = []
        for contribution in result.contributions:
            binding = bindings[contribution.model_reference]
            for signal_id in contribution.signal_ids:
                signal = signals[signal_id]
                provenance = FeatureExtractionProvenance.model_validate(
                    signal.explanation_payload()["feature_provenance"]
                )
                prediction = validated_signal(
                    signal, provenance, contribution.feature_fingerprint, binding
                )
                validated.append(
                    _ValidatedSignal(
                        signal, provenance, contribution.feature_fingerprint, prediction
                    )
                )
        if len(validated) > 128:
            raise FusionValidationError("Too many contribution aliases")
        unavailable = tuple(
            ModelAvailability(model_kind=c.model_kind, status=c.status, reason=c.reason)
            for c in result.coverage
            if c.status in ("not_run", "failed", "insufficient_input")
        )
        rebuilt = engine._assemble(result.incident_id, tuple(validated), unavailable)
        if not set(rebuilt.limitations) <= set(result.limitations):
            raise FusionValidationError("Required fusion limitations missing")
        if rebuilt.model_dump(exclude={"limitations"}) != result.model_dump(
            exclude={"limitations"}
        ):
            raise FusionValidationError("Fusion artifact differs from retained signal aggregation")
        return result
    except FusionValidationError:
        raise
    except (ValueError, TypeError, KeyError, AttributeError) as error:
        raise FusionValidationError("Invalid retained fusion artifact") from error
