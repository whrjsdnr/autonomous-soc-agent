"""Stateless external Evidence adapter; validation outcomes are not capabilities."""

from datetime import datetime

from pydantic import ValidationError
from pydantic_core import PydanticSerializationError

from soc_agent.review.models import StoredIncident
from soc_agent.security_ai.external.models import (
    AdapterOutcome,
    ExternalModelResult,
    InferenceProvenance,
    SourceFeatureObservation,
    TrustedExternalModelBinding,
    ValidationReport,
)
from soc_agent.security_ai.external.validation import (
    ValidationFailure,
    check_history,
    envelope_snapshot,
    normalized_result,
    validate_setup,
)


class ExternalEvidenceAdapter:
    """Trusted composition supplies setup/source provenance separately from the receipt.

    No globals, mutation, logging, inference, storage or execution. A caller must
    provide its bounded previous results for duplicate detection across calls.
    """

    def adapt(
        self,
        value: object,
        *,
        binding: TrustedExternalModelBinding,
        observation: SourceFeatureObservation,
        provenance: InferenceProvenance,
        received_at: datetime,
        incident: StoredIncident | None = None,
        history: tuple[ExternalModelResult, ...] = (),
    ) -> AdapterOutcome:
        try:
            binding = validate_setup(binding)
            envelope, original_digest, normalized = envelope_snapshot(value)
            result = normalized_result(
                envelope,
                original_digest,
                normalized,
                binding,
                observation,
                provenance,
                received_at,
                incident,
            )
            check_history(result, history)
            return AdapterOutcome(validation=result.validation, result=result)
        except ValidationFailure as error:
            report = ValidationReport(status="INVALID", code=str(error))
        except (ImportError, OSError):
            report = ValidationReport(status="INVALID", code="EXTERNAL_CONTRACT_UNAVAILABLE")
        except (
            ValidationError,
            PydanticSerializationError,
            ValueError,
            TypeError,
            KeyError,
            OverflowError,
            RecursionError,
        ):
            # External validation messages can contain raw payloads: deliberately omit them.
            report = ValidationReport(status="INVALID", code="INVALID_CONTRACT")
        return AdapterOutcome(validation=report)
