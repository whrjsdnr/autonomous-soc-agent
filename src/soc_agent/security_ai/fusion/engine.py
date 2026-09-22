"""Bounded pure deterministic fusion of already-computed analytical signals."""

from dataclasses import dataclass
from typing import Literal
from uuid import UUID

from pydantic import TypeAdapter

from soc_agent.security_ai.evaluation.data import digest
from soc_agent.security_ai.fusion.compatibility import (
    group_agreement,
    network_relations,
    overall_agreement,
)
from soc_agent.security_ai.fusion.coverage import coverage_entries
from soc_agent.security_ai.fusion.enums import CoverageState
from soc_agent.security_ai.fusion.errors import FusionIdentityCollision, FusionValidationError
from soc_agent.security_ai.fusion.models import (
    CorrelationGroup,
    FusionContribution,
    FusionInput,
    FusionModelBinding,
    FusionResult,
    FusionSummary,
    ModelAvailability,
)
from soc_agent.security_ai.fusion.validation import (
    checked_input,
    source_payload,
    validate_binding,
    validated_prediction,
)
from soc_agent.security_ai.network.classifier import ClassificationPrediction
from soc_agent.security_ai.packaging.package import Kind
from soc_agent.security_ai.signals import AISignal


@dataclass(frozen=True)
class MultiModelFusionEngine:
    bindings: tuple[FusionModelBinding, ...]
    expected_models: tuple[Kind, ...]

    def __post_init__(self) -> None:
        try:
            if len(self.bindings) > 16:
                raise FusionValidationError("At most 16 trusted model bindings supported")
            bindings = tuple(validate_binding(b) for b in self.bindings)
            if len({b.manifest_digest for b in bindings}) != len(bindings):
                raise FusionValidationError("Duplicate package identity in trusted bindings")
            expected = TypeAdapter(tuple[Kind, ...]).validate_python(self.expected_models)
            if not expected or len(set(expected)) != len(expected):
                raise FusionValidationError("Nonempty unique coverage expectations required")
            object.__setattr__(
                self, "bindings", tuple(sorted(bindings, key=lambda b: b.manifest_digest))
            )
            object.__setattr__(self, "expected_models", tuple(sorted(expected)))
        except (ValueError, TypeError, AttributeError) as error:
            raise FusionValidationError("Invalid fusion engine metadata") from error

    def fuse(
        self,
        *,
        incident_id: UUID,
        inputs: tuple[FusionInput, ...],
        unavailable: tuple[ModelAvailability, ...] = (),
    ) -> FusionResult:
        try:
            return self._fuse(incident_id, inputs, unavailable)
        except FusionValidationError:
            raise
        except (ValueError, TypeError, KeyError, AttributeError) as error:
            raise FusionValidationError("Invalid fusion input; no result produced") from error

    def _fuse(
        self,
        incident_id: UUID,
        inputs: tuple[FusionInput, ...],
        unavailable: tuple[ModelAvailability, ...],
    ) -> FusionResult:
        if not isinstance(incident_id, UUID) or not isinstance(inputs, tuple) or len(inputs) > 128:
            raise FusionValidationError("UUID incident and at most 128 immutable inputs required")
        bindings = {b.manifest_digest: b for b in self.bindings}
        signals: dict[UUID, AISignal] = {}
        results: dict[UUID, str] = {}
        sources: dict[str, str] = {}
        contributions: dict[str, FusionContribution] = {}
        group_keys: dict[str, Literal["network", "authentication"]] = {}
        contribution_groups: dict[str, str] = {}
        replay_values: dict[str, str] = {}
        # Sort to select the same representative provenance for a replay, regardless of order.
        checked = tuple(checked_input(item) for item in inputs)
        for item in sorted(checked, key=lambda item: str(item.signal.signal_id)):
            signal, features = item.signal, item.features
            if signal.incident_id != incident_id:
                raise FusionValidationError("Mixed incident signals")
            key = signal.explanation_payload()["package_manifest_digest"]
            if key not in bindings:
                raise FusionValidationError("Unknown package identity")
            binding = bindings[key]
            prediction = validated_prediction(item, binding)
            if signal.signal_id in signals and signals[signal.signal_id] != signal:
                raise FusionIdentityCollision("Same signal_id has different contents")
            result_content = signal.model_dump(
                mode="json", exclude={"signal_id", "created_at", "source_evidence_ids"}
            )
            result_digest = digest(result_content)
            if (
                signal.source_result_id in results
                and results[signal.source_result_id] != result_digest
            ):
                raise FusionIdentityCollision("Same source_result_id has different contents")
            results[signal.source_result_id] = result_digest
            signals[signal.signal_id] = signal
            for source in features.provenance.sources:
                logical_key = digest(
                    {
                        "reference": source.source_reference.model_dump(mode="json"),
                        "observed_at": source.observed_at.isoformat(),
                        "record_type": source.record_type,
                    }
                )
                value = digest(source.model_dump(mode="json", exclude={"record_id"}))
                if logical_key in sources and sources[logical_key] != value:
                    raise FusionIdentityCollision("Same logical source/time has different contents")
                sources[logical_key] = value
            domain = (
                "authentication"
                if binding.manifest.model_kind == "authentication_anomaly"
                else "network"
            )
            group_id = digest(
                {
                    "incident": str(incident_id),
                    "domain": domain,
                    "fingerprint": features.input_fingerprint,
                    "sources": list(source_payload(features)),
                }
            )
            identity = digest(
                {
                    "group": group_id,
                    "package": binding.manifest_digest,
                    "model": binding.manifest.model_id,
                    "version": binding.manifest.model_version,
                    "selection": binding.manifest.selection_digest,
                    "operating_point": binding.manifest.operating_point.model_dump()
                    if binding.manifest.operating_point
                    else "argmax",
                }
            )
            value = digest(
                {"prediction": prediction.model_dump(mode="json"), "decision": signal.prediction}
            )
            if identity in replay_values and replay_values[identity] != value:
                raise FusionIdentityCollision(
                    "Replayed model/input identity has different prediction"
                )
            replay_values[identity] = value
            if identity in contributions:
                prior = contributions[identity]
                contributions[identity] = prior.model_copy(
                    update={
                        "signal_ids": tuple(
                            sorted(set(prior.signal_ids + (signal.signal_id,)), key=str)
                        )
                    }
                )
                continue
            group_keys[group_id] = domain
            contribution_groups[identity] = group_id
            contributions[identity] = FusionContribution(
                contribution_id=identity,
                signal_ids=(signal.signal_id,),
                model_reference=key,
                model_kind=binding.manifest.model_kind,
                decision=signal.prediction,
                scores=prediction,
                score_semantics="class probabilities"
                if isinstance(prediction, ClassificationPrediction)
                else "empirical anomaly rank; raw=-score_samples",
                operating_point=binding.manifest.operating_point or "argmax",
                feature_fingerprint=features.input_fingerprint,
                provenance=features.provenance,
            )
        ordered = tuple(contributions[k] for k in sorted(contributions))
        groups = []
        for group_id, domain in sorted(group_keys.items()):
            members = tuple(
                c for c in ordered if contribution_groups[c.contribution_id] == group_id
            )
            agreement, rules = group_agreement(members)
            groups.append(
                CorrelationGroup(
                    group_id=group_id,
                    domain=domain,
                    contribution_ids=tuple(c.contribution_id for c in members),
                    agreement_state=agreement,
                    compatibility_rules=rules,
                    network_relations=network_relations(members),
                )
            )
        groups = tuple(groups)
        observed = {c.model_kind for c in ordered}
        missing = tuple(k for k in self.expected_models if k not in observed)
        coverage_details = coverage_entries(self.expected_models, observed, unavailable)
        coverage = (
            CoverageState.NONE
            if not observed
            else CoverageState.COMPLETE
            if not missing
            else CoverageState.MINIMAL
            if len(observed) == 1
            else CoverageState.PARTIAL
        )
        identity = digest(
            {
                "version": "1.0.0",
                "compatibility": "directional-compatibility:v1",
                "incident": str(incident_id),
                "expected_models": list(self.expected_models),
                "contributions": [
                    [c.contribution_id, replay_values[c.contribution_id]] for c in ordered
                ],
                "groups": [g.model_dump(mode="json") for g in groups],
                "coverage": [c.model_dump(mode="json") for c in coverage_details],
            }
        )
        return FusionResult(
            fusion_id=identity,
            incident_id=incident_id,
            signals=tuple(signals[k] for k in sorted(signals, key=str)),
            contributions=ordered,
            model_references=tuple(
                bindings[k] for k in sorted({c.model_reference for c in ordered})
            ),
            correlation_groups=groups,
            agreement_state=overall_agreement(tuple(g.agreement_state for g in groups)),
            coverage_state=coverage,
            expected_models=self.expected_models,
            missing_models=missing,
            coverage=coverage_details,
            summary=FusionSummary(
                model_contribution_count=len(ordered),
                unique_source_record_count=len(sources),
                input_group_count=len(groups),
                domains_present=tuple(sorted({g.domain for g in groups})),
                cross_domain_state="unverified"
                if len({g.domain for g in groups}) > 1
                else "not_applicable",
            ),
            created_at=max(
                (s.observed_at for c in ordered for s in c.provenance.sources), default=None
            ),
        )
