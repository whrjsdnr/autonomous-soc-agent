"""Retained runtime measurements only; no inference, calibration or Fusion assembly."""

from soc_agent.api.dashboard.incident_query import display_text
from soc_agent.api.dashboard.security_ai_models import (
    FileDigestView,
    FusionMonitorView,
    RetainedModelView,
    RuntimeValue,
    SecurityAIMonitorView,
)
from soc_agent.review.persistence.security_ai_monitor import RetainedSignalSource
from soc_agent.security_ai.anomaly_common import AnomalyPrediction
from soc_agent.security_ai.fusion.models import FusionContribution, FusionModelBinding
from soc_agent.security_ai.network.classifier import ClassificationPrediction

MODEL_LABELS = {
    "network_classifier": ("Network XGBoost", "NetworkClassifierAdapter"),
    "network_anomaly": ("Network IsolationForest", "NetworkAnomalyAdapter"),
    "authentication_anomaly": ("Authentication IsolationForest", "AuthenticationAnomalyAdapter"),
}


def model_view(
    source: RetainedSignalSource,
    binding: FusionModelBinding,
    contribution: FusionContribution | None = None,
) -> RetainedModelView:
    manifest, fusion = binding.manifest, source.fusion
    title, adapter = MODEL_LABELS[manifest.model_kind]
    coverage = next(
        (c.status for c in fusion.coverage if c.model_kind == manifest.model_kind), None
    )
    signals = tuple(
        s for s in fusion.signals if contribution and s.signal_id in contribution.signal_ids
    )
    values, probabilities, operating = (), (), None
    if contribution is not None:
        prediction = contribution.scores
        if isinstance(prediction, ClassificationPrediction):
            probabilities = tuple(
                (display_text(p.label), p.probability) for p in prediction.class_probabilities
            )
            operating = "argmax"
        elif isinstance(prediction, AnomalyPrediction):
            values = tuple(
                RuntimeValue(name=name, value=value)
                for name, value in (
                    ("Raw score_samples", prediction.raw_score),
                    ("Raw anomaly measure (-score_samples)", prediction.raw_anomaly_measure),
                    ("Raw decision function", prediction.raw_decision_score),
                    ("Empirical anomaly rank", prediction.anomaly_score),
                    ("Normalization threshold", prediction.threshold),
                    ("Normalization decision", prediction.is_anomaly),
                )
            )
            point = contribution.operating_point
            operating = f"{point.space} ≥ {point.threshold}"
    return RetainedModelView(
        kind=manifest.model_kind,
        title=title,
        adapter=adapter,
        availability=(
            "AVAILABLE"
            if contribution
            else "NOT AVAILABLE"
            if coverage in ("not_run", "failed", "insufficient_input")
            else "UNKNOWN"
        ),
        metadata_available=True,
        model_name=display_text(manifest.model_id),
        model_version=display_text(manifest.model_version),
        manifest_digest=binding.manifest_digest,
        file_hashes=tuple(
            FileDigestView(path=h.path, sha256=h.sha256) for h in manifest.file_hashes
        ),
        feature_schema=(
            f"{display_text(manifest.feature_schema_name)} "
            f"v{display_text(manifest.feature_schema_version)}"
        ),
        extractor=(
            f"{display_text(manifest.extractor_name)} v{display_text(manifest.extractor_version)}"
        ),
        feature_count=len(manifest.ordered_feature_names),
        feature_names=tuple(display_text(n) for n in manifest.ordered_feature_names),
        signal_state=display_text(contribution.decision) if contribution else "UNKNOWN",
        last_observed=max((s.source_created_at for s in signals), default=None),
        contribution_id=contribution.contribution_id if contribution else None,
        incident_id=source.incident_id,
        run_id=source.run_id,
        assessment_id=source.assessment_id,
        fusion_id=fusion.fusion_id,
        signal_ids=tuple(s.signal_id for s in signals),
        source_result_ids=tuple(s.source_result_id for s in signals),
        source_types=tuple(
            sorted({display_text(s.record_type) for s in contribution.provenance.sources})
        )
        if contribution
        else (),
        source_record_count=len(contribution.provenance.sources) if contribution else None,
        evidence_references=tuple(
            sorted({i for s in signals for i in s.source_evidence_ids}, key=str)
        ),
        values=values,
        class_probabilities=probabilities,
        score_semantics=contribution.score_semantics if contribution else None,
        operating_point=operating,
        reported_coverage=coverage,
    )


def project_security_ai(sources: tuple[RetainedSignalSource, ...]) -> SecurityAIMonitorView:
    options = {kind: [] for kind in MODEL_LABELS}
    observations, fusion_views, signal_ids = [], [], set()
    for source in sources:
        fusion = source.fusion
        bindings = {b.manifest_digest: b for b in fusion.model_references}
        for binding in bindings.values():
            contributions = tuple(
                c for c in fusion.contributions if c.model_reference == binding.manifest_digest
            )
            if not contributions:
                options[binding.manifest.model_kind].append(model_view(source, binding))
            for contribution in contributions:
                view = model_view(source, binding, contribution)
                observations.append(view)
                options[view.kind].append(view)
                signal_ids.update(view.signal_ids)
        for coverage in fusion.coverage:
            if any(b.manifest.model_kind == coverage.model_kind for b in bindings.values()):
                continue
            title, adapter = MODEL_LABELS[coverage.model_kind]
            options[coverage.model_kind].append(
                RetainedModelView(
                    kind=coverage.model_kind,
                    title=title,
                    adapter=adapter,
                    availability=(
                        "NOT AVAILABLE"
                        if coverage.status in ("not_run", "failed", "insufficient_input")
                        else "UNKNOWN"
                    ),
                    metadata_available=False,
                    reported_coverage=coverage.status,
                    incident_id=source.incident_id,
                    run_id=source.run_id,
                    assessment_id=source.assessment_id,
                    fusion_id=fusion.fusion_id,
                )
            )
        fusion_views.append(
            FusionMonitorView(
                fusion_id=fusion.fusion_id,
                version=fusion.fusion_version,
                incident_id=source.incident_id,
                run_id=source.run_id,
                assessment_id=source.assessment_id,
                checkpoint_revision=source.checkpoint_revision,
                snapshot_revision=source.snapshot_revision,
                agreement=fusion.agreement_state.value,
                coverage=fusion.coverage_state.value,
                confidence=fusion.confidence_state.value,
                created_at=fusion.created_at,
                contributions=tuple(
                    (c.model_kind, c.contribution_id) for c in fusion.contributions
                ),
                missing_models=fusion.missing_models,
                limitations=tuple(display_text(s) for s in fusion.limitations),
                cross_domain_state=fusion.summary.cross_domain_state,
            )
        )

    def order(value):
        return (
            value.last_observed.isoformat() if value.last_observed else "",
            value.contribution_id or "",
            str(value.incident_id),
            value.manifest_digest or "",
        )

    models = []
    for kind, values in options.items():
        title, adapter = MODEL_LABELS[kind]
        models.append(
            max(values, key=order)
            if values
            else RetainedModelView(
                kind=kind,
                title=title,
                adapter=adapter,
                availability="UNKNOWN",
                metadata_available=False,
            )
        )
    observations.sort(key=order, reverse=True)
    fusion_views.sort(
        key=lambda f: (
            f.created_at.isoformat() if f.created_at else "",
            str(f.incident_id),
            f.fusion_id,
        ),
        reverse=True,
    )
    return SecurityAIMonitorView(
        models=tuple(models),
        latest_retained_signals=tuple(observations),
        fusion_contexts=tuple(fusion_views),
        linked_incident_count=len({s.incident_id for s in sources}),
        retained_signal_count=len(signal_ids),
        latest_signal_at=max(
            (s.last_observed for s in observations if s.last_observed), default=None
        ),
    )
