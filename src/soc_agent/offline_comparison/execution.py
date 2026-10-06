"""One allowlisted pure coverage transformation and paired offline replay."""

from soc_agent.improvement_candidates.models import (
    CoverageProposal,
    ImprovementCandidate,
    SampleFacts,
)
from soc_agent.improvement_dataset.models import ArtifactReference
from soc_agent.offline_comparison.adapter import measure, replay, safety
from soc_agent.offline_comparison.coverage_models import (
    CoverageConfiguration,
    CoverageGroundTruth,
    FrozenBaseline,
)
from soc_agent.offline_comparison.models import (
    EXEC_BUILDER_VERSION,
    EXEC_EVALUATOR_VERSION,
    CaseContent,
    CaseOutcome,
    EvaluationArtifacts,
    EvaluationBinding,
    EvaluationCase,
    OfflineCandidateVariant,
    OfflineEvaluationResult,
    ResultContent,
    VariantContent,
)
from soc_agent.offline_evaluation.models import CandidateTestPlan, EvaluationSpecification
from soc_agent.review.identity import content_digest
from soc_agent.review.persistence.models import StoredDataError


def build_variant(
    source: ImprovementCandidate, binding: EvaluationBinding, baseline: FrozenBaseline | None
) -> OfflineCandidateVariant:
    proposal = source.content.proposal
    baseline_ref = binding.frozen_baseline or "UNKNOWN"
    if baseline is not None:
        baseline = FrozenBaseline.model_validate(baseline.model_dump())
        if baseline_ref != ArtifactReference(
            identity=baseline.baseline_id, digest=content_digest(baseline.content)
        ) or (baseline.content.target_component, baseline.content.target_reference) != (
            proposal.target_component,
            proposal.target_reference,
        ):
            raise StoredDataError("Wrong frozen baseline target or digest")
    if isinstance(proposal, CoverageProposal):
        configuration = (
            CoverageConfiguration(
                covered_permissions=tuple(
                    sorted(
                        set(baseline.content.configuration.covered_permissions)
                        | {proposal.required_permission}
                    )
                )
            )
            if baseline is not None
            else None
        )
        content = VariantContent(
            binding=binding,
            candidate_type=source.content.candidate_type,
            target_component=proposal.target_component,
            baseline_reference=baseline_ref,
            builder_version=EXEC_BUILDER_VERSION,
            construction_status="CONSTRUCTIBLE",
            construction_reason="EXPLICIT_ALLOWLISTED_COVERAGE",
            structured_offline_change=proposal,
            configuration=configuration,
        )
    else:
        content = VariantContent(
            binding=binding,
            candidate_type=source.content.candidate_type,
            target_component=proposal.target_component,
            baseline_reference=baseline_ref,
        )
    digest = content_digest(content)
    return OfflineCandidateVariant(variant_id=digest, variant_version=digest, content=content)


def execute_pair(
    source: ImprovementCandidate,
    specification: EvaluationSpecification,
    plan: CandidateTestPlan,
    facts: tuple[SampleFacts, ...],
    baseline: FrozenBaseline,
    ground_truth: dict[str, CoverageGroundTruth],
) -> EvaluationArtifacts:
    from soc_agent.offline_comparison.evaluation import compare, evaluate_unavailable, reference

    # Shared integrity validation also retains the safe non-executable/empty-holdout path.
    foundation = evaluate_unavailable(source, specification, plan, facts, baseline=baseline)
    variant = foundation.variant
    if variant.content.configuration is None or not specification.content.partition.content.holdout:
        return foundation
    binding = variant.content.binding
    cases = []
    for original in foundation.baseline_result.content.cases:
        fact = original.content.facts
        truth = ground_truth.get(fact.sample.identity)
        if truth is None:
            raise StoredDataError("Frozen holdout ground-truth status missing")
        content = CaseContent(
            binding=binding,
            facts=fact,
            applicable_metrics=specification.content.metrics,
            coverage=truth,
            context_status="FROZEN_PERMISSION_COVERAGE_INPUT",
        )
        cases.append(EvaluationCase(case_id=content_digest(content), content=content))
    frozen_cases = tuple(cases)
    results = []
    for arm, configuration in (
        ("BASELINE", baseline.content.configuration),
        ("CANDIDATE", variant.content.configuration),
    ):
        outcomes = tuple(
            CaseOutcome(
                case=reference(case.case_id, case),
                status="EXECUTED",
                trace=replay(case, configuration),
            )
            for case in frozen_cases
        )
        invariants = safety(frozen_cases, outcomes)
        measurements = measure(specification.content.metrics, outcomes, invariants)
        content = ResultContent(
            evaluator_version=EXEC_EVALUATOR_VERSION,
            binding=binding,
            arm=arm,
            baseline_reference=binding.frozen_baseline,
            variant=reference(variant.variant_id, variant.content) if arm == "CANDIDATE" else None,
            cases=frozen_cases,
            per_case_outcomes=outcomes,
            metric_definitions=specification.content.metrics,
            measurements=measurements,
            invariants=invariants,
            blockers=(
                "INDEPENDENT_UNSEEN_EVIDENCE_UNAVAILABLE",
                "UNOBSERVABLE_DOWNSTREAM_GATES",
                "UNMEASURED_SPECIFICATION_METRICS",
            ),
            execution_status="EXECUTED",
            sandbox="OFFLINE_PERMISSION_COVERAGE",
        )
        results.append(
            OfflineEvaluationResult(
                result_id=content_digest(content),
                run_version=EXEC_EVALUATOR_VERSION,
                content=content,
            )
        )
    baseline_result, candidate_result = results
    return EvaluationArtifacts(
        variant=variant,
        baseline_result=baseline_result,
        candidate_result=candidate_result,
        comparison=compare(specification, baseline_result, candidate_result),
    )
