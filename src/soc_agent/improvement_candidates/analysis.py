"""Pure repeated-fact grouping. Correlation never supplies causal attribution."""

from soc_agent.experience.models import HistoricalOutcome
from soc_agent.feedback.models import DiagnosticLabel, Verdict
from soc_agent.improvement_candidates.models import (
    AnalysisConfig,
    DatasetBinding,
    FailurePattern,
    PatternContent,
    PatternType,
    SampleFacts,
)
from soc_agent.review.identity import content_digest
from soc_agent.review.persistence.models import StoredDataError


def matches(kind: PatternType, facts: SampleFacts) -> bool:
    if kind == PatternType.INCORRECT:
        return facts.verdict == Verdict.INCORRECT
    if kind in {
        PatternType.FALSE_POSITIVE,
        PatternType.FALSE_NEGATIVE,
        PatternType.UNNECESSARY_INVESTIGATION,
        PatternType.MISSED_INVESTIGATION,
    }:
        return DiagnosticLabel(kind.value.removesuffix("_pattern")) in facts.labels
    if kind == PatternType.EXECUTION_FAILURE:
        return facts.objective.execution_outcome == HistoricalOutcome.FAILED
    if kind == PatternType.EXECUTION_UNCERTAINTY:
        return facts.uncertain_observed or (
            facts.objective.execution_outcome == HistoricalOutcome.UNCERTAIN
        )
    return facts.recovery_observed


def analyze(
    dataset: DatasetBinding,
    facts: tuple[SampleFacts, ...],
    config: AnalysisConfig,
) -> tuple[FailurePattern, ...]:
    ordered = tuple(sorted(facts, key=lambda f: f.sample.identity))
    if len({f.sample.identity for f in ordered}) != len(ordered):
        raise StoredDataError("Duplicate analysis sample")
    patterns = []
    for kind in PatternType:
        support = tuple(f for f in ordered if matches(kind, f))
        if len(support) < config.minimum_pattern_support:
            continue
        feedback = {}
        for fact in support:
            for ref in fact.sources.feedback:
                if ref.identity in feedback and feedback[ref.identity] != ref:
                    raise StoredDataError("Conflicting feedback provenance")
                feedback[ref.identity] = ref
        content = PatternContent(
            dataset=dataset,
            config=config,
            pattern_type=kind,
            supporting_sample_refs=tuple(f.sample for f in support),
            supporting_feedback_refs=tuple(feedback[key] for key in sorted(feedback)),
            observed_facts=support,
            occurrence_count=len(support),
        )
        patterns.append(FailurePattern(pattern_id=content_digest(content), content=content))
    return tuple(sorted(patterns, key=lambda p: p.pattern_id))
