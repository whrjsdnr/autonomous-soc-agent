"""Project pinned learning facts, without running the historical learning pipeline."""

from soc_agent.api.dashboard.incident_query import display_text
from soc_agent.api.dashboard.self_improvement_models import (
    ActiveVersionView,
    ComparisonView,
    LearningRecordView,
    LearningSection,
    SelfImprovementView,
    VersionView,
)
from soc_agent.improvement_candidates.models import CoverageProposal
from soc_agent.improvement_promotion.eligibility import project_eligibility
from soc_agent.review.persistence.self_improvement import SelfImprovementSnapshot


def project_self_improvement(source: SelfImprovementSnapshot) -> SelfImprovementView:
    records, visible = source.records, source.visible_incidents
    sections = []

    def values(table):
        return records.get(table, {}).values()

    def section(name, table, rows):
        sections.append(
            LearningSection(
                name=name,
                available=table in records,
                records=tuple(sorted(rows, key=lambda r: r.identity)),
            )
        )

    def row(identity, title, facts, incidents=(), created_at=None):
        return LearningRecordView(
            identity=identity,
            title=title,
            facts=tuple((label, display_text(str(value))) for label, value in facts),
            incidents=tuple(sorted(incidents, key=str)),
            created_at=created_at,
        )

    experiences = [v for v in values("experiences") if v.content.incident_id in visible]
    experience_ids = {v.experience_id for v in experiences}
    outcomes = [v for v in values("evaluations") if v.content.experience_id in experience_ids]
    feedback = [v for v in values("analyst_feedback") if v.request.experience_id in experience_ids]
    section(
        "Historical Experience",
        "experiences",
        [
            row(
                v.experience_id,
                "HISTORICAL DATA · NOT AUTHORITY",
                (
                    ("Outcome", v.content.execution_outcome.value),
                    (
                        "Outcome evaluation records",
                        sum(o.content.experience_id == v.experience_id for o in outcomes),
                    ),
                    (
                        "Feedback records",
                        sum(f.request.experience_id == v.experience_id for f in feedback),
                    ),
                    (
                        "Prior governance",
                        "Historical references cannot authorize current execution",
                    ),
                ),
                (v.content.incident_id,),
                v.created_at,
            )
            for v in experiences
        ],
    )
    section(
        "Outcome Evaluation",
        "evaluations",
        [
            row(
                v.evaluation_id,
                "DESCRIPTIVE FACTS · NOT CORRECTNESS OR FUTURE SAFETY",
                (
                    ("Experience", v.content.experience_id),
                    ("Execution outcome", v.content.execution_outcome.value),
                    ("Governance outcome", v.content.governance_outcome.value),
                    ("Recovery observed", v.content.recovery_observed),
                    ("Uncertainty observed", v.content.uncertain_observed),
                ),
                (v.content.incident_id,),
                v.created_at,
            )
            for v in outcomes
        ],
    )
    section(
        "Analyst Feedback",
        "analyst_feedback",
        [
            row(
                v.feedback_id,
                "HUMAN JUDGMENT · NOT EXECUTION AUTHORITY",
                (
                    ("Verdict", v.request.verdict.value),
                    ("Labels", ", ".join(label.value for label in v.request.labels) or "NONE"),
                    (
                        "Path adjudication",
                        v.request.coverage_expectation.path_adjudication.review_completeness.value
                        if v.request.coverage_expectation
                        and v.request.coverage_expectation.path_adjudication
                        else "NOT AVAILABLE",
                    ),
                    ("Human note", v.request.note or "NOT AVAILABLE"),
                ),
                (v.request.incident_id,),
                v.created_at,
            )
            for v in feedback
        ],
    )
    datasets = [
        v
        for v in values("improvement_datasets")
        if all(s.sources.incident_id in visible for s in v.manifest.selection)
    ]
    dataset_ids = {v.dataset_id for v in datasets}
    section(
        "Dataset Snapshots",
        "improvement_datasets",
        [
            row(
                v.dataset_id,
                "IMMUTABLE OFFLINE SNAPSHOT",
                (
                    ("Version / manifest", v.manifest_digest),
                    ("Samples", v.manifest.sample_count),
                    ("Excluded", v.manifest.excluded_count),
                ),
                created_at=v.created_at,
            )
            for v in datasets
        ],
    )
    patterns = [
        v for v in values("failure_patterns") if v.content.dataset.dataset_id in dataset_ids
    ]
    section(
        "Failure Analysis",
        "failure_patterns",
        [
            row(
                v.pattern_id,
                v.content.pattern_type.value,
                (
                    ("Dataset", v.content.dataset.dataset_id),
                    ("Occurrences", v.content.occurrence_count),
                    ("Root cause", v.content.root_cause_status),
                ),
                created_at=v.created_at,
            )
            for v in patterns
        ],
    )
    candidates = [
        v for v in values("improvement_candidates") if v.content.dataset.dataset_id in dataset_ids
    ]
    candidate_ids = {v.candidate_id for v in candidates}
    requests = [
        v
        for v in values("improvement_review_requests")
        if v.content.binding.source.candidate.identity in candidate_ids
    ]
    reviews = [
        v
        for v in values("improvement_review_records")
        if v.snapshot.binding.source.candidate.identity in candidate_ids
    ]
    review_by_request = {v.submission.review_request.identity: v for v in reviews}
    plans = [
        v
        for v in values("candidate_test_plans")
        if v.content.binding.candidate.identity in candidate_ids
    ]
    section(
        "Improvement Candidates",
        "improvement_candidates",
        [
            row(
                v.candidate_id,
                v.content.candidate_type.value,
                (
                    ("Operation", v.content.proposal.operation),
                    ("Status", v.content.status),
                    (
                        "Structured support",
                        "SUPPORTED TYPED CONTRACT"
                        if isinstance(v.content.proposal, CoverageProposal)
                        else "NOT SUPPORTED · REVIEW ONLY",
                    ),
                    ("Dataset", v.content.dataset.dataset_id),
                    ("Proposal rationale", v.content.rationale),
                    ("Expected effect (advisory)", v.content.expected_effect),
                    (
                        "Offline test plans",
                        sum(p.content.binding.candidate.identity == v.candidate_id for p in plans),
                    ),
                    (
                        "Review requests",
                        sum(
                            r.content.binding.source.candidate.identity == v.candidate_id
                            for r in requests
                        ),
                    ),
                ),
                created_at=v.created_at,
            )
            for v in candidates
        ],
    )
    for title, table in (
        ("Offline Specifications", "offline_evaluation_specifications"),
        ("Offline Test Plans", "candidate_test_plans"),
        ("Offline Candidate Variants", "offline_candidate_variants"),
        ("Offline Evaluation Results", "offline_evaluation_results"),
    ):
        rows = []
        for value in values(table):
            content = value.content
            binding = content.binding
            candidate_ref = (
                binding.candidate if hasattr(binding, "candidate") else binding.source.candidate
            )
            if candidate_ref.identity not in candidate_ids:
                continue
            facts = [("Candidate", candidate_ref.identity)]
            for field in (
                "status",
                "evaluation_mode",
                "execution_mode",
                "construction_status",
                "execution_status",
                "arm",
                "sandbox",
            ):
                if hasattr(content, field):
                    facts.append((field, getattr(content, field)))
            if hasattr(binding, "frozen_baseline"):
                facts.append(
                    (
                        "Frozen baseline",
                        binding.frozen_baseline.identity if binding.frozen_baseline else "UNKNOWN",
                    )
                )
            if hasattr(content, "blockers"):
                facts.append(("Blockers", ", ".join(content.blockers) or "NONE"))
            identity_field = {
                "offline_evaluation_specifications": "specification_id",
                "candidate_test_plans": "plan_id",
                "offline_candidate_variants": "variant_id",
                "offline_evaluation_results": "result_id",
            }[table]
            rows.append(
                row(
                    getattr(value, identity_field),
                    "OFFLINE ONLY · NOT PRODUCTION EXECUTION",
                    facts,
                    created_at=value.created_at,
                )
            )
        section(title, table, rows)
    comparisons = []
    for v in values("offline_comparisons"):
        c = v.content
        if c.binding.source.candidate.identity not in candidate_ids:
            continue
        spec = records["offline_evaluation_specifications"][c.binding.specification.identity]
        partition = spec.content.partition.content
        comparisons.append(
            ComparisonView(
                identity=v.comparison_id,
                candidate_id=c.binding.source.candidate.identity,
                dataset_id=c.binding.source.dataset.dataset_id,
                development_count=len(partition.development),
                holdout_count=len(partition.holdout),
                baseline_id=c.baseline_result.identity,
                candidate_result_id=c.candidate_result.identity,
                metrics=tuple(
                    (
                        m.metric.value,
                        str(m.baseline.value)
                        if m.baseline.value is not None
                        else m.baseline.state.value,
                        str(m.candidate.value)
                        if m.candidate.value is not None
                        else m.candidate.state.value,
                        str(m.delta) if m.delta is not None else "NOT_MEASURABLE",
                        m.outcome,
                    )
                    for m in c.metrics
                ),
                safety=tuple(
                    (s.invariant.value, s.baseline.value, s.candidate.value) for s in c.safety
                ),
                acceptance=tuple(
                    (a.metric.value, a.operator, a.status.value) for a in c.acceptance
                ),
                created_at=v.created_at,
            )
        )
    eligibility_rows = []
    for request in requests:
        record = review_by_request.get(request.review_request_id)
        result = records["offline_evaluation_results"][request.content.candidate_result.identity]
        eligibility = project_eligibility(request, record, result)
        eligibility_rows.append(
            row(
                request.review_request_id,
                eligibility.status,
                (
                    ("Candidate", eligibility.candidate.identity),
                    ("Reasons", ", ".join(eligibility.reasons) or "NONE"),
                    (
                        "Scope",
                        "Pinned durable evidence projection; command revalidates full source graph",
                    ),
                    ("Reviewability", request.content.reviewability),
                ),
                created_at=request.created_at,
            )
        )
    section("Promotion Eligibility", "improvement_review_requests", eligibility_rows)
    section(
        "Human Improvement Review",
        "improvement_review_records",
        [
            row(
                v.review_record_id,
                v.submission.decision.value,
                (
                    ("Candidate", v.snapshot.binding.source.candidate.identity),
                    ("Review request", v.submission.review_request.identity),
                    ("Reason", v.submission.reason.value),
                    ("Human note", v.submission.note or "NOT AVAILABLE"),
                    ("Reviewer", v.verification.subject_id),
                    ("Authority", "PROMOTION CONSIDERATION ONLY · NOT PROMOTION"),
                ),
                created_at=v.created_at,
            )
            for v in reviews
        ],
    )
    artifacts = [
        v
        for v in values("improvement_artifacts")
        if v.content.source_snapshot.snapshot.binding.source.candidate.identity in candidate_ids
    ]
    artifact_ids = {v.artifact_id for v in artifacts}
    promotions = [
        v
        for v in values("improvement_promotion_records")
        if v.current.active_artifact.identity in artifact_ids
    ]
    rollbacks = [
        v
        for v in values("improvement_rollback_records")
        if v.current.active_artifact.identity in artifact_ids
        and v.previous.active_artifact.identity in artifact_ids
    ]
    versions = tuple(
        sorted(
            (
                VersionView(
                    artifact_id=v.artifact_id,
                    family=v.content.artifact_family.value,
                    version=v.content.version,
                    operation=v.content.payload.operation,
                    permissions=tuple(p.value for p in v.content.payload.required_permissions),
                    source_candidate=v.content.source_snapshot.snapshot.binding.source.candidate.identity,
                    active=source.pointer is not None
                    and source.pointer.active_artifact is not None
                    and source.pointer.active_artifact.identity == v.artifact_id,
                    promotion_records=tuple(
                        p.record_id
                        for p in promotions
                        if p.current.active_artifact.identity == v.artifact_id
                    ),
                    rollback_from=tuple(
                        r.record_id
                        for r in rollbacks
                        if r.previous.active_artifact.identity == v.artifact_id
                    ),
                    rollback_to=tuple(
                        r.record_id
                        for r in rollbacks
                        if r.current.active_artifact.identity == v.artifact_id
                    ),
                    created_at=v.created_at,
                )
                for v in artifacts
            ),
            key=lambda v: v.version,
        )
    )
    active_version = next((v for v in versions if v.active), None)
    pointer = source.pointer
    active = ActiveVersionView(state="UNKNOWN")
    if pointer is not None and pointer.active_artifact is None:
        active = ActiveVersionView(state="NONE", pointer_revision=0)
    elif active_version is not None:
        activation = next((v for v in promotions + rollbacks if v.current == pointer), None)
        active = ActiveVersionView(
            state="ACTIVE",
            artifact=active_version,
            pointer_revision=pointer.revision,
            activation_record=activation.record_id if activation else None,
            activated_at=activation.created_at if activation else None,
        )
    for title, table, entries in (
        ("Promotion Records", "improvement_promotion_records", promotions),
        ("Rollback Records", "improvement_rollback_records", rollbacks),
    ):
        section(
            title,
            table,
            [
                row(
                    v.record_id,
                    v.action,
                    (
                        ("Request", v.request.identity),
                        (
                            "Previous version",
                            v.previous.active_version
                            if v.previous.active_version is not None
                            else "NONE",
                        ),
                        ("New version", v.current.active_version),
                        ("Pointer revision", v.current.revision),
                        ("Permission", v.verification.permission.value),
                    ),
                    created_at=v.created_at,
                )
                for v in entries
            ],
        )

    def count(table, entries):
        return len(entries) if table in records else None

    return SelfImprovementView(
        experience_count=count("experiences", experiences),
        candidate_count=count("improvement_candidates", candidates),
        awaiting_review_count=count(
            "improvement_review_requests",
            [r for r in requests if r.review_request_id not in review_by_request],
        ),
        rollback_target_count=len([v for v in versions if not v.active])
        if active.state == "ACTIVE"
        else 0
        if active.state == "NONE"
        else None,
        active=active,
        sections=tuple(sections),
        comparisons=tuple(sorted(comparisons, key=lambda v: v.identity)),
        versions=versions,
        lifecycle_counts=(
            ("EXPERIENCE", count("experiences", experiences)),
            ("FAILURE ANALYSIS", count("failure_patterns", patterns)),
            ("CANDIDATE", count("improvement_candidates", candidates)),
            ("OFFLINE EVALUATION", count("offline_comparisons", comparisons)),
            ("HUMAN REVIEW", count("improvement_review_records", reviews)),
            ("PROMOTION", count("improvement_promotion_records", promotions)),
            (
                "ACTIVE VERSION",
                1 if active.state == "ACTIVE" else 0 if active.state == "NONE" else None,
            ),
            ("ROLLBACK", count("improvement_rollback_records", rollbacks)),
        ),
    )
