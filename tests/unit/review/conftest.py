import pytest
from tests.review_support import HumanConfirmations, authorize, record_review

from soc_agent.assessment import ThreatAssessment
from soc_agent.decision import IncidentDecisionEngine
from soc_agent.review import HumanReviewService, InMemoryIncidentStateStore, SeverityChange
from soc_agent.state import Evidence, IncidentState
from soc_agent.state.evidence import utc_now


@pytest.fixture
def case():
    state = IncidentState()
    state = state.add_evidence(
        Evidence(
            incident_id=state.incident_id,
            source="auth.log",
            summary="Failed login",
            raw_data="{}",
            observed_at=utc_now(),
        )
    )
    assessment = ThreatAssessment(
        incident_id=state.incident_id,
        severity="high",
        confidence=0.2,
        summary="Advisory concern, not confirmed compromise",
        supporting_evidence_ids=(state.evidence[0].evidence_id,),
    )
    decision = IncidentDecisionEngine().decide(state, assessment)
    authority = HumanConfirmations()
    store = InMemoryIncidentStateStore((state,))
    service = HumanReviewService(store=store, authority=authority)
    return state, decision, authority, store, service


@pytest.fixture
def prepared(case):
    state, decision, authority, store, service = case
    review_request = service.request_review(state, decision)
    review = record_review(service, authority, review_request)
    request = service.propose_change(
        review,
        changes=(SeverityChange(before="info", after="high"),),
        reason="Human selected advisory severity after source review",
    )
    authorization = authorize(service, authority, request, review)
    return *case, review, request, authorization
