import pytest
from tests.review_support import HumanConfirmations, authorize, record_review

from soc_agent.assessment import ThreatAssessment
from soc_agent.decision import IncidentDecisionEngine
from soc_agent.review import SeverityChange
from soc_agent.review.persistence import PersistentHumanReviewService, SQLiteGovernanceStore
from soc_agent.state import Evidence, IncidentState
from soc_agent.state.evidence import utc_now


@pytest.fixture
def case(tmp_path):
    state = IncidentState()
    state = state.add_evidence(
        Evidence(
            incident_id=state.incident_id,
            source="synthetic",
            summary="Test event",
            raw_data="{}",
            observed_at=utc_now(),
        )
    )
    assessment = ThreatAssessment(
        incident_id=state.incident_id,
        severity="high",
        confidence=0.2,
        summary="Unverified concern",
        supporting_evidence_ids=(state.evidence[0].evidence_id,),
    )
    decision = IncidentDecisionEngine().decide(state, assessment)
    store = SQLiteGovernanceStore.create(tmp_path / "governance.sqlite")
    store.register(state)
    authority = HumanConfirmations()
    service = PersistentHumanReviewService(store=store, authority=authority)
    return state, decision, authority, store, service


@pytest.fixture
def prepared(case):
    state, decision, authority, store, service = case
    review = record_review(service, authority, service.request_review(state, decision))
    request = service.propose_change(
        review,
        changes=(SeverityChange(before="info", after="medium"),),
        reason="Explicit human selection",
    )
    authorization = authorize(service, authority, request, review)
    return *case, review, request, authorization
