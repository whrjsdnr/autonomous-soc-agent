from datetime import timedelta

import pytest
from pydantic import ValidationError
from tests.unit.identity.conftest import Boundary
from tests.unit.improvement_review.test_policy import request_for_policy

from soc_agent.improvement_dataset.models import ArtifactReference
from soc_agent.improvement_promotion.models import (
    FAMILY_SCOPE,
    ActivePointer,
    ArtifactContent,
    PromotionContent,
    PromotionRequest,
    RollbackContent,
    RollbackRequest,
    SourceSnapshot,
    VersionedImprovementArtifact,
    action_context,
)
from soc_agent.planning.strategy import InvestigationStrategy
from soc_agent.review.authorization import HumanRole, RBACPermissionVerifier
from soc_agent.review.errors import HumanAuthorizationDenied
from soc_agent.review.identity import content_digest
from soc_agent.state.evidence import utc_now
from soc_agent.tools.enums import ToolPermission as P


def proposal():
    r = request_for_policy()
    source = SourceSnapshot(
        review_request=ArtifactReference(
            identity=r.review_request_id, digest=content_digest(r.content)
        ),
        review_record=ArtifactReference(identity="a" * 64, digest="b" * 64),
        snapshot=r.content,
    )
    content = PromotionContent(
        payload=InvestigationStrategy(required_permissions=(P.NETWORK_READ,)),
        source_snapshot=source,
        expected=ActivePointer(),
    )
    return PromotionRequest(request_id=content_digest(content), content=content)


def test_canonical_immutable_identity_and_separate_family_scope():
    r = proposal()
    other = r.model_copy(update={"created_at": r.created_at + timedelta(seconds=1)})
    assert other.request_id == r.request_id
    content = ArtifactContent(
        version=1, payload=r.content.payload, source_snapshot=r.content.source_snapshot
    )
    artifact = VersionedImprovementArtifact(
        artifact_id=content_digest(content), content_digest=content_digest(content), content=content
    )
    assert (
        artifact.model_copy(update={"created_at": utc_now()}).content_digest
        == artifact.content_digest
    )
    with pytest.raises(ValidationError):
        artifact.content.version = 9
    assert (
        action_context(r).incident_id
        == FAMILY_SCOPE
        != r.content.source_snapshot.snapshot.authorization_incident
    )
    assert not hasattr(r.content, "role")


@pytest.mark.parametrize(
    "values",
    [
        {"family": "arbitrary"},
        {"payload": {"required_permissions": ["system_write"]}},
        {"payload": {"required_permissions": ["arbitrary"]}},
        {"payload": {"required_permissions": ["network_read"], "operation": "EXECUTE"}},
        {"executable": "arbitrary shell"},
    ],
)
def test_malformed_artifact_parameters_rejected(values):
    r = proposal()
    data = ArtifactContent(
        version=1, payload=r.content.payload, source_snapshot=r.content.source_snapshot
    ).model_dump(mode="json")
    if "family" in values:
        values = {"artifact_family": values["family"]}
    with pytest.raises(ValidationError):
        ArtifactContent.model_validate(data | values)


@pytest.mark.parametrize("kind", ["promotion", "rollback"])
def test_admin_only_separate_permission_and_purpose(kind):
    r = proposal()
    if kind == "rollback":
        content = RollbackContent(
            target=ArtifactReference(identity="c" * 64, digest="c" * 64),
            target_version=1,
            expected=ActivePointer(
                active_artifact=ArtifactReference(identity="d" * 64, digest="d" * 64),
                active_version=2,
                revision=2,
            ),
        )
        r = RollbackRequest(request_id=content_digest(content), content=content)
    b = Boundary()
    context = action_context(r)
    for role in HumanRole:
        token = b.issue(context, (role,))
        permissions = RBACPermissionVerifier(roles=b.roles)
        principal = b.provider.authenticate(token)
        if role == HumanRole.ADMIN:
            permissions.require_permission(principal, context)
        else:
            with pytest.raises(HumanAuthorizationDenied):
                permissions.require_permission(principal, context)


def test_canonical_source_hash_json_contract_and_concurrent_independence():
    from concurrent.futures import ThreadPoolExecutor

    from soc_agent._json import canonical_json_object

    values = [{"number": i, "array": [True, None, i], "unicode": "검증"} for i in range(16)]
    expected = [canonical_json_object(value) for value in values]
    with ThreadPoolExecutor(max_workers=4) as pool:
        assert list(pool.map(canonical_json_object, values)) == expected
    assert all(canonical_json_object(value) == value for value in expected)
    assert canonical_json_object({"b": 1, "a": [2, 1]}) == '{"a":[2,1],"b":1}'
    for invalid in ({1: "not a string key"}, {"number": float("nan")}, [1, 2]):
        with pytest.raises(ValueError):
            canonical_json_object(invalid)
