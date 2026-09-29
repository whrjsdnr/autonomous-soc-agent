"""Independent interpreters; no shared provider memory or SQLite connection."""

import multiprocessing
import os

import pytest
from tests.unit.confirmations.conftest import authority_for
from tests.unit.confirmations.test_consumption import issue
from tests.unit.identity.conftest import Boundary

from soc_agent.review.authentication import (
    AuthenticatedPrincipal,
    HumanActionContext,
    HumanConfirmation,
)
from soc_agent.review.authorization import HumanRole
from soc_agent.review.errors import HumanAuthorizationDenied
from soc_agent.review.persistence import SQLiteGovernanceStore
from soc_agent.review.persistence.confirmations import SQLiteConfirmationConsumer


def consume_worker(path, packet, barrier, output):
    principal = AuthenticatedPrincipal.model_validate_json(packet[0])
    confirmation = HumanConfirmation.model_validate_json(packet[1])
    context = HumanActionContext.model_validate_json(packet[2])
    boundary = Boundary()
    token = "test-only-opaque-proof"
    boundary.provider.principals[token] = principal
    boundary.provider.confirmations[token] = confirmation
    boundary.contexts[(context.action, context.binding_digest)] = context
    boundary.roles.assignments[
        (principal.provider_id, principal.subject_id, context.incident_id)
    ] = (HumanRole.ADMIN,)
    consumer = SQLiteConfirmationConsumer(SQLiteGovernanceStore(path).database)
    authority = authority_for(boundary, consumer)
    if barrier:
        barrier.wait(timeout=30)
    try:
        authority.verify(
            credential=token, action=context.action, binding_digest=context.binding_digest
        )
        result = "consumed"
    except HumanAuthorizationDenied:
        result = "denied"
    output.put((os.getpid(), result))


@pytest.mark.parametrize("concurrent", [False, True])
def test_independent_process_replay_or_race(boundary, planning, concurrent):
    token, context = issue(boundary, planning)
    packet = (
        boundary.provider.principals[token].model_dump_json(),
        boundary.provider.confirmations[token].model_dump_json(),
        context.model_dump_json(),
    )
    ctx = multiprocessing.get_context("spawn")
    barrier = ctx.Barrier(2) if concurrent else None
    output = ctx.Queue()
    children = [
        ctx.Process(
            target=consume_worker, args=(planning[3].database.path, packet, barrier, output)
        )
        for _ in range(2)
    ]
    results = []
    for child in children:
        child.start()
        if not concurrent:
            results.append(output.get(timeout=45))
            child.join(30)
    if concurrent:
        results = [output.get(timeout=45) for _ in children]
    for child in children:
        child.join(30)
        assert child.exitcode == 0
    assert len({pid for pid, _ in results}) == 2
    assert sorted(result for _, result in results) == ["consumed", "denied"]
    proof = boundary.provider.confirmations[token]
    stored = SQLiteConfirmationConsumer(planning[3].database).load(
        proof.provider_id, proof.confirmation_id
    )
    assert stored.consumed
    assert stored.verification.context == context
