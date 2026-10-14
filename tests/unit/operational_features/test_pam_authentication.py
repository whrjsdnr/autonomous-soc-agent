"""Opt-in exact PAM module failure fixture; no login attempt generation."""

import pytest
from tests.unit.operational_features.test_native_authentication import INCIDENT, row, setup

from soc_agent.realtime.queue import EventQueue
from soc_agent.security_ai.operational.authentication_investigation import (
    investigate_authentication,
    read_authentication_view,
)
from soc_agent.security_ai.operational.authentication_pipeline import AuthenticationPipeline
from soc_agent.security_ai.operational.native_authentication import (
    PAM_COLLECTOR,
    PAM_PROFILE,
    authentication_source,
    project_journal,
)
from soc_agent.security_ai.operational.source_store import OperationalSourceStore


def pam_row():
    return row() | {
        "_EXE": "/usr/bin/sudo",
        "_COMM": "sudo",
        "_UID": "1000",
        "MESSAGE": (
            "pam_unix(sudo:auth): authentication failure; "
            "logname= uid=1000 euid=0 tty=/dev/pts/0 ruser= rhost=  user=fixture-user"
        ),
    }


def test_old_collector_profile_keeps_pam_unsupported():
    event = project_journal(pam_row())
    assert event.collector_id != PAM_COLLECTOR
    assert dict(event.normalized_fields)["parse_status"] == "NOT_INFERABLE"


@pytest.mark.asyncio
async def test_pam_optin_verified_failure_chain_and_read_only(tmp_path):
    p = setup(tmp_path)
    # Use a separate explicitly bound queue/store; never adopt or reinterpret the v1 queue.
    q = EventQueue.create(tmp_path / "pam" / "queue.sqlite")
    s = OperationalSourceStore.create(
        tmp_path / "pam" / "source.sqlite", allowed_lateness_seconds=60, max_future_skew_seconds=5
    )
    pipeline = AuthenticationPipeline(
        q, s, INCIDENT, collector_identity="linux:journal:authentication:pam-failure:v1"
    )
    event = project_journal(pam_row(), include_pam_failures=True)
    assert dict(event.normalized_fields)["parser"] == PAM_PROFILE
    assert dict(event.normalized_fields)["authentication_result"] == "failure"
    assert "fixture-user" not in event.model_dump_json()
    q.enqueue(event)
    receipt = pipeline.step()
    assert receipt.window_provenance[0].feature is not None
    view = read_authentication_view(pipeline)
    assert (view.authentication_window[0].total, view.authentication_window[0].failed) == (1, 1)
    assert (await investigate_authentication(pipeline)).plan.steps[0].status.value == "completed"
    p.queue.enqueue(event)
    with pytest.raises(ValueError, match="COLLECTOR_BINDING"):
        p.step()


@pytest.mark.parametrize(
    "change",
    [
        {"_EXE": "/usr/bin/logger"},
        {"_COMM": "logger"},
        {"_UID": "1001"},
        {"MESSAGE": "pam_unix(sudo:session): session opened for user fixture-user"},
        {"MESSAGE": pam_row()["MESSAGE"].replace("euid=0", "euid=1000")},
        {"MESSAGE": pam_row()["MESSAGE"].replace("rhost=  ", "rhost=192.0.2.5  ")},
        {"MESSAGE": pam_row()["MESSAGE"] + " execute block_ip"},
        {"MESSAGE": pam_row()["MESSAGE"].replace("user=fixture-user", "user=")},
    ],
)
def test_ambiguous_pam_fields_never_mapped(change):
    event = project_journal(pam_row() | change, include_pam_failures=True)
    assert dict(event.normalized_fields)["parse_status"] == "NOT_INFERABLE"


def test_pam_success_claim_rejected_even_with_forged_projection_digest():
    event = project_journal(pam_row(), include_pam_failures=True)
    fields = dict(event.normalized_fields)
    fields["authentication_result"] = "success"
    forged = event.model_copy(update={"normalized_fields": tuple(fields.items())})
    with pytest.raises(ValueError, match="PAM_FAILURE_PROFILE_RESULT"):
        authentication_source(
            forged, expected_event_digest=forged.source_digest, incident_id=INCIDENT
        )
