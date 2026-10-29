"""Accelerated synthetic event time, never a real Kernel or wall-clock soak."""

import json
from uuid import NAMESPACE_URL, uuid5

import pytest
from tests.unit.continuous.test_capture_admission import NS, raw_event, transcript

from soc_agent.continuous.capture import CaptureSeal, CaptureWindows
from soc_agent.security_ai.research.models import digest
from soc_agent.security_ai.tcx_input import candidates


def shifted_window(index):
    seal, events = transcript()
    shift = index * 180_000_000_000
    generation = 7 + index
    session = uuid5(NAMESPACE_URL, str(generation))
    body = seal.model_dump(mode="json", exclude={"seal_sha256"})
    body.update(generation=generation, session=str(session))
    for row in body["cpu_windows"]:
        row["before_ns"] += shift
        row["after_ns"] += shift
    for row in body["clock_samples"]:
        row["generation"] = generation
        for field in ("before_ns", "after_ns", "wall_ns"):
            row[field] += shift
    sealed = CaptureSeal.model_validate(body | dict(seal_sha256=digest(body)))
    messages = []
    for event in events:
        moved = event.model_copy(
            update=dict(generation=generation, session_id=session, timestamp_ns=event.ns + shift)
        )
        message = raw_event(moved)
        message["id"] = str(uuid5(session, str(event.sequence)))
        messages.append(message)
    messages.append(
        dict(
            kind="native_seal",
            id=str(uuid5(session, "seal")),
            sequence=4,
            seal=sealed.model_dump(mode="json"),
        )
    )
    return messages


def test_seventy_two_minutes_multiseal_crash_reconstruction_and_replay():
    windows = CaptureWindows(NS, "b" * 64)
    retained = []
    identities = set()
    for index in range(25):
        raw = shifted_window(index)
        for message in raw:
            retained.append(json.loads(json.dumps(message)))
            jobs, assessment = windows.accept(message)
            if jobs:
                assert assessment["status"] == "VERIFIED"
                assert sum(r["eligible"] for j in jobs for r in candidates(j)[2]) == 1
                identities.update(digest(j.model_dump(mode="json")) for j in jobs)
        assert not windows.events
        if index == 12:
            recovered = CaptureWindows(NS, "b" * 64)
            recovered_ids = set()
            for message in retained:
                jobs, _ = recovered.accept(message)
                recovered_ids.update(digest(j.model_dump(mode="json")) for j in jobs)
            assert recovered_ids == identities
            windows = recovered
    assert len(identities) == len(windows.sealed) == 25
    assert windows.abandoned == 0 and windows.last_capture["status"] == "VERIFIED"
    with pytest.raises(ValueError, match="REPLAY"):
        windows.accept(retained[-1])
