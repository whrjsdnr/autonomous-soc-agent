"""New drafts preserve the existing validity ceiling; no live operations or grants."""

from datetime import UTC, datetime, timedelta

import pytest

from soc_agent import agent_session


def test_fresh_session_keeps_shorter_review_expiry():
    now = datetime(2026, 11, 3, tzinfo=UTC)
    upper = now + timedelta(minutes=90)
    first = agent_session.draft_expiry(upper.isoformat(), now=now)
    later = agent_session.draft_expiry(first, now=now + timedelta(minutes=30))
    assert first == later == upper.isoformat()


def test_long_review_still_limits_candidate_to_twenty_four_hours():
    now = datetime(2026, 11, 3, tzinfo=UTC)
    value = agent_session.draft_expiry((now + timedelta(days=7)).isoformat(), now=now)
    assert datetime.fromisoformat(value) == now + timedelta(hours=24)


def test_expired_review_blocks_before_session_creation_or_namespace_check(tmp_path, monkeypatch):
    monkeypatch.setattr(
        agent_session,
        "verify_review",
        lambda *_args, **_kwargs: {"expires_at": "2020-01-01T00:00:00+00:00"},
    )

    def forbidden(*_args, **_kwargs):
        raise AssertionError("Expired review must stop before namespace observation")

    monkeypatch.setattr(agent_session, "namespace_binding", forbidden)
    parent = tmp_path / "session"
    with pytest.raises(ValueError, match="EXPIRED_NEW_REVIEW_REQUIRED"):
        agent_session.draft(tmp_path / "template", parent)
    assert not parent.exists()


@pytest.mark.parametrize("naive_now", [False, True])
def test_ambiguous_time_cannot_produce_candidate_validity(naive_now):
    now = datetime(2026, 11, 3, tzinfo=None if naive_now else UTC)
    upper = datetime(2026, 11, 4, tzinfo=UTC if naive_now else None)
    with pytest.raises(ValueError, match="TIMEZONE_REQUIRED"):
        agent_session.draft_expiry(upper.isoformat(), now=now)
