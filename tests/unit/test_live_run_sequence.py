"""Control orchestration fixture only; no OS authentication, BPF, TCX or GUI."""

from types import SimpleNamespace
from uuid import uuid4

import pytest

from soc_agent.security_ai.ebpf_native.contracts import Scope
from soc_agent.security_ai.ebpf_tc.live_run import start_live_run


def preparation(tmp_path, sequence, *, denied=False):
    scope = Scope(
        ifindex=1,
        net_namespace="net:[1]",
        hook="INGRESS",
        program_sha256="a" * 64,
        loader_sha256="b" * 64,
        bundle_digest="c" * 64,
    )
    app = SimpleNamespace(application_session=uuid4(), scope=scope)
    handoff = SimpleNamespace(
        origin="TCX_LIVE_QUALIFICATION_NATIVE",  # Exercise guard; no real Native actions.
        state="BROKER_READY",
        sequence=sequence,
        plan=SimpleNamespace(approval="d" * 64, broker=SimpleNamespace(application=app)),
        data=SimpleNamespace(adapter=SimpleNamespace(flow=SimpleNamespace(closed=True))),
        error=None,
    )
    commands, closes = [], []

    def command(value):
        commands.append(value)
        assert value.sequence == handoff.sequence + 1
        if denied:
            raise ValueError("fixture rejection")
        handoff.sequence = value.sequence

    handoff.command = command
    handoff.observe = lambda: None
    handoff.close = lambda: closes.append("closed")
    handoff.snapshot = lambda: {"source": "UNPRIVILEGED_ORCHESTRATION_FIXTURE"}
    prep = SimpleNamespace(
        _os_handoff=handoff,
        controller=SimpleNamespace(application=SimpleNamespace(directory=tmp_path)),
    )
    return prep, commands, closes


@pytest.mark.parametrize("sequence", [0, 1, 7])
def test_attach_follows_last_control_request(tmp_path, sequence):
    prep, commands, closes = preparation(tmp_path, sequence)
    result = start_live_run(prep)
    assert len(commands) == 1
    assert commands[0].command == "ATTACH"
    assert commands[0].sequence == sequence + 1
    assert closes == ["closed"]
    assert result["source"] == "UNPRIVILEGED_ORCHESTRATION_FIXTURE"


def test_attach_failure_closes_once_without_retry(tmp_path):
    prep, commands, closes = preparation(tmp_path, 1, denied=True)
    with pytest.raises(ValueError, match="fixture rejection"):
        start_live_run(prep)
    assert len(commands) == 1
    assert closes == ["closed"]
