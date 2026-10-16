import asyncio

import pytest
from tests.research_adapter_support import research_paths
from tests.unit.streaming_network.test_auth import Process

from soc_agent.security_ai.research.stream_service import StreamingMonitoring
from soc_agent.security_ai.research.total_auth import TerminalAuthentication


@pytest.mark.asyncio
@pytest.mark.parametrize("code", [0, 1, 126, 127])
async def test_total_mock_auth_exit_no_privilege_or_password(tmp_path, monkeypatch, code):
    owner = StreamingMonitoring(tmp_path, total=True, paths=research_paths())
    command = await owner.start()
    calls = []

    async def launcher(*args, **kwargs):
        calls.append((args, kwargs))
        return Process(code)

    auth = TerminalAuthentication(launcher=launcher)
    try:
        with pytest.raises(ValueError, match="EXPLICIT_APPROVAL"):
            await auth.start(owner, "f" * 64)
        await auth.start(owner, command["helper_sha256"])
        await asyncio.wait_for(auth.task, 5)
        args, kw = calls[0]
        assert args[:3] == ("/usr/bin/sudo", "-n", "/usr/bin/setpriv")
        assert "soc_agent.security_ai.operational.network_capture.total_helper" in args
        assert "--no-new-privs" in args and "--clear-groups" in args
        assert "-S" not in args
        assert kw["stdin"] == asyncio.subprocess.DEVNULL
        assert set(kw["env"]) == {"PATH", "LANG"}
        assert not owner.capture.listener_ready()
        assert not owner.snapshot()["collection_live"]
    finally:
        await owner.stop(abort=True)
        await auth.cancel()
