"""All privilege launchers are injected mocks. Only unprivileged UNIX listeners exist."""

import asyncio
from types import SimpleNamespace

import pytest
from tests.research_adapter_support import research_paths

from soc_agent.security_ai.research.stream_auth import OSAuthentication, arguments, support
from soc_agent.security_ai.research.stream_service import StreamingMonitoring


class Process:
    def __init__(self, code=None):
        self.returncode = code
        self.finished = asyncio.Event()
        self.terminated = False
        if code is not None:
            self.finished.set()

    async def wait(self):
        await self.finished.wait()
        return self.returncode

    def terminate(self):
        self.terminated = True
        self.returncode = -15
        self.finished.set()


def available():
    return {"status": "OS_AUTH_UI_AVAILABLE_UNTESTED"}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("code", "expected"),
    [
        (0, "HELPER_EXIT_WITHOUT_READY"),
        (126, "AUTH_CANCELLED"),
        (127, "AUTH_DENIED"),
        (1, "HELPER_FAILED"),
    ],
)
async def test_mock_auth_result_and_no_secret_environment(tmp_path, monkeypatch, code, expected):
    owner = StreamingMonitoring(tmp_path, paths=research_paths())
    command = await owner.start()
    calls = []

    async def launcher(*args, **kwargs):
        calls.append((args, kwargs))
        return Process(code)

    monkeypatch.setenv("UNRELATED_SECRET_TOKEN", "must-not-enter-helper-env")
    auth = OSAuthentication(
        launcher=launcher, inspector=available, binary=lambda: "/usr/bin/pkexec"
    )
    try:
        await auth.start(owner, command["helper_sha256"])
        await asyncio.wait_for(auth.task, 5)
        assert auth.state == expected
        args, kwargs = calls[0]
        assert args[:2] == ("/usr/bin/pkexec", "/usr/bin/setpriv")
        assert "--reuid=1000" in args or f"--reuid={owner.session.uid}" in args
        assert "--bounding-set=-all,+net_raw" in args
        assert "--ambient-caps=-all,+net_raw" in args
        assert "--no-new-privs" in args
        assert not kwargs.get("shell", False)
        assert "UNRELATED_SECRET_TOKEN" not in kwargs["env"]
        assert "password" not in kwargs
        if code:
            assert not owner.capture.listener_ready()
            assert owner.state == "ERROR"
    finally:
        await owner.stop(abort=True)
        await auth.cancel()


@pytest.mark.asyncio
async def test_unavailable_ui_never_launches_or_claims_auth_verified():
    calls = []
    auth = OSAuthentication(
        launcher=lambda *a, **k: calls.append(a),
        inspector=lambda: {"status": "OS_AUTH_UI_UNAVAILABLE"},
    )
    result = await auth.start(None, "a" * 64)
    assert result["status"] == "OS_AUTH_UI_UNAVAILABLE"
    assert not calls
    assert support()["native_authentication_verified"] is False


@pytest.mark.asyncio
async def test_new_sha_and_current_listener_required(tmp_path):
    owner = StreamingMonitoring(tmp_path, paths=research_paths())
    command = await owner.start()
    calls = []
    auth = OSAuthentication(
        launcher=lambda *a, **k: calls.append(a),
        inspector=available,
        binary=lambda: "/usr/bin/pkexec",
    )
    with pytest.raises(ValueError, match="EXPLICIT_APPROVAL"):
        await auth.start(owner, "a" * 64)
    await owner.stop(abort=True)
    with pytest.raises(ValueError, match="CURRENT_LISTENER"):
        await auth.start(owner, command["helper_sha256"])
    assert not calls


@pytest.mark.asyncio
async def test_cancel_and_launch_error_close_listener(tmp_path):
    owner = StreamingMonitoring(tmp_path, paths=research_paths())
    command = await owner.start()
    process = Process()

    async def launcher(*a, **k):
        return process

    auth = OSAuthentication(
        launcher=launcher, inspector=available, binary=lambda: "/usr/bin/pkexec"
    )
    await auth.start(owner, command["helper_sha256"])
    with pytest.raises(ValueError, match="ALREADY_PENDING"):
        await auth.start(owner, command["helper_sha256"])
    await owner.stop(abort=True)
    await auth.cancel()
    await asyncio.wait_for(auth.task, 5)
    assert process.terminated
    assert not owner.capture.listener_ready()
    owner2 = StreamingMonitoring(tmp_path / "another", paths=research_paths())
    command2 = await owner2.start()

    async def fail(*a, **k):
        raise OSError("private diagnostic must not be retained")

    auth2 = OSAuthentication(launcher=fail, inspector=available, binary=lambda: "/usr/bin/pkexec")
    result = await auth2.start(owner2, command2["helper_sha256"])
    assert result["last_error"] == "OS_AUTH_LAUNCH_FAILED"
    assert not owner2.capture.listener_ready()
    assert "private" not in str(result)


def test_minimum_privilege_arguments_are_fixed():
    args = arguments(SimpleNamespace(uid=1000, gid=1000, python="/trusted/python"))
    assert "--clear-groups" in args
    assert "--inh-caps=-all,+net_raw" in args
    assert "-I" in args
    assert args[-1].endswith(".stream_helper")


@pytest.mark.asyncio
async def test_prepared_session_policy_tampering_cannot_launch(tmp_path):
    import json

    owner = StreamingMonitoring(tmp_path, paths=research_paths())
    command = await owner.start()
    path = owner.directory / "session.json"
    data = json.loads(path.read_text())
    data["policy"]["seconds"] = 1800
    path.write_text(json.dumps(data))
    calls = []
    auth = OSAuthentication(
        launcher=lambda *a, **k: calls.append(a),
        inspector=available,
        binary=lambda: "/usr/bin/pkexec",
    )
    try:
        assert owner.command(str(owner.session.session_id))["status"] == "BLOCKED"
        with pytest.raises(ValueError, match="CURRENT_LISTENER"):
            await auth.start(owner, command["helper_sha256"])
        assert not calls
    finally:
        await owner.stop(abort=True)
