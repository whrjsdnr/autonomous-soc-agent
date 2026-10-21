"""Diagnostic fixtures never invoke authentication, capset or Kernel operations."""

import errno
import json
import os
import socket
import struct
from types import SimpleNamespace

import pytest

from soc_agent.security_ai.ebpf_tc import supervisor_engine as engine
from soc_agent.security_ai.ebpf_tc.supervisor import SupervisedSession


class Channel:
    def __init__(self, body, uid=0):
        self.body, self.uid = body, uid

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass

    def settimeout(self, _):
        pass

    def getsockopt(self, *_):
        # Explicit synthetic credentials, not a Native authentication result.
        return struct.pack("3i", os.getpid(), self.uid, self.uid)

    def recvmsg(self, *_):
        return json.dumps(self.body).encode(), [], 0, None


class Listener:
    def __init__(self, channel):
        self.channel, self.closed = channel, False

    def accept(self):
        return self.channel, None

    def close(self):
        self.closed = True


def evidence():
    return dict(
        contract="SOC_ENTRY_DIAGNOSTIC_V1",
        stage="RESOURCE_INSPECTION_PROGRAMS",
        code="PERMISSIONERROR",
        errno=13,
        native_actions_started=False,
    )


@pytest.mark.parametrize("mutation", [None, "ordinary_peer", "secret_text", "authority_claim"])
def test_private_diagnostic_is_not_authorization(tmp_path, mutation):
    body = evidence()
    if mutation == "secret_text":
        body["code"] = "password=DO_NOT_STORE"
    if mutation == "authority_claim":
        body["native_actions_started"] = True
    listener = Listener(Channel(body, os.getuid() if mutation == "ordinary_peer" else 0))
    events = []
    owner = SimpleNamespace(
        entry_diagnostic_listener=listener,
        error="ENTRY_REJECTED",
        application=SimpleNamespace(directory=tmp_path),
        _event=lambda *a, **kw: events.append((a, kw)),
        authentication="REVOKED",
    )
    SupervisedSession._collect_entry_diagnostic(owner)
    assert listener.closed and owner.authentication == "REVOKED"
    assert owner.entry_diagnostic["authorization"] is False
    path = tmp_path / "entry-diagnostic.json"
    if mutation is None:
        assert owner.entry_diagnostic["errno"] == 13
        assert path.stat().st_mode & 0o777 == 0o600
        assert events
    else:
        assert not path.exists() and not events


def test_inspection_failure_preserves_original_exception_and_never_retries(monkeypatch):
    calls = []
    original = PermissionError(errno.EPERM, "sensitive text is not copied")

    def inspect(*_):
        calls.append("inspect")
        raise original

    monkeypatch.setattr(engine, "SUPERVISOR_CONFIG", {}, raising=False)
    monkeypatch.setattr(engine, "sup_inventory", inspect)
    monkeypatch.setattr(engine, "sup_entry_failure", lambda envelope, exc: calls.append(exc))
    with pytest.raises(PermissionError) as caught:
        engine.supervisor_prepare({}, bytes(352), bytes(32), {})
    assert caught.value is original and calls == ["inspect", original]


def test_sender_omits_exception_text_and_credentials(monkeypatch):
    sent = []

    class Sender:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            pass

        def settimeout(self, _):
            pass

        def connect(self, address):
            assert address.startswith("\0soc-entry-diagnostic.")

        def sendall(self, data):
            sent.append(json.loads(data))

    monkeypatch.setattr(socket, "socket", lambda *_: Sender())
    monkeypatch.setattr(engine, "SUP_ENTRY_STAGE", "RESOURCE_INSPECTION_PROGRAMS", raising=False)
    engine.sup_entry_failure(bytes(352), PermissionError(13, "SECRET"))
    assert sent[0]["errno"] == 13 and "SECRET" not in json.dumps(sent)
    assert set(sent[0]) == set(evidence())


def test_preexec_errno_is_reported_before_subprocess_generalizes_it(monkeypatch, tmp_path):
    calls = []
    original = PermissionError(1, "must not be persisted")
    path = tmp_path / "ordinary-file"
    path.write_bytes(b"not executed")
    monkeypatch.setattr(engine, "SUPERVISOR_REDUCED", False, raising=False)
    monkeypatch.setattr(engine, "SUP_ENTRY_ENVELOPE", bytes(352), raising=False)
    monkeypatch.setattr(engine, "sup_executable", lambda _: os.open(path, os.O_RDONLY))

    def cap_failure(*args, **kwargs):
        raise original

    monkeypatch.setattr(engine, "sup_caps", cap_failure)
    monkeypatch.setattr(engine, "sup_entry_failure", lambda envelope, exc: calls.append(exc))
    monkeypatch.setattr(engine.subprocess, "Popen", lambda *args, **kwargs: kwargs["preexec_fn"]())
    with pytest.raises(PermissionError) as caught:
        engine.sup_tool(["/fixed/tool"], engine.SUP_MASK)
    assert caught.value is original and calls == [original]
