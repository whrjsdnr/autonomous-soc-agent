"""Actual builds/inspection + reused B-1 process, authority, audit and recovery fixtures."""

import ctypes
import json
import os

import pytest
from tests.ebpf_tc_support import preparation

from soc_agent.security_ai.ebpf_native.authentication import FixtureAuthentication
from soc_agent.security_ai.ebpf_tc.bridge import NATIVE_ERROR, native_handoff


def test_bootstrap_preparation_reuses_b1_auth_and_new_plan_approval(tmp_path):
    p = preparation(tmp_path)
    try:
        value = p.prepare()
        assert value["ebpf"]["native_gate"] == "B2A_CLOSED"
        assert value["ebpf"]["native_hook"] == "NOT_ATTACHED" and not value["collection_live"]
        assert p.controller.broker is None
        with pytest.raises(ValueError, match="APPROVAL_DIGEST"):
            p.approve(p.controller.plan.identity)
        p.approve(p.plan.approval)
        p.controller.authenticate(FixtureAuthentication())
        assert p.transaction_fixture()["cleanup_verified"]
        p.controller.start()
        first = p.controller.run
        p.controller.stop()
        p.controller.start()
        assert first.capture_session != p.controller.run.capture_session
        p.controller.stop()
        with p.controller.application.store.database.transaction(write=False) as db:
            rows = [json.loads(r[0]) for r in db.execute("SELECT payload FROM monitor_audit")]
        assert sum(r["kind"] == "AUTHENTICATION_VERIFIED" for r in rows) == 1
        assert all(not r["details"].get("native_authentication", False) for r in rows)
        assert not any(r["kind"] == "LOAD_VERIFIED" for r in rows)
    finally:
        p.controller.close()
    recovered = p.controller.recover(p.controller.application.directory)
    assert not recovered["automatic_attach"] and not recovered["authentication_restored"]
    assert recovered["native_ai"] == recovered["dns9"] == "BLOCKED"


@pytest.mark.parametrize(
    "change",
    [
        {"tty": False},
        {"cached_only": True},
        {"nopasswd": True},
        {"result": "CANCELLED"},
        {"result": "TIMEOUT"},
    ],
)
def test_auth_failures_never_start_broker_or_load(tmp_path, change):
    p = preparation(tmp_path)
    try:
        p.prepare()
        p.approve(p.plan.approval)
        with pytest.raises(ValueError):
            p.controller.authenticate(FixtureAuthentication.model_validate(change))
        assert p.controller.broker is None and not p.controller.application._authenticated
    finally:
        p.controller.close()


@pytest.mark.parametrize("name", ["bootstrap", "broker", "libnative-tc.so"])
def test_changed_executable_never_uses_approval_or_authentication(tmp_path, name):
    p = preparation(tmp_path)
    try:
        p.prepare()
        path = p.artifacts / name
        path.write_bytes(path.read_bytes() + b"tampered")
        with pytest.raises(ValueError, match="REFERENCE_MISMATCH"):
            p.approve(p.plan.approval)
        assert p.controller.broker is None
    finally:
        p.controller.close()


def test_native_handoff_cannot_invoke_privilege_even_with_valid_approval(tmp_path, monkeypatch):
    p = preparation(tmp_path)
    try:
        p.prepare()

        def forbidden(*args, **kwargs):
            raise AssertionError("Native process cannot be launched in B-2A")

        monkeypatch.setattr("subprocess.Popen", forbidden)
        with pytest.raises(ValueError, match=NATIVE_ERROR):
            native_handoff(p.plan, 3, 4)
        assert p.controller.broker is None
    finally:
        p.controller.close()


def test_actual_sealed_fd_and_environment_validation_remain_read_only(tmp_path):
    p = preparation(tmp_path)
    try:
        lib = ctypes.CDLL(str(p.artifacts / "libnative-tc.so"))
        lib.soc_sealed.argtypes = [ctypes.c_int, ctypes.c_void_p]
        from soc_agent.security_ai.ebpf_broker.identity import sealed_object

        fd = sealed_object(p.controller.application.program, p.plan.program_sha256)
        expected = ctypes.create_string_buffer(bytes.fromhex(p.plan.program_sha256))
        try:
            assert lib.soc_sealed(fd, expected) == 0
            with pytest.raises(OSError):
                os.pwrite(fd, b"x", 0)
        finally:
            os.close(fd)
        wire = ctypes.create_string_buffer(p.plan.wire())
        lib.soc_environment.argtypes = [ctypes.c_void_p]
        assert lib.soc_environment(wire) == 0
        damaged = bytearray(p.plan.wire())
        damaged[16] ^= 1  # Controller start ticks; no process/namespace changes performed.
        assert lib.soc_environment(ctypes.create_string_buffer(bytes(damaged))) != 0
    finally:
        p.controller.close()
