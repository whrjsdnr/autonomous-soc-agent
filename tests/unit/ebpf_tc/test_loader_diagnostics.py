"""Real C fault-injection and journal/IPC tests; no Root, load, attach or PAM."""

import errno
import hashlib
import json
import subprocess
import time
from collections import deque
from pathlib import Path
from types import SimpleNamespace

import pytest

from soc_agent.security_ai.ebpf_broker.contracts import Command
from soc_agent.security_ai.ebpf_tc.build import ROOT, compile_native
from soc_agent.security_ai.ebpf_tc.journal import recover_native
from soc_agent.security_ai.ebpf_tc.loader_diagnostics import DETAIL, decode_diagnostic
from soc_agent.security_ai.ebpf_tc.os_handoff import REPLY, Handoff


@pytest.fixture(scope="module")
def fault_program(tmp_path_factory):
    path = tmp_path_factory.mktemp("loader-faults")
    compile_native(path)
    executable = path / "loader-fault-fixture"
    subprocess.run(
        [
            "cc",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-Wno-misleading-indentation",
            "-Wl,--export-dynamic",
            "-I" + str(ROOT),
            str(Path(__file__).with_name("loader_fault_fixture.c")),
            "-L" + str(path),
            "-lnative-tc",
            "-lbpf",
            "-ldl",
            "-Wl,-rpath," + str(path),
            "-o",
            str(executable),
        ],
        check=True,
        capture_output=True,
    )
    assert hashlib.sha256((path / "tcx.bpf.o").read_bytes()).hexdigest() == (
        "928a8afc1a75ce97acef5edaa6b5bb8823b681a0784bed7e067fc9f90cf50e4a"
    )
    return executable, path / "tcx.bpf.o"


@pytest.mark.parametrize(
    "scenario,stage,api,code,saved",
    [
        (1, "LOAD_PREPARE", "soc_release_check", -errno.EPERM, None),
        (2, "OBJECT_OPEN", "bpf_object__open_mem", -errno.ENOEXEC, errno.ENOEXEC),
        (3, "OBJECT_VERIFY", "bpf_program__set_autoload", -errno.EINVAL, errno.EINVAL),
        (4, "BPF_OBJECT_LOAD", "bpf_object__load", -errno.EACCES, errno.EACCES),
        (5, "MAP_INIT", "bpf_obj_get_info_by_fd(map)", -1, errno.EBADF),
        (6, "RING_BUFFER_INIT", "ring_buffer__new", -errno.ENOMEM, errno.ENOMEM),
        (7, "CLEANUP", "soc_snapshot_tcx", -errno.EAGAIN, None),
    ],
)
def test_first_failure_and_cleanup_are_separate(
    fault_program, tmp_path, scenario, stage, api, code, saved
):
    executable, object_file = fault_program
    journal = tmp_path / "journal"
    result = json.loads(
        subprocess.check_output(
            [str(executable), str(scenario), str(object_file), str(journal)], text=True, timeout=5
        )
    )
    recovered = recover_native(journal, "aa" * 32)
    detail = recovered["loader_diagnostics"][0]
    assert (detail["stage"], detail["api"], detail["return_value"], detail["saved_errno"]) == (
        stage,
        api,
        code,
        saved,
    )
    assert result["context_released"] and result["cleanup_return"] < 0
    assert not result["cleanup_verified"] and not recovered["claimed_cleanup"]
    assert result["load_api_calls"] == (1 if scenario >= 4 else 0)
    assert recovered["loader_diagnostics"][-1]["owned_object_released"] == (scenario != 1)
    if scenario == 4:
        assert (
            detail["kernel_log_sha256"]
            == hashlib.sha256(b"fixture-verifier-no-traffic").hexdigest()
        )
        assert not detail["raw_kernel_log_retained"]
        assert (
            detail["saved_errno"] != errno.EIO
        )  # Later cleanup errno cannot overwrite first failure.
    if scenario == 7:
        assert result["ring_freed"] == result["drain_calls"] == 1
    assert not recovered["automatic_attach"] and recovered["native_ai"] == "BLOCKED"


def test_decoder_rejects_unknown_stage_reserved_or_unbounded_log():
    body = DETAIL.pack(1, 4, 14, 2, -errno.EACCES, errno.EACCES, 16, 0, bytes(32), 0, 0, 0, 0)
    assert decode_diagnostic(body)["return_value"] == -errno.EACCES
    for index, value in ((1, 99), (7, 65537), (12, 1)):
        fields = list(DETAIL.unpack(body))
        fields[index] = value
        with pytest.raises(ValueError, match="SCHEMA"):
            decode_diagnostic(DETAIL.pack(*fields))


def test_broker_reply_error_survives_controller_rejection():
    handoff = object.__new__(Handoff)
    handoff.qualification_only, handoff.ended = False, False
    handoff.state, handoff.deadline = "BROKER_READY", time.monotonic() + 10
    handoff.plan = SimpleNamespace(approval="a" * 64, broker=SimpleNamespace(uid=1000, gid=1000))
    handoff.sequence, handoff.rate = 0, deque(maxlen=32)
    handoff._scope = lambda: None
    handoff.channel = SimpleNamespace(send=lambda body: len(body))
    handoff._next = lambda **kwargs: REPLY.pack(1, 3, -errno.EUCLEAN, 0, bytes(56))
    events = []
    handoff._event = lambda *args, **kwargs: events.append((args, kwargs))
    handoff._reject = lambda code: events.append(code)
    with pytest.raises(ValueError, match="HANDOFF_BROKER_REQUEST_DENIED:-117"):
        handoff.command(Command(command="STATUS", sequence=1, plan_digest="a" * 64))
    assert handoff.broker_error == dict(operation="STATUS", sequence=1, return_value=-errno.EUCLEAN)
