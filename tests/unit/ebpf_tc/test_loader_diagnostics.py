"""Real C fault-injection and journal/IPC tests; no Root, load, attach or PAM."""

import errno
import hashlib
import json
import subprocess
import threading
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
        "9a4d26cfc3b09ac4635972f8559006d735aa3bc3da0cb09028b3ce53ae5fde06"
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
        assert detail["raw_kernel_log_retained"]
        assert recovered["verifier_log"] == {
            "complete": True,
            "bytes_observed": len(b"fixture-verifier-no-traffic"),
            "text": "fixture-verifier-no-traffic",
        }
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
    handoff.control_lock, handoff.control_failures = threading.RLock(), []
    handoff.qualification_only, handoff.ended = False, False
    handoff.state, handoff.deadline = "BROKER_READY", time.monotonic() + 10
    handoff.data = SimpleNamespace(error=None)  # __new__ fixture retains real command preflight.
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


@pytest.mark.parametrize("mutation", ["offset", "padding", "digest", "truncated"])
def test_verifier_log_recovery_checks_content_and_partial_evidence(
    fault_program, tmp_path, mutation
):
    executable, object_file = fault_program
    journal = tmp_path / "journal"
    subprocess.run(
        [str(executable), "4", str(object_file), str(journal)],
        check=True,
        capture_output=True,
        timeout=5,
    )
    # Recompute the ordinary journal chain to exercise the content contract,
    # rather than merely its outer checksum. No privileged API is called.
    import struct

    rows = []
    body = journal.read_bytes()
    while body:
        kind = body[32:64].split(b"\0", 1)[0].decode()
        size = (
            216
            if kind in {"LOADER_DIAGNOSTIC", "LOADER_VERIFIER_LOG", "FD_RELEASE_EVIDENCE"}
            else 192
        )
        row, body = bytearray(body[:size]), body[size:]
        if kind == "LOADER_VERIFIER_LOG":
            if mutation == "truncated":
                break
            if mutation == "offset":
                struct.pack_into("<I", row, 64, 1)
            elif mutation == "padding":
                row[143] = 1
            else:
                row[72] ^= 1
        rows.append(row)
    before = bytes(32)
    for row in rows:
        row[-64:-32] = before
        row[-32:] = hashlib.sha256(row[:-32]).digest()
        before = bytes(row[-32:])
    journal.write_bytes(b"".join(rows))
    if mutation == "truncated":
        evidence = recover_native(journal, "aa" * 32)
        assert not evidence["verifier_log"]["complete"]
        assert evidence["verifier_log"]["text"] is None
        assert not evidence["claimed_cleanup"]
    else:
        with pytest.raises(ValueError, match="NATIVE_VERIFIER_LOG"):
            recover_native(journal, "aa" * 32)


@pytest.mark.parametrize("scenario,length", [(8, 24355), (9, 65535)])
def test_verifier_log_chunks_cover_native_size_and_buffer_bound(
    fault_program, tmp_path, scenario, length
):
    executable, object_file = fault_program
    journal = tmp_path / "journal"
    subprocess.run(
        [str(executable), str(scenario), str(object_file), str(journal)],
        check=True,
        capture_output=True,
        timeout=10,
    )
    evidence = recover_native(journal, "aa" * 32)
    assert evidence["verifier_log"] == {
        "complete": True,
        "bytes_observed": length,
        "text": "V" * length,
    }
    assert evidence["records"] < 1024
    assert evidence["loader_diagnostics"][0]["kernel_log_at_bound"] == (length == 65535)
    assert evidence["loader_diagnostics"][-1]["owned_object_released"]
    assert not evidence["claimed_cleanup"]


@pytest.mark.parametrize("scenario,closed", [(10, True), (11, False)])
def test_owned_fd_release_check_detects_partial_close_after_drain_failure(
    fault_program, tmp_path, scenario, closed
):
    executable, object_file = fault_program
    journal = tmp_path / "journal"
    # Kernel BPF APIs are replaced by the existing fixture. These owned FDs
    # are real ordinary /dev/null descriptors, not BPF maps or programs.
    result = json.loads(
        subprocess.check_output(
            [str(executable), str(scenario), str(object_file), str(journal)],
            text=True,
        )
    )
    evidence = recover_native(journal, "aa" * 32)
    release = evidence["fd_release_evidence"][0]
    assert release["map_fds_checked"] == 3 and release["program_fds_checked"] == 1
    assert release["all_observed_fds_closed"] is closed
    assert result["context_released"] and result["drain_calls"] == 1
    assert result["cleanup_return"] < 0 and not evidence["claimed_cleanup"]


@pytest.mark.parametrize("scenario,lookup,totals", [(12, 0, True), (13, -1, False)])
def test_owned_counter_query_runs_after_drain_failure(
    fault_program, tmp_path, scenario, lookup, totals
):
    executable, object_file = fault_program
    journal = tmp_path / "journal"
    result = json.loads(
        subprocess.check_output(
            [str(executable), str(scenario), str(object_file), str(journal)],
            text=True,
            timeout=5,
        )
    )
    evidence = recover_native(journal, "aa" * 32)
    query = evidence["data_counter_queries"][0]
    assert query["drain_result"] == -errno.EAGAIN
    assert query["lookup_attempted"] and query["lookup_result"] == lookup
    assert query["saved_errno"] == (None if totals else errno.EPERM)
    assert query["transmit_result"] == -errno.EPERM  # No data socket in this fixture.
    assert bool(evidence["data_counter_status"][0]["totals"]) == totals
    assert result["context_released"] and result["ring_freed"] == 1
    assert evidence["fd_release_evidence"][0]["result"] == 0


@pytest.mark.parametrize("generation", [1, 2**63 - 1, 2**63, 12918548832694615738, 2**64 - 1])
def test_c_counter_query_preserves_uint64_and_signed_errors(fault_program, tmp_path, generation):
    executable, object_file = fault_program
    journal = tmp_path / "journal"
    subprocess.run(
        [str(executable), "12", str(object_file), str(journal), str(generation)],
        check=True,
        capture_output=True,
        timeout=5,
    )
    original = journal.read_bytes()
    evidence = recover_native(journal, "aa" * 32)
    query = evidence["data_counter_queries"][0]
    assert query["generation"] == generation
    assert query["drain_result"] == -errno.EAGAIN
    assert query["transmit_result"] == -errno.EPERM
    assert evidence["data_counter_status"][0]["generation"] == generation
    assert evidence["fd_release_evidence"][0]["all_observed_fds_closed"]
    assert journal.read_bytes() == original
    assert not evidence["claimed_cleanup"]  # Real fixture drain failed; no promotion.
