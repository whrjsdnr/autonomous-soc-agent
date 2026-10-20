"""Compile/link API and execute fake link resource table, never BPF syscalls."""

import ctypes
import json
import subprocess

import pytest

from soc_agent.security_ai.ebpf_tc.build import ROOT, compile_native
from soc_agent.security_ai.ebpf_tc.tcx import LinkFixtureResult


@pytest.fixture(scope="module")
def compiled(tmp_path_factory):
    path = tmp_path_factory.mktemp("tcx")
    compile_native(path)
    return path


def scenario(path, number):
    result = subprocess.run(
        [str(path / "tc-fixture"), "--tcx", str(number)],
        capture_output=True,
        text=True,
        timeout=5,
        check=True,
    )
    return LinkFixtureResult.model_validate_json(result.stdout)


def test_installed_tcx_header_and_linker_symbols_are_available_not_kernel_support(compiled):
    probe = compiled / "api-probe"
    subprocess.run(
        ["cc", "-O0", "-Wall", "-Werror", str(ROOT / "tcx_probe.c"), "-lbpf", "-o", str(probe)],
        check=True,
    )
    symbols = subprocess.check_output(["nm", "-D", str(probe)], text=True)
    for symbol in (
        "bpf_program__attach_tcx",
        "bpf_link_create",
        "bpf_link_update",
        "bpf_link_detach",
        "bpf_link_get_info_by_fd",
        "bpf_link__pin",
        "bpf_link__unpin",
        "bpf_link__destroy",
    ):
        assert symbol in symbols
    value = json.loads(subprocess.check_output([str(probe)], text=True))
    assert value["kernel_support"] == "UNKNOWN"
    assert value["tc_act_ok"] == value["tcx_pass"] == 0 and value["tcx_next"] == -1


def test_link_lifecycle_detaches_only_held_object(compiled):
    r = scenario(compiled, 0)
    assert r.attach == r.detach == 0 and r.phase == 4
    assert r.link_id == 501 and r.deletes == r.closed == 1
    assert r.active == r.references == 0 and r.foreign == 1
    assert r.replay < 0 and r.snapshot()["ownership"] == "FIXTURE_ONLY"


@pytest.mark.parametrize("number", [1, 2, 3, 4, 5, 7, 8, 9, 10, 14, 15, 16, 17, 18, 20])
def test_partial_attach_identity_pin_namespace_interface_and_cleanup_failures(compiled, number):
    r = scenario(compiled, number)
    assert r.detach != 0 and r.phase == 6
    assert r.foreign == 1
    if number in (1, 2, 3, 4, 5, 10, 14, 15, 16, 17, 18, 20):
        assert r.deletes == r.closed == 0
    assert r.snapshot()["cleanup"] == "UNVERIFIED"


def test_positional_replacement_after_query_does_not_change_link_target(compiled):
    r = scenario(compiled, 6)
    assert r.detach == 0 and r.phase == 4 and r.foreign == 2
    assert r.deletes == r.closed == 1


def test_explicit_link_detach_stops_observation_despite_duplicated_reference(compiled):
    r = scenario(compiled, 11)
    assert r.detach == 0 and r.active == 0 and r.references == 1
    assert r.phase == 4  # Object remains referenced but no longer attached.


@pytest.mark.parametrize("number,active", [(12, 0), (13, 1)])
def test_crash_close_is_not_cleanup_attestation_and_other_reference_can_keep_link(
    compiled, number, active
):
    r = scenario(compiled, number)
    assert r.active == active and r.deletes == 0
    assert r.phase == (5 if number == 13 else 6)
    assert r.detach != 0  # No fake CLOSED/audit after SIGKILL.


def test_real_provider_and_migration_gate_cannot_invoke_bpf(compiled, tmp_path):
    lib = ctypes.CDLL(str(compiled / "libnative-tc.so"))
    assert lib.soc_native_gate() == lib.soc_tcx_native_admitted() == 0
    trace = tmp_path / "trace"
    p = subprocess.run(
        [
            "strace",
            "-f",
            "-e",
            "trace=bpf,socket,capset",
            "-o",
            str(trace),
            str(compiled / "tc-fixture"),
            "--tcx",
            "6",
        ],
        capture_output=True,
    )
    assert p.returncode == 0
    assert all(token not in trace.read_text() for token in ("bpf(", "socket(", "capset("))
    symbols = subprocess.check_output(["nm", "-D", str(compiled / "libnative-tc.so")], text=True)
    for symbol in ("bpf_link_create", "bpf_link_get_info_by_fd", "bpf_link_detach"):
        assert symbol in symbols
    for forbidden in ("bpf_link_get_fd_by_id", "bpf_link_update", "bpf_obj_pin", "bpf_link__pin"):
        assert forbidden not in symbols


def test_external_pin_cannot_extend_observation_after_explicit_owned_detach(compiled):
    r = scenario(compiled, 19)
    assert r.references == 1 and r.active == 0 and r.phase == 4
    assert r.snapshot()["external_pins"] == "UNKNOWN"
