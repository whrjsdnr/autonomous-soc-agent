"""Production transaction C core + fake API table; actual libbpf calls stay gated."""

import ctypes
import json
import subprocess

import pytest
from tests.unit.ebpf_tc.test_contracts import native_plan

from soc_agent.security_ai.ebpf_tc.build import compile_native
from soc_agent.security_ai.ebpf_tc.contracts import PLAN


@pytest.fixture(scope="module")
def compiled(tmp_path_factory):
    root = tmp_path_factory.mktemp("native-c")
    compile_native(root)
    return root


def scenario(compiled, number):
    p = subprocess.run(
        [str(compiled / "tc-fixture"), str(number)], capture_output=True, text=True, timeout=5
    )
    assert p.returncode == 0, p.stderr
    value = json.loads(p.stdout)
    assert value["source"] == "C_TRANSACTION_CORE_FAKE_OPS_ONLY" and not value["native_gate"]
    return value


def test_real_compiled_core_successful_attach_detach_preserves_foreign_filter(compiled):
    value = scenario(compiled, 0)
    assert value["prepare"] == value["attach"] == value["cleanup"] == 0
    assert value["loads"] == value["attaches"] == value["detaches"] == value["releases"] == 1
    assert value["foreign_program"] == 77 and value["remaining"] == 1
    assert value["trace"] == (
        "LOAD_REQUESTED;LOAD_VERIFIED;ATTACH_REQUESTED;ATTACH_VERIFIED;"
        "DETACH_REQUESTED;DETACH_VERIFIED;CLEANUP_VERIFIED;"
    )


@pytest.mark.parametrize("number", [1, 2, 3, 13, 14])
def test_invalid_scope_collision_object_or_qdisc_never_attaches(compiled, number):
    value = scenario(compiled, number)
    assert value["prepare"] != 0 and value["attaches"] == value["detaches"] == 0
    assert value["foreign_program"] == 77


@pytest.mark.parametrize("number", [5, 6, 7, 8, 10, 11, 12])
def test_unknown_ownership_and_partial_detach_never_claim_cleanup(compiled, number):
    value = scenario(compiled, number)
    assert value["cleanup"] != 0 and not value["cleanup_verified"]
    assert value["failed"]
    if number in (5, 6, 7, 11):
        assert value["detaches"] == 0 and value["remaining"] == 2
    if number != 12:
        assert value["foreign_program"] == 77


@pytest.mark.parametrize("number", [4, 9])
def test_partial_attach_stops_and_cleans_only_proven_own_filter(compiled, number):
    value = scenario(compiled, number)
    assert value["attach"] != 0 and value["failed"]
    assert value["cleanup"] == 0 and value["cleanup_verified"]
    assert value["foreign_program"] == 77


def test_native_entrypoints_gate_before_pam_or_privileged_syscall(compiled):
    for name in ("bootstrap", "broker"):
        p = subprocess.run([str(compiled / name), "--inspect"], capture_output=True, text=True)
        assert p.returncode == 0 and not json.loads(p.stdout)["native_gate"]
        for args in ([], ["3", "4", "5"], ["--native"], ["--enable"]):
            p = subprocess.run([str(compiled / name), *args], capture_output=True, text=True)
            assert p.returncode == 2 and p.stderr.strip() == "EBPF_B2A_NATIVE_EXECUTION_BLOCKED"
    lib = ctypes.CDLL(str(compiled / "libnative-tc.so"))
    assert lib.soc_native_gate() == 0
    assert lib.soc_reduce(1000, 1000) != 0  # Gate precedes setgroups/UID/capset calls.


def test_c_and_python_scope_validation_agree_and_reject_approval_mutation(compiled):
    lib = ctypes.CDLL(str(compiled / "libnative-tc.so"))
    lib.soc_plan_validate.argtypes = [ctypes.c_void_p]
    wire = native_plan().wire()
    assert len(wire) == PLAN.size == 272
    assert lib.soc_plan_validate(ctypes.create_string_buffer(wire)) == 0
    damaged = wire[:-1] + bytes([wire[-1] ^ 1])
    assert lib.soc_plan_validate(ctypes.create_string_buffer(damaged)) != 0


def test_actual_api_implementations_are_linked_but_no_mutating_qdisc_api(compiled):
    p = subprocess.run(
        ["nm", "-D", str(compiled / "libnative-tc.so")], capture_output=True, text=True, check=True
    )
    for symbol in (
        "bpf_object__load",
        "bpf_tc_attach",
        "bpf_tc_query",
        "bpf_tc_detach",
        "bpf_map_update_elem",
        "ring_buffer__new",
    ):
        assert symbol in p.stdout
    assert "bpf_tc_hook_destroy" not in p.stdout and "bpf_tc_hook_create" not in p.stdout


@pytest.mark.parametrize(
    "field,value",
    [
        (0, 0),
        (1, 0),
        (2, 0),
        (3, 1000),
        (4, 0),
        (5, 0),
        (6, 0),
        (7, 0),
        (8, 0),
        (8, 2),
        (9, 7),
        (10, 1),
    ],
)
def test_c_auth_contract_requires_new_terminal_password_not_sudo_cache(compiled, field, value):
    lib = ctypes.CDLL(str(compiled / "libnative-tc.so"))
    facts_type = ctypes.c_uint32 * 11
    valid = [1000, 1000, 1000, 0, 1000, 1, 1, 1, 1, 0, 0]
    assert lib.soc_auth_contract(facts_type(*valid)) == 0
    valid[field] = value
    assert lib.soc_auth_contract(facts_type(*valid)) != 0


def test_syscall_trace_proves_gate_denies_bpf_capability_and_network_entry(compiled, tmp_path):
    trace = tmp_path / "syscalls"
    p = subprocess.run(
        [
            "strace",
            "-f",
            "-e",
            "trace=bpf,socket,capset,setuid,setgid,setresuid,setresgid",
            "-o",
            str(trace),
            str(compiled / "broker"),
            "3",
            "4",
            "5",
            "6",
        ],
        capture_output=True,
        text=True,
    )
    assert p.returncode == 2
    body = trace.read_text()
    for forbidden in ("bpf(", "socket(", "capset(", "setuid(", "setgid(", "setresuid("):
        assert forbidden not in body
