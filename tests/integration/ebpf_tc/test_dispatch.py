"""Compiled TCX program/dispatcher tests without kernel load, authentication or hooks."""

import hashlib
import json
import subprocess

import pytest

from soc_agent.security_ai.ebpf.build import compile_program
from soc_agent.security_ai.ebpf_tc.build import ROOT, compile_native, compile_tcx
from soc_agent.security_ai.ebpf_tc.journal import recover_native


@pytest.fixture(scope="module")
def built(tmp_path_factory):
    directory = tmp_path_factory.mktemp("tcx-dispatch")
    compile_native(directory)
    compile_tcx(directory)
    return directory


def run(built, scenario):
    return json.loads(
        subprocess.check_output(
            [str(built / "tcx-dispatch-fixture"), str(scenario)], text=True, timeout=5
        )
    )


def test_distinct_tcx_object_preserves_legacy_and_all_exits_continue(built):
    original = compile_program(built)
    assert (
        original["tc.bpf.o"] == "69de609ea8ee90ecf90d091ec361e46e61ed0638b3175390c77305145e19d5f4"
    )
    assert hashlib.sha256((built / "tcx.bpf.o").read_bytes()).hexdigest() != original["tc.bpf.o"]
    source = (ROOT / "tcx.bpf.c").read_text()
    assert "return TC_ACT_OK" not in source and "return TCX_NEXT" in source
    disassembly = subprocess.check_output(
        ["llvm-objdump-18", "-d", str(built / "tcx.bpf.o")], text=True
    )
    assert "tcx/ingress" in disassembly and "tcx/egress" in disassembly
    # Optimized common epilogue sets r0 to -1 immediately before every exit.
    lines = disassembly.splitlines()
    exits = [i for i, line in enumerate(lines) if line.rstrip().endswith("exit")]
    assert len(exits) == 2
    assert all(
        "r0 = -0x1" in lines[i - 1]
        or "r0 = -1" in lines[i - 1]
        or "r0 = 0xffffffff ll" in lines[i - 1]
        for i in exits
    )


def test_dispatcher_records_full_link_lifecycle_and_read_only_recovery(built, tmp_path):
    value = run(built, 0)
    assert value["attach"] == value["stop"] == value["cleanup"] == 0
    assert value["created"] == value["removed"] == value["foreign"] == 1
    assert value["active"] == 0 and value["phase"] == 4 and value["native"] is False
    journal = tmp_path / "journal"
    journal.write_bytes(bytes.fromhex(value["journal"]))
    result = recover_native(journal, value["approval"])
    assert result["records"] == 6 and result["claimed_cleanup"]
    assert result["last_owner_observed"] and result["process_exit"] == "UNKNOWN"
    assert not result["authentication_restored"] and not result["automatic_attach"]
    assert not result["automatic_inference"] and result["native_ai"] == "BLOCKED"
    journal.write_bytes(journal.read_bytes()[:-1])
    with pytest.raises(ValueError, match="PARTIAL"):
        recover_native(journal, value["approval"])


@pytest.mark.parametrize("scenario", range(1, 10))
def test_dispatcher_failures_never_touch_foreign_links_or_claim_cleanup(built, scenario, tmp_path):
    value = run(built, scenario)
    assert value["foreign"] == 1 and not value["native"]
    assert value["attach"] < 0 or value["stop"] < 0
    if scenario in (7, 8):
        assert value["created"] == 0  # Wrong approval or Legacy plan cannot enter TCX.
    if scenario in (4, 5, 6):
        assert value["cleanup"] < 0 and value["active"] == 1
    if value["journal"]:
        journal = tmp_path / "journal"
        journal.write_bytes(bytes.fromhex(value["journal"]))
        recovered = recover_native(journal, value["approval"])
        if value["cleanup"] < 0:
            assert not recovered["claimed_cleanup"]
        corrupted = bytearray(journal.read_bytes())
        corrupted[-1] ^= 1
        journal.write_bytes(corrupted)
        with pytest.raises(ValueError, match="INTEGRITY"):
            recover_native(journal, value["approval"])


def test_dispatcher_fixture_and_native_entries_cannot_load_kernel(built, tmp_path):
    for executable, arguments in (
        ("tcx-dispatch-fixture", ["0"]),
        ("broker", []),
        ("bootstrap", []),
    ):
        trace = tmp_path / executable
        result = subprocess.run(
            [
                "strace",
                "-f",
                "-e",
                "trace=bpf,capset",
                "-o",
                str(trace),
                str(built / executable),
                *arguments,
            ],
            capture_output=True,
            timeout=5,
        )
        assert result.returncode == (0 if arguments else 2)
        assert "bpf(" not in trace.read_text() and "capset(" not in trace.read_text()


def test_app_broker_auth_scope_audit_and_no_fixture_replay(tmp_path):
    from tests.ebpf_tc_support import preparation

    from soc_agent.security_ai.ebpf_native.authentication import FixtureAuthentication

    p = preparation(tmp_path)
    try:
        p.prepare()
        with pytest.raises(ValueError, match="AUTH_REQUIRED"):
            p.tcx_dispatch_fixture(p.tcx_dispatch_approval)
        p.approve(p.plan.approval)
        p.controller.authenticate(FixtureAuthentication())
        with pytest.raises(ValueError, match="APPROVAL"):
            p.tcx_dispatch_fixture(p.tcx_fixture_approval)
        value = p.tcx_dispatch_fixture(p.tcx_dispatch_approval)
        assert value["cleanup"] == 0 and p.snapshot()["tcx"]["ownership"] == "FIXTURE_ONLY"
        assert p.snapshot()["tcx"]["program_sha256"] == p.hashes["tcx.bpf.o"]
        with pytest.raises(ValueError, match="REPLAY"):
            p.tcx_dispatch_fixture(p.tcx_dispatch_approval)
        with p.controller.application.store.database.transaction(write=False) as db:
            rows = [json.loads(row[0]) for row in db.execute("SELECT payload FROM monitor_audit")]
        events = [row for row in rows if row["kind"] == "TCX_DISPATCHER_FIXTURE"]
        assert len(events) == 1 and not events[0]["details"]["native_execution"]
    finally:
        p.controller.close()
    recovered = p.controller.recover(p.controller.application.directory)
    assert not recovered["automatic_attach"] and not recovered["authentication_restored"]


def test_tcx_gate_blocks_dispatch_and_loader_even_if_global_gate_changes(built, tmp_path):
    # Test-only ELF symbol interposition. Production contains no admission override.
    source = tmp_path / "gate.c"
    source.write_text("""
#include "tcx.h"
#include <errno.h>
int soc_native_gate(void) {return 1;}
int soc_plan_validate(const struct soc_plan *p) {(void)p;return 0;}
int soc_peer(int fd,const struct soc_plan *p) {(void)fd;(void)p;return 0;}
int soc_sealed(int fd,const uint8_t *sha) {(void)fd;(void)sha;return 0;}
int main(void) {
    struct soc_state s={0};s.plan.version=SOC_TCX_VERSION;s.context=(void *)1;
    struct soc_tcx l={.session=&s,.ops=&soc_tcx_real_ops,.fd=-1};
    struct soc_request q={.operation=2};
    return soc_native_gate()==1 && !soc_tcx_native_admitted() && soc_tcx_dispatch(&l,&q)==-EPERM &&
        soc_program_fd(&s)==-EPERM?0:1;
}
""")
    executable = tmp_path / "gate-fixture"
    subprocess.run(
        [
            "cc",
            "-I" + str(ROOT),
            str(source),
            "-L" + str(built),
            "-lnative-tc",
            "-Wl,--export-dynamic",
            "-Wl,-rpath," + str(built),
            "-o",
            str(executable),
        ],
        check=True,
        timeout=30,
    )
    trace = tmp_path / "gate-trace"
    subprocess.run(
        ["strace", "-e", "trace=bpf,capset", "-o", str(trace), str(executable)],
        check=True,
        timeout=5,
    )
    assert "bpf(" not in trace.read_text() and "capset(" not in trace.read_text()
