"""A real closed ordinary-UID socket preserves errno; never loads a BPF program."""

import errno
import subprocess
from pathlib import Path

import pytest

from soc_agent.security_ai.ebpf_tc.build import ROOT
from soc_agent.security_ai.ebpf_tc.journal import recover_native


@pytest.fixture
def sender(tmp_path):
    executable = tmp_path / "sender"
    subprocess.run(
        [
            "cc",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-Wno-misleading-indentation",
            "-I" + str(ROOT),
            str(Path(__file__).with_name("data_send_fixture.c")),
            str(ROOT / "data.c"),
            "-lcrypto",
            "-Wl,--wrap=send",
            "-o",
            str(executable),
        ],
        check=True,
        capture_output=True,
    )
    return executable


def test_send_failure_retains_raw_result_and_epipe(tmp_path, sender):
    journal = tmp_path / "journal"
    result = subprocess.check_output([str(sender), str(journal)], text=True)
    assert int(result) == -errno.EPIPE
    d = recover_native(journal, "aa" * 32)["loader_diagnostics"][0]
    assert (d["stage"], d["api"]) == ("DATA_PLANE", "send_data")
    assert d["return_value"] == -1 and d["saved_errno"] == errno.EPIPE


@pytest.mark.parametrize(
    "mode,expected", [("slow", 0), ("blocked", -errno.EAGAIN), ("partial", -errno.EIO)]
)
def test_bounded_backpressure_and_terminal_evidence(tmp_path, sender, mode, expected):
    journal = tmp_path / "journal"
    result = subprocess.check_output([str(sender), str(journal), mode], text=True, timeout=2)
    assert int(result) == expected
    evidence = recover_native(journal, "aa" * 32)
    rows = evidence["data_send_status"]
    assert evidence["data_counter_status"][0]["source"] == "FIXTURE_COUNTER_NEVER_NATIVE"
    assert rows[-1]["status"] == "FINAL"
    assert rows[-1]["readiness_waits"] <= 40
    if mode == "slow":
        assert rows[0]["status"] == "BACKPRESSURE_OBSERVED"
        assert rows[-1]["resumed_sends"] == 1
        assert rows[-1]["last_delivered_sequence"] == 3  # packet, counter, CLOSED
        assert rows[-1]["packets_sent"] == 1 and rows[-1]["result"] == 0
        assert not evidence["loader_diagnostics"]
    else:
        failure = next(r for r in rows if r["status"] == "FAILED")
        assert failure["message"] == "PACKET" and failure["sequence"] == 1
        assert failure["result"] == (-1 if mode == "blocked" else 17)
        assert failure["saved_errno"] == (errno.EAGAIN if mode == "blocked" else 0)
        assert failure["resumed_sends"] == 0  # never send a partial suffix
