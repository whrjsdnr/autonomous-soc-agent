"""A real closed ordinary-UID socket preserves errno; never loads a BPF program."""

import errno
import subprocess
from pathlib import Path

from soc_agent.security_ai.ebpf_tc.build import ROOT
from soc_agent.security_ai.ebpf_tc.journal import recover_native


def test_send_failure_retains_raw_result_and_epipe(tmp_path):
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
            "-o",
            str(executable),
        ],
        check=True,
        capture_output=True,
    )
    journal = tmp_path / "journal"
    result = subprocess.check_output([str(executable), str(journal)], text=True)
    assert int(result) == -errno.EPIPE
    d = recover_native(journal, "aa" * 32)["loader_diagnostics"][0]
    assert (d["stage"], d["api"]) == ("DATA_PLANE", "send_data")
    assert d["return_value"] == -1 and d["saved_errno"] == errno.EPIPE
