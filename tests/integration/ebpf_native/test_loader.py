"""Actual libbpf read-only preparation; prohibited flags never invoke Kernel load."""

import subprocess

import pytest
from tests.ebpf_native_support import application

from soc_agent.security_ai.ebpf_native.loader import capability_preflight, inspect


def test_real_loader_sha_maps_and_prohibited_native_flags(tmp_path):
    c = application(tmp_path)
    result = inspect(c.program, c.scope.program_sha256, c.loader, c.scope.loader_sha256)
    assert result["programs"] == 2 and result["maps"] == 3
    assert result["kernel_load"] is False and result["tc_attach"] is False
    assert result["map_identity"] == "ELF_DECLARATIONS_NOT_KERNEL_IDS"
    for flag in ("--load", "--attach", "--detach", "--sudo", "--native"):
        p = subprocess.run([str(c.loader), flag], capture_output=True, text=True, timeout=5)
        assert p.returncode != 0 and "PHASE_A_NATIVE_EXECUTION_DISABLED" in p.stderr
    p = subprocess.run(
        [str(c.loader), "--inspect", str(c.program), "0" * 64], capture_output=True, timeout=5
    )
    assert p.returncode == 4
    caps = capability_preflight()
    from soc_agent._json import canonical_json_object

    assert canonical_json_object(caps)
    assert caps["privilege_granted"] is False and caps["native_execution"] == "PHASE_A_DISABLED"


def test_inspector_rejects_symlink_changed_image_and_malformed_elf(tmp_path):
    c = application(tmp_path)
    link = tmp_path / "alias"
    link.symlink_to(c.program)
    with pytest.raises(ValueError):
        inspect(link, c.scope.program_sha256, c.loader, c.scope.loader_sha256)
    with pytest.raises(ValueError):
        inspect(c.program, "b" * 64, c.loader, c.scope.loader_sha256)
    with pytest.raises(ValueError):
        inspect(c.program, c.scope.program_sha256, c.loader, "b" * 64)


def test_no_privileged_loader_api_in_source():
    from pathlib import Path

    root = Path(__file__).resolve().parents[3] / "src/soc_agent/security_ai/ebpf_native"
    source = (root / "loader.c").read_text()
    assert "bpf_object__open_mem" in source
    assert not any(
        word in source
        for word in (
            "bpf_object__load(",
            "bpf_tc_attach(",
            "bpf_tc_detach(",
            "bpf_tc_hook_destroy(",
            "bpf_map_update_elem(",
        )
    )


def test_supplied_untrusted_loader_is_rejected_before_execution(tmp_path):
    from soc_agent.security_ai.ebpf_native.loader import file_sha

    c = application(tmp_path / "real")
    untrusted = tmp_path / "phase-a-loader"
    marker = tmp_path / "must-not-exist"
    untrusted.write_text("#!/bin/sh\ntouch " + str(marker) + "\n" + "#not a reviewed loader\n" * 4)
    with pytest.raises(ValueError, match="REFERENCE_MISMATCH"):
        inspect(c.program, c.scope.program_sha256, untrusted, file_sha(untrusted))
    assert not marker.exists()
