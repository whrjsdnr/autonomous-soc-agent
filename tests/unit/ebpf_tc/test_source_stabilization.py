"""Offline release-assembly source races; no compiler/authentication/BPF syscalls."""

from pathlib import Path

import pytest

from soc_agent.security_ai.ebpf_tc import phase_d
from soc_agent.security_ai.ebpf_tc.source_guard import SourceGuard


@pytest.mark.parametrize("mutation", ["none", "changed", "restored"])
def test_prepare_observes_changes_after_compile_before_image_hashing(
    tmp_path, monkeypatch, mutation
):
    source = tmp_path / "inputs"
    source.mkdir()
    file = source / "module.py"
    file.write_text("original")
    roots = []

    def guard(root):
        roots.append(root)
        return SourceGuard(source)

    def after_compile(_, *, deployment_directory=None):
        assert deployment_directory is None
        # Simulate a change during packaging, outside the nested compile guard.
        if mutation != "none":
            file.write_text("changed")
        if mutation == "restored":
            file.write_text("original")
        return {"fixture": "PREPARED_ONLY"}

    monkeypatch.setattr(phase_d, "SourceGuard", guard)
    monkeypatch.setattr(phase_d, "_prepare", after_compile)
    if mutation == "none":
        assert phase_d.prepare(tmp_path / "output") == {"fixture": "PREPARED_ONLY"}
    else:
        with pytest.raises(ValueError, match="SOURCE_CHANGED_DURING_BUILD"):
            phase_d.prepare(tmp_path / "output")
    assert roots == [Path(phase_d.__file__).parents[2]]


def test_prepare_preserves_first_build_error_and_closes_source_observer(tmp_path, monkeypatch):
    guards = []

    def guard(_):
        item = SourceGuard(tmp_path)
        guards.append(item)
        return item

    def failed(_, *, deployment_directory=None):
        assert deployment_directory is None
        (tmp_path / "mutated.py").write_text("concurrent write")
        raise RuntimeError("FIRST_BUILD_ERROR")

    monkeypatch.setattr(phase_d, "SourceGuard", guard)
    monkeypatch.setattr(phase_d, "_prepare", failed)
    with pytest.raises(RuntimeError, match="FIRST_BUILD_ERROR"):
        phase_d.prepare(tmp_path / "output")
    assert guards[0].fd == -1
