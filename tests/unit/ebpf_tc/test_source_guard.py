"""Real ordinary-user file changes; never kernel BPF/capture/authentication."""

import os
import sys

import pytest

from soc_agent.security_ai.ebpf_tc.source_guard import SourceGuard, snapshot

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Linux build-input guard")


def test_stable_sources_hash_and_close_watch(tmp_path):
    (tmp_path / "broker.c").write_text("source")
    with SourceGuard(tmp_path) as guard:
        assert guard.check() == snapshot(tmp_path) == guard.start
        fd = guard.fd
    with pytest.raises(OSError):
        os.fstat(fd)


@pytest.mark.parametrize("mutation", ["restore", "replace", "add_delete", "new_directory"])
def test_transient_changes_are_not_hidden_by_equal_end_hash(tmp_path, mutation):
    source = tmp_path / "broker.c"
    source.write_text("source")
    with pytest.raises(ValueError, match="SOURCE_CHANGED_DURING_BUILD"):
        with SourceGuard(tmp_path):
            if mutation == "restore":
                source.write_text("changed")
                source.write_text("source")
            elif mutation == "replace":
                replacement = tmp_path / "replacement"
                replacement.write_text("source")
                replacement.replace(source)
            elif mutation == "add_delete":
                added = tmp_path / "temporary.c"
                added.write_text("temporary")
                added.unlink()
            else:
                (tmp_path / "new").mkdir()


def test_symlink_never_becomes_build_input(tmp_path):
    source = tmp_path / "real"
    source.write_text("source")
    (tmp_path / "alias").symlink_to(source)
    with pytest.raises(OSError):
        with SourceGuard(tmp_path):
            pytest.fail("symlink admitted")


def test_detected_write_permanently_invalidates_the_guard(tmp_path):
    source = tmp_path / "broker.c"
    source.write_text("source")
    with pytest.raises(ValueError, match="SOURCE_CHANGED_DURING_BUILD"):
        with SourceGuard(tmp_path) as guard:
            source.write_text("source")
            with pytest.raises(ValueError, match="SOURCE_CHANGED_DURING_BUILD"):
                guard.check()
            assert guard.events[0]["name"] == "broker.c"


def test_cache_writes_are_excluded_and_original_error_preserved(tmp_path):
    with pytest.raises(RuntimeError, match="FIRST_COMPILER_ERROR"):
        with SourceGuard(tmp_path) as guard:
            cache = tmp_path / "__pycache__"
            cache.mkdir()
            (cache / "temporary.pyc").write_bytes(b"cache")
            assert guard.check() == {}
            raise RuntimeError("FIRST_COMPILER_ERROR")
    assert guard.fd == -1
