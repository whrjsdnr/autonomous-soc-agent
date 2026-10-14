"""Pinned path creation and bounded marker access do not require a runtime or OS response."""

import os
from pathlib import Path

import pytest

from soc_agent.linux_runtime.restricted_resource import AVAILABLE, TestResource
from soc_agent.review.persistence.secure_storage import create_private_directory


def test_creation_refuses_root_swapped_to_symlink(tmp_path, monkeypatch):
    runtime, outside = tmp_path / "runtime", tmp_path / "outside"
    create_private_directory(runtime)
    create_private_directory(outside)
    mkdir = os.mkdir

    def replaced(path, mode=0o777, *, dir_fd=None):
        mkdir(path, mode, dir_fd=dir_fd)
        if path == "test-resources":
            (runtime / "test-resources").rename(runtime / "original-test-resources")
            (runtime / "test-resources").symlink_to(outside, target_is_directory=True)

    monkeypatch.setattr(os, "mkdir", replaced)
    with pytest.raises(ValueError):
        TestResource(runtime).create()
    assert not list(outside.iterdir())
    assert not list((runtime / "original-test-resources").iterdir())


def test_creation_refuses_ancestor_symlink_inserted_during_open(tmp_path, monkeypatch):
    parent, outside = tmp_path / "parent", tmp_path / "outside"
    create_private_directory(parent)
    runtime = parent / "runtime"
    create_private_directory(runtime)
    create_private_directory(outside)
    create_private_directory(outside / "runtime")
    opened = os.open

    def swap(path, flags, *args, **kwargs):
        if path == "parent" and kwargs.get("dir_fd") is not None:
            parent.rename(tmp_path / "original-parent")
            parent.symlink_to(outside, target_is_directory=True)
        return opened(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", swap)
    with pytest.raises(OSError):
        TestResource(runtime).create()
    assert not (outside / "runtime/test-resources").exists()
    assert not (tmp_path / "original-parent/runtime/test-resources").exists()


def test_inspection_opens_marker_read_only(tmp_path, monkeypatch):
    runtime = tmp_path / "runtime"
    create_private_directory(runtime)
    resource = TestResource(runtime)
    registration = resource.create()
    opened, flags = os.open, []

    def observed(path, options, *args, **kwargs):
        if path == "marker":
            flags.append(options)
        return opened(path, options, *args, **kwargs)

    monkeypatch.setattr(os, "open", observed)
    resource.probe(registration)
    assert flags and all((options & os.O_ACCMODE) == os.O_RDONLY for options in flags)
    assert (runtime / "test-resources/marker").read_bytes() == AVAILABLE


@pytest.mark.parametrize("path", ["relative", "/tmp/../etc"])
def test_resource_creation_does_not_resolve_traversal_or_relative_paths(path):
    with pytest.raises(ValueError, match="PATH_REJECTED"):
        TestResource(Path(path)).create()
