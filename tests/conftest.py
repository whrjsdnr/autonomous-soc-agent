"""Shared real-boundary composition for bounded investigation tests."""

import os
from collections.abc import Callable

import pytest

from soc_agent.review.persistence.secure_storage import create_private_directory
from tests.bounded_support import Runtime, runtime


@pytest.fixture
def tmp_path(tmp_path):
    """Windows test storage is newly created private NTFS, never a repaired temp ACL."""
    if os.name != "nt":
        return tmp_path
    directory = tmp_path / "SOC private tests"
    create_private_directory(directory, exist_ok=False)
    return directory


@pytest.fixture
def bounded_runtime() -> Callable[..., Runtime]:
    return runtime
