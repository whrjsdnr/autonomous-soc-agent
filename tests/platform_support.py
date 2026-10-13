"""Actual filesystem capabilities; never substitute mocked symlinks or elevation."""

import os
from pathlib import Path

import pytest


def make_test_symlink(link: Path, target: Path, *, directory: bool = False) -> None:
    try:
        link.symlink_to(target, target_is_directory=directory)
    except OSError as error:
        if os.name == "nt" and getattr(error, "winerror", None) == 1314:
            pytest.skip("Native symlink creation unavailable (WinError 1314); no elevation or mock")
        raise
