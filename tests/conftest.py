"""Shared real-boundary composition for bounded investigation tests."""

from collections.abc import Callable

import pytest

from tests.bounded_support import Runtime, runtime


@pytest.fixture
def bounded_runtime() -> Callable[..., Runtime]:
    return runtime
