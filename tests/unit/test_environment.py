import sys

import pydantic


def test_python_version() -> None:
    assert sys.version_info >= (3, 12)


def test_pydantic_is_available() -> None:
    assert pydantic.__version__
