"""Actual host lock behavior; on Windows these are native LockFileEx tests, not mocks."""

import os
import subprocess
import sys
import threading
from pathlib import Path
from queue import Queue

import pytest

from soc_agent.review.persistence.secure_storage import (
    StorageSecurityError,
    create_private_directory,
)
from soc_agent.runtime_lock import _backend, exclusive_runtime_lock

ROOT = Path(__file__).parents[2]
CHILD = """
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from soc_agent.runtime_lock import exclusive_runtime_lock
from soc_agent.review.persistence.secure_storage import StorageSecurityError
try:
    with exclusive_runtime_lock(Path(sys.argv[2])):
        print("HELD", flush=True)
        if len(sys.argv) > 3:
            sys.stdin.read(1)
except (OSError, StorageSecurityError):
    print("BLOCKED", flush=True)
    sys.exit(2)
"""


@pytest.fixture
def lock_path(tmp_path):
    directory = tmp_path / "runtime lock 한글 space"
    create_private_directory(directory)
    return directory / "runtime.lock"


def child_command(path, *, hold=False):
    command = [sys.executable, "-c", CHILD, str(ROOT / "src"), str(path)]
    if hold:
        command.append("hold")
    return command


def test_same_process_exclusion_reacquire_without_removing_lock_file(lock_path):
    with exclusive_runtime_lock(lock_path):
        with pytest.raises((OSError, StorageSecurityError)):
            with exclusive_runtime_lock(lock_path):
                pytest.fail("Concurrent writer must not enter")
    assert lock_path.exists()
    before = lock_path.stat().st_ino
    with exclusive_runtime_lock(lock_path):
        assert lock_path.stat().st_ino == before


@pytest.mark.parametrize("failure", (RuntimeError, KeyboardInterrupt))
def test_exception_and_interrupt_release_lock(lock_path, failure):
    with pytest.raises(failure):
        with exclusive_runtime_lock(lock_path):
            raise failure("Controlled test interruption")
    with exclusive_runtime_lock(lock_path):
        pass


def test_cross_process_nonblocking_exclusion_then_reacquire(lock_path):
    with exclusive_runtime_lock(lock_path):
        blocked = subprocess.run(child_command(lock_path), capture_output=True, timeout=20)
        assert blocked.returncode == 2 and blocked.stdout.splitlines() == [b"BLOCKED"]
    acquired = subprocess.run(child_command(lock_path), capture_output=True, timeout=20)
    assert acquired.returncode == 0 and acquired.stdout.splitlines() == [b"HELD"]


def test_process_exit_releases_kernel_lock(lock_path):
    child = subprocess.Popen(
        child_command(lock_path, hold=True),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    ready = Queue()
    thread = threading.Thread(target=lambda: ready.put(child.stdout.readline()), daemon=True)
    thread.start()
    try:
        assert ready.get(timeout=20).strip() == b"HELD", (
            "Child lock unavailable; raw diagnostics withheld"
        )
        with pytest.raises((OSError, StorageSecurityError)):
            with exclusive_runtime_lock(lock_path):
                pytest.fail("Second writer must be rejected")
        child.terminate()  # Only the controlled test child, no privilege/elevation.
        child.wait(timeout=20)
        with exclusive_runtime_lock(lock_path):
            pass
    finally:
        if child.poll() is None:
            child.kill()
        child.communicate(timeout=20)
        thread.join(timeout=1)


def test_unsupported_platform_has_no_fallback():
    with pytest.raises(OSError, match="unsupported"):
        _backend("unsupported")


def test_live_import_does_not_import_fcntl():
    script = """
import builtins, sys
sys.path.insert(0, sys.argv[1])
original = builtins.__import__
def checked(name, *args, **kwargs):
    if name == "fcntl":
        raise ImportError("fcntl unavailable")
    return original(name, *args, **kwargs)
builtins.__import__ = checked
import soc_agent.live
print("IMPORTED")
"""
    result = subprocess.run(
        [sys.executable, "-c", script, str(ROOT / "src")], capture_output=True, timeout=30
    )
    assert result.returncode == 0 and result.stdout.splitlines() == [b"IMPORTED"]


def test_lock_module_has_no_eager_platform_imports():
    assert _backend(os.name) is not None


@pytest.mark.parametrize("failure", ("none", "acquire", "body", "release", "verify"))
def test_mocked_windows_lock_contract_closes_handles_and_never_bypasses(monkeypatch, failure):
    import ctypes
    from contextlib import contextmanager
    from unittest.mock import Mock

    from soc_agent import runtime_lock
    from soc_agent.review.persistence import windows_storage
    from soc_agent.review.persistence.secure_storage import FileIdentity

    api = Mock()
    api.user = "contract-user"
    api.kernel.CreateFileW.return_value = 123
    api.kernel.LockFileEx.return_value = failure != "acquire"
    api.kernel.UnlockFileEx.return_value = failure != "release"
    api.snapshot.return_value = windows_storage.Snapshot(
        FileIdentity(1, 1),
        False,
        False,
        "NTFS",
        True,
        "untrusted-owner" if failure == "verify" else api.user,
        True,
        (windows_storage.ACE(api.user, windows_storage.FULL_ACCESS, 0),),
    )

    def check(ok):
        if not ok:
            raise StorageSecurityError("Mocked native failure")

    api._check = check

    @contextmanager
    def descriptor(*, directory):
        assert directory is False
        yield windows_storage.SecurityAttributes(
            ctypes.sizeof(windows_storage.SecurityAttributes), 456, False
        )

    api.descriptor = descriptor
    monkeypatch.setattr(windows_storage, "NativeWin32", lambda: api)

    def exercise():
        with runtime_lock._windows_lock(Path("contract-file")):
            if failure == "body":
                raise RuntimeError("Controlled interruption")

    if failure == "none":
        exercise()
    else:
        with pytest.raises(RuntimeError if failure == "body" else StorageSecurityError):
            exercise()
    api.kernel.CloseHandle.assert_called_once_with(123)
    create = api.kernel.CreateFileW.call_args.args
    assert create[2] == 3 and create[4] == 4 and create[5] & 0x00200000
    if failure != "verify":
        args = api.kernel.LockFileEx.call_args.args
        assert args[1:5] == (3, 0, 1, 0)
        overlap = ctypes.cast(args[5], ctypes.POINTER(runtime_lock.Overlapped)).contents
        assert (overlap.offset, overlap.offset_high, overlap.event) == (0, 0, None)
    assert api.kernel.UnlockFileEx.call_count == (0 if failure in {"acquire", "verify"} else 1)
