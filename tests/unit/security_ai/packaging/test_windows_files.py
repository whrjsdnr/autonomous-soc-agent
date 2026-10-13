"""Mocked Windows package-read contract; native Desktop smoke is the OS evidence."""

import ctypes
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import Mock

import pytest

from soc_agent.review.persistence.secure_storage import StorageSecurityError
from soc_agent.security_ai.packaging import windows_files as reader


class ContractAPI:
    def __init__(self):
        self.kernel = Mock()
        self.events = []
        self.files = {}
        self.offsets = {}
        self.calls = {}
        self.defect = None
        self.kernel.CreateFileW.side_effect = self.open_file
        self.kernel.GetFileInformationByHandle.side_effect = self.information
        self.kernel.GetFileType.return_value = 1
        self.kernel.ReadFile.side_effect = self.read

    @contextmanager
    def hold(self, path, *, share_delete=False):
        assert not share_delete
        self.events.append(("open_directory", path))
        try:
            yield path
        finally:
            self.events.append(("close_directory", path))

    def open_file(self, path, access, sharing, security, disposition, flags, template):
        assert access == 0x80000080 and sharing == 1 and disposition == 3
        assert flags & 0x00200000  # OPEN_REPARSE_POINT
        handle = len(self.files) + 1
        self.files[handle] = path
        self.offsets[handle] = 0
        return handle

    def information(self, handle, pointer):
        info = ctypes.cast(pointer, ctypes.POINTER(reader.FileInformation)).contents
        directory = isinstance(handle, str)
        info.attributes = reader.DIRECTORY if directory else 0
        info.volume, info.index_low, info.size_low = 1, 1, 8 if not directory else 0
        self.calls[handle] = self.calls.get(handle, 0) + 1
        if self.defect == "ancestor_reparse" and handle == "C:\\":
            info.attributes |= reader.REPARSE
        if self.defect == "file_reparse" and not directory:
            info.attributes |= reader.REPARSE
        if self.defect == "oversized" and not directory:
            info.size_low = reader.MAX_FILE_BYTES + 1
        if self.defect == "replaced" and not directory and self.calls[handle] > 1:
            info.index_low = 2
        return True

    def read(self, handle, buffer, length, count, overlapped):
        if self.defect == "read_error":
            return False
        value = b"contract"[self.offsets[handle] : self.offsets[handle] + length]
        ctypes.memmove(buffer, value, len(value))
        ctypes.cast(count, ctypes.POINTER(reader.DWORD)).contents.value = len(value)
        self.offsets[handle] += len(value)
        return True

    def _check(self, ok):
        if not ok:
            raise StorageSecurityError("Mocked Windows API failure")


@pytest.fixture
def api(monkeypatch):
    api = ContractAPI()
    monkeypatch.setattr(reader, "NativeWin32", lambda: api)
    monkeypatch.setattr(reader.os.path, "abspath", lambda _: r"C:\packages\release")

    def listing(path):
        if path.endswith("\\model"):
            return ["model.json"]
        if path.endswith("\\preprocessing"):
            return ["profile.json"]
        return ["manifest.json", "metadata.json", "model", "preprocessing"]

    monkeypatch.setattr(reader.os, "listdir", listing)
    return api


def assert_closed(api):
    opened = [path for event, path in api.events if event == "open_directory"]
    closed = [path for event, path in api.events if event == "close_directory"]
    assert closed == list(reversed(opened))
    assert api.kernel.CloseHandle.call_count == len(api.files)


def test_read_only_handles_inventory_bounded_bytes_and_cleanup(api):
    assert reader.read_windows_package(Path("relative package")) == {
        name: b"contract" for name in reader.FILES
    }
    assert_closed(api)


@pytest.mark.parametrize(
    "defect", ("ancestor_reparse", "file_reparse", "oversized", "replaced", "read_error")
)
def test_package_reader_fail_closed_and_closes_all_handles(api, defect):
    api.defect = defect
    with pytest.raises((ValueError, StorageSecurityError)):
        reader.read_windows_package(Path("package"))
    assert_closed(api)


def test_total_package_budget_fail_closed(api, monkeypatch):
    monkeypatch.setattr(reader, "MAX_PACKAGE_BYTES", 4)
    with pytest.raises(ValueError, match="total size budget"):
        reader.read_windows_package(Path("package"))
    assert_closed(api)


def test_unknown_inventory_rejected(api, monkeypatch):
    monkeypatch.setattr(reader.os, "listdir", lambda _: ["extra"])
    with pytest.raises(ValueError, match="package entries"):
        reader.read_windows_package(Path("package"))
    assert_closed(api)
