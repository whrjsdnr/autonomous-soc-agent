"""Read-only Windows package handles; bytes still require the existing trusted digest.

Package files are public artifacts, not private persistence. Inspect every path for
reparse points and pin directories; do not impose storage DACL ownership on packages.
"""

import ctypes as c
import os
from contextlib import ExitStack
from pathlib import Path

from soc_agent.review.persistence.windows_storage import (
    DIRECTORY,
    DWORD,
    PTR,
    REPARSE,
    FileInformation,
    NativeWin32,
    canonical_path,
)
from soc_agent.security_ai.packaging.files import (
    DIRECTORIES,
    FILES,
    MAX_FILE_BYTES,
    MAX_PACKAGE_BYTES,
)


def _information(api: NativeWin32, handle: int, *, directory: bool) -> FileInformation:
    info = FileInformation()
    api._check(api.kernel.GetFileInformationByHandle(handle, c.byref(info)))
    if info.attributes & REPARSE or bool(info.attributes & DIRECTORY) != directory:
        raise ValueError("Package reparse points or unexpected object types forbidden")
    return info


def _identity(info: FileInformation) -> tuple[int, ...]:
    return (
        info.volume,
        info.index_high,
        info.index_low,
        info.size_high,
        info.size_low,
        info.written.high,
        info.written.low,
    )


def _read_file(api: NativeWin32, path: str) -> bytes:
    # GENERIC_READ; share read only, so writers/deleters cannot change the open file.
    handle = api.kernel.CreateFileW(path, 0x80000080, 1, None, 3, 0x08200000, None)
    if handle == c.c_void_p(-1).value:
        raise ValueError("Package file handle unavailable")
    try:
        info = _information(api, handle, directory=False)
        if (
            api.kernel.GetFileType(handle) != 1
            or (info.size_high << 32 | info.size_low) > MAX_FILE_BYTES
        ):
            raise ValueError("Unsupported or oversized package file")
        chunks = []
        total = 0
        while True:
            buffer = c.create_string_buffer(min(65536, MAX_FILE_BYTES + 1 - total))
            count = DWORD()
            api._check(api.kernel.ReadFile(handle, buffer, len(buffer), c.byref(count), None))
            if count.value > len(buffer):
                raise ValueError("Invalid package read length")
            if not count.value:
                break
            chunks.append(buffer.raw[: count.value])
            total += count.value
            if total > MAX_FILE_BYTES:
                raise ValueError("Oversized package file")
        after = _information(api, handle, directory=False)
        if _identity(info) != _identity(after) or total != (info.size_high << 32 | info.size_low):
            raise ValueError("Package file changed during read")
        return b"".join(chunks)
    finally:
        api.kernel.CloseHandle(handle)


def read_windows_package(path: Path) -> dict[str, bytes]:
    api = NativeWin32()
    api.kernel.ReadFile.argtypes = [PTR, PTR, DWORD, c.POINTER(DWORD), PTR]
    api.kernel.ReadFile.restype = c.c_int32
    api.kernel.GetFileType.argtypes = [PTR]
    api.kernel.GetFileType.restype = DWORD
    absolute = canonical_path(Path(os.path.abspath(path)))
    with ExitStack() as handles:
        for parent in reversed((absolute, *absolute.parents)):
            handle = handles.enter_context(api.hold(str(parent)))
            _information(api, handle, directory=True)
        expected_root = {"manifest.json", "metadata.json", *DIRECTORIES}
        if set(os.listdir(str(absolute))) != expected_root:
            raise ValueError("Unexpected or missing package entries")
        for name in sorted(DIRECTORIES):
            nested = absolute / name
            handle = handles.enter_context(api.hold(str(nested)))
            _information(api, handle, directory=True)
            if set(os.listdir(str(nested))) != (
                {"model.json"} if name == "model" else {"profile.json"}
            ):
                raise ValueError("Unexpected or missing nested entries")
        values = {}
        total = 0
        for name in sorted(FILES):
            value = _read_file(api, str(absolute / name))
            total += len(value)
            if total > MAX_PACKAGE_BYTES:
                raise ValueError("Package exceeds total size budget")
            values[name] = value
        if set(os.listdir(str(absolute))) != expected_root or any(
            set(os.listdir(str(absolute / name)))
            != ({"model.json"} if name == "model" else {"profile.json"})
            for name in DIRECTORIES
        ):
            raise ValueError("Package inventory changed during read")
        return values
