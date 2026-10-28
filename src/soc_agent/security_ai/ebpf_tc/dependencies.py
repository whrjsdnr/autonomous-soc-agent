"""Static ELF dependency qualification. Never ldd, dlopen or execute the inspected ELF."""

import hashlib
import os
import re
import stat
import subprocess
from pathlib import Path
from typing import Literal

from pydantic import Field

from soc_agent.review.models import Hash
from soc_agent.security_ai.ebpf_broker.identity import F_ADD_SEALS, SEALS
from soc_agent.security_ai.research.models import Frozen

LIBRARY_DIRS = (Path("/usr/lib/x86_64-linux-gnu"), Path("/usr/lib64"), Path("/usr/lib"))


class Dependency(Frozen):
    path: str = Field(pattern=r"^/usr/lib[^\x00]*$", max_length=256)
    sha256: Hash
    size: int = Field(gt=0, le=16 * 1024**2)
    needed: tuple[str, ...] = Field(max_length=32)
    interpreter: str | None = Field(default=None, max_length=256)
    mode: int = Field(default=0o644, ge=0, le=0o777)
    soname: str | None = Field(default=None, max_length=128)
    source: Literal["STATIC_READELF_NOT_LOADED"] = "STATIC_READELF_NOT_LOADED"


def read_held(
    path: Path, *, owner: int, limit: int = 16 * 1024**2, allow_empty: bool = False
) -> bytes:
    """Walk directories by FD; return a stable bounded snapshot, not path execution authority."""
    if not path.is_absolute() or any(p in {".", ".."} for p in str(path).split("/")):
        raise ValueError("TRUST_PATH_INVALID")
    directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for component in path.parts[1:-1]:
            child = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=directory,
            )
            os.close(directory)
            directory = child
            info = os.fstat(directory)
            # Root-owned ancestors are allowed for an ordinary-UID simulation.
            if info.st_uid not in {0, owner} or (
                info.st_mode & 0o022
                and not (owner != 0 and info.st_uid == 0 and info.st_mode & stat.S_ISVTX)
            ):
                raise ValueError("TRUST_PARENT_MUTABLE")
        fd = os.open(
            path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory
        )
        try:
            before = os.fstat(fd)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_uid != owner
                or owner == 0
                and before.st_gid != 0
                or before.st_nlink != 1
                or before.st_mode & 0o022
                or not (0 if allow_empty else 1) <= before.st_size <= limit
            ):
                raise ValueError("TRUST_FILE_INVALID")
            body = os.pread(fd, before.st_size + 1, 0)
            after = os.fstat(fd)
            if (
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
                before.st_mode,
                before.st_nlink,
            ) != (
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
                after.st_mode,
                after.st_nlink,
            ) or len(body) != before.st_size:
                raise ValueError("TRUST_FILE_CHANGED")
            return body
        finally:
            os.close(fd)
    finally:
        os.close(directory)


def inspect_elf(body: bytes, *, symbols: bool = False) -> str:
    """Inspect immutable bytes in a sealed memfd, with a clean child environment."""
    import fcntl

    if not body.startswith(b"\x7fELF"):
        raise ValueError("DEPENDENCY_NOT_ELF")
    fd = os.memfd_create("soc-elf-inspection", os.MFD_ALLOW_SEALING | os.MFD_CLOEXEC)
    try:
        if os.write(fd, body) != len(body):
            raise ValueError("DEPENDENCY_SNAPSHOT_WRITE")
        fcntl.fcntl(fd, F_ADD_SEALS, SEALS)
        result = subprocess.run(
            [
                "/usr/bin/readelf",
                "-W",
                "-d",
                "-l",
                *(["--dyn-syms"] if symbols else []),
                "/proc/self/fd/" + str(fd),
            ],
            pass_fds=(fd,),
            capture_output=True,
            text=True,
            timeout=5,
            env={"PATH": "/usr/bin:/bin", "LANG": "C"},
            check=True,
        )
    finally:
        os.close(fd)
    text = result.stdout
    if len(text) > (1048576 if symbols else 65536) or any(
        tag in text
        for tag in ("(RPATH)", "(RUNPATH)", "(AUDIT)", "(DEPAUDIT)", "(FILTER)", "(AUXILIARY)")
    ):
        raise ValueError("DEPENDENCY_SEARCH_PATH_DENIED")
    return text


def elf_metadata(body: bytes) -> tuple[tuple[str, ...], str | None]:
    text = inspect_elf(body)
    needed = tuple(re.findall(r"\(NEEDED\).*\[([^\]]+)\]", text))
    if len(needed) > 32 or any(not re.fullmatch(r"[a-zA-Z0-9_.+-]{1,96}", n) for n in needed):
        raise ValueError("DEPENDENCY_NAME_INVALID")
    interpreter = re.search(r"Requesting program interpreter: ([^\]]+)\]", text)
    path = interpreter.group(1) if interpreter else None
    if path is not None and path not in {
        "/lib64/ld-linux-x86-64.so.2",
        "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
    }:
        raise ValueError("DEPENDENCY_INTERPRETER_DENIED")
    return needed, path


def _library(name: str) -> Path:
    for directory in LIBRARY_DIRS:
        candidate = directory / name
        if candidate.exists():
            result = candidate.resolve(strict=True)
            if result.is_relative_to("/usr/lib") or result.is_relative_to("/usr/lib64"):
                return result
    raise ValueError("DEPENDENCY_UNRESOLVED")


def inventory(binaries: tuple[bytes, ...]) -> tuple[Dependency, ...]:
    pending: list[Path] = []
    for body in binaries:
        needed, interpreter = elf_metadata(body)
        pending.extend(_library(n) for n in needed)
        if interpreter:
            pending.append(Path(interpreter).resolve(strict=True))
    # PAM modules are loaded dynamically, not listed in the bootstrap's DT_NEEDED.
    pending.append(_library("security/pam_unix.so"))
    from soc_agent.security_ai.ebpf_tc.dynamic_trust import nss_policy

    policy = nss_policy(read_held(Path("/etc/nsswitch.conf"), owner=0))
    for service in policy.services:
        if service not in {"files", "dns"}:
            try:
                pending.append(_library("libnss_" + service + ".so.2"))
            except ValueError as exc:
                if str(exc) != "DEPENDENCY_UNRESOLVED":
                    raise
                # Recorded explicitly by the trust report; never inferred as available.

    records: dict[str, Dependency] = {}
    total = 0
    while pending:
        path = pending.pop()
        if str(path) in records:
            continue
        if len(records) >= 64:
            raise ValueError("DEPENDENCY_COUNT_BUDGET")
        body = read_held(path, owner=0)
        total += len(body)
        if total > 64 * 1024**2:
            raise ValueError("DEPENDENCY_MEMORY_BUDGET")
        needed, interpreter = elf_metadata(body)
        records[str(path)] = Dependency(
            path=str(path),
            sha256=hashlib.sha256(body).hexdigest(),
            size=len(body),
            needed=needed,
            mode=stat.S_IMODE(path.stat().st_mode),
            soname=soname(body),
            interpreter=interpreter,
        )
        pending.extend(_library(n) for n in needed)
    return tuple(records[k] for k in sorted(records))


def verify_dependencies(records: tuple[Dependency, ...]) -> dict[str, str]:
    if not records or len(records) > 64 or len({r.path for r in records}) != len(records):
        raise ValueError("DEPENDENCY_INVENTORY_INVALID")
    for record in records:
        path = Path(record.path)
        if (
            not any(path.is_relative_to(root) for root in LIBRARY_DIRS)
            or path.resolve(strict=True) != path
        ):
            raise ValueError("DEPENDENCY_CANONICAL_PATH_REQUIRED")
        body = read_held(path, owner=0)
        if (
            len(body) != record.size
            or hashlib.sha256(body).hexdigest() != record.sha256
            or stat.S_IMODE(path.stat().st_mode) != record.mode
        ):
            raise ValueError("DEPENDENCY_HASH_MISMATCH")
    return {
        "static_inventory": "VERIFIED_READ_ONLY",
        "dynamic_pam_nss_closure": "UNKNOWN",
        "native_release": "BLOCKED",
    }


def soname(body: bytes) -> str | None:
    match = re.search(r"\(SONAME\).*\[([^\]]+)\]", inspect_elf(body))
    if not match:
        return None
    value = match.group(1)
    if not re.fullmatch(r"[a-zA-Z0-9_.+-]{1,128}", value):
        raise ValueError("DEPENDENCY_SONAME_INVALID")
    return value
