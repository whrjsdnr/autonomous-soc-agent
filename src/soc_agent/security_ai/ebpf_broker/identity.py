"""Read-only source identity and sealed, inherited object descriptor admission."""

import fcntl
import hashlib
import os
import stat
from pathlib import Path

from soc_agent.security_ai.ebpf_native.loader import bundle as phase_a_bundle
from soc_agent.security_ai.research.models import digest

# Linux UAPI fcntl.h; Python 3.12 does not expose these constants.
F_ADD_SEALS, F_GET_SEALS = 1033, 1034
SEALS = 0x0001 | 0x0002 | 0x0004 | 0x0008


def bundle() -> dict[str, str]:
    root = Path(__file__).parent
    result = {"phase_a/" + k: v for k, v in phase_a_bundle().items()}
    result.update(
        {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(root.glob("*.py"))}
    )
    return result


def broker_sha() -> str:
    return hashlib.sha256(Path(__file__).with_name("server.py").read_bytes()).hexdigest()


def sealed_object(path: Path, expected: str) -> int:
    if path.is_symlink():
        raise ValueError("BROKER_OBJECT_PATH_DENIED")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("BROKER_OBJECT_NOT_REGULAR")
        size = info.st_size
        if not 64 <= size <= 1024**2:
            raise ValueError("BROKER_OBJECT_BOUND")
        body = os.read(fd, size + 1)
        if hashlib.sha256(body).hexdigest() != expected:
            raise ValueError("BROKER_OBJECT_SHA_MISMATCH")
        target = os.memfd_create("soc-bpf-approved-object", os.MFD_ALLOW_SEALING | os.MFD_CLOEXEC)
        try:
            if os.write(target, body) != len(body):
                raise ValueError("BROKER_OBJECT_COPY_FAILED")
            fcntl.fcntl(target, F_ADD_SEALS, SEALS)
            return target
        except BaseException:
            os.close(target)
            raise
    finally:
        os.close(fd)


def verify_object(fd: int, expected: str) -> None:
    if fcntl.fcntl(fd, F_GET_SEALS) & SEALS != SEALS:
        raise ValueError("BROKER_OBJECT_NOT_SEALED")
    size = os.fstat(fd).st_size
    if not 64 <= size <= 1024**2:
        raise ValueError("BROKER_OBJECT_BOUND")
    body = os.pread(fd, size + 1, 0)
    if hashlib.sha256(body).hexdigest() != expected or body[:6] != b"\x7fELF\x02\x01":
        raise ValueError("BROKER_OBJECT_SHA_MISMATCH")


def verify_bundle(expected: str) -> None:
    if digest(bundle()) != expected:
        raise ValueError("BROKER_BUNDLE_MISMATCH")
