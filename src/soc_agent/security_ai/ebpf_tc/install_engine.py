"""Standalone standard-library installer engine; no authentication or Kernel actions.

The generated, SHA-pinned image embeds reviewed bytes. It never imports SOC code
as root, reads caller-selected payload paths, runs a shell, or overwrites a release.
"""

import base64
import ctypes
import hashlib
import json
import os
import stat

DESTINATION = "soc-agent-ebpf"


def _directory(fd: int, owner: int) -> None:
    st = os.fstat(fd)
    if (
        not stat.S_ISDIR(st.st_mode)
        or st.st_uid != owner
        or owner == 0
        and st.st_gid != 0
        or st.st_mode & 0o022
    ):
        raise ValueError("INSTALL_PARENT_UNTRUSTED")


def _read(fd: int, owner: int, mode: int, expected: str, limit: int = 1048576) -> bytes:
    st = os.fstat(fd)
    if (
        not stat.S_ISREG(st.st_mode)
        or st.st_uid != owner
        or owner == 0
        and st.st_gid != 0
        or st.st_nlink != 1
        or stat.S_IMODE(st.st_mode) != mode
        or not 0 < st.st_size <= limit
    ):
        raise ValueError("INSTALL_FILE_UNTRUSTED")
    body = os.pread(fd, st.st_size + 1, 0)
    after = os.fstat(fd)
    if (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    ) or hashlib.sha256(body).hexdigest() != expected:
        raise ValueError("INSTALL_SHA_MISMATCH")
    return body


def _open_directory(path: str, owner: int) -> int:
    # Production always starts at / and walks trusted root-owned parents via FDs.
    current = os.open("/", os.O_DIRECTORY | os.O_RDONLY | os.O_CLOEXEC)
    try:
        _directory(current, owner)
        for part in path.split("/")[1:]:
            if not part or part in {".", ".."}:
                raise ValueError("INSTALL_PARENT_PATH")
            nxt = os.open(part, os.O_DIRECTORY | os.O_NOFOLLOW | os.O_RDONLY, dir_fd=current)
            os.close(current)
            current = nxt
            _directory(current, owner)
        return current
    except BaseException:
        os.close(current)
        raise


def _rename(parent: int, source: str, target: str) -> None:
    # Linux atomic publish without overwriting either a file, symlink or directory.
    libc = ctypes.CDLL(None, use_errno=True)
    rename = libc.renameat2
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    if rename(parent, source.encode(), parent, target.encode(), 1):  # RENAME_NOREPLACE
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))
    os.fsync(parent)


def _verify(directory: int, image: dict, owner: int) -> None:
    _directory(directory, owner)
    if set(os.listdir(directory)) != set(image["files"]):
        raise ValueError("INSTALL_FILE_SET_MISMATCH")
    for name, row in image["files"].items():
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        try:
            _read(fd, owner, row["mode"], row["sha256"])
        finally:
            os.close(fd)


def _apply(image: dict, parent: int, owner: int, action: str) -> dict:
    """Private common engine for ordinary-UID temporary-directory tests and root entry."""
    _directory(parent, owner)
    expected = {
        "entry",
        "bootstrap",
        "broker",
        "libnative-tc.so",
        "tc.bpf.o",
        "manifest.bin",
        "pam-policy.conf",
        "release.json",
        "release.trust",
    }
    if set(image["files"]) != expected or action not in {"install", "check", "rollback"}:
        raise ValueError("INSTALL_IMAGE_SCHEMA")
    manifest = image["manifest_sha256"]
    if len(manifest) != 64 or any(c not in "0123456789abcdef" for c in manifest):
        raise ValueError("INSTALL_MANIFEST_DIGEST")
    for name, row in image["files"].items():
        mode = 0o555 if name in {"entry", "bootstrap", "broker"} else 0o444
        if row["mode"] != mode:
            raise ValueError("INSTALL_IMAGE_MODE")
        body = base64.b64decode(row["body"], validate=True)
        if not 0 < len(body) <= 1048576 or hashlib.sha256(body).hexdigest() != row["sha256"]:
            raise ValueError("INSTALL_IMAGE_HASH")
    if image["files"]["release.json"]["sha256"] != manifest:
        raise ValueError("INSTALL_MANIFEST_MISMATCH")
    staging = ".soc-agent-ebpf.staging-" + manifest
    backup = ".soc-agent-ebpf.rollback-" + manifest
    if action != "install":
        fd = os.open(DESTINATION, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        try:
            _verify(fd, image, owner)
            before = os.fstat(fd)
            current = os.stat(DESTINATION, dir_fd=parent, follow_symlinks=False)
            if (before.st_dev, before.st_ino) != (current.st_dev, current.st_ino):
                raise ValueError("INSTALL_DIRECTORY_CHANGED")
            if action == "rollback":
                # Never remove unknown files; retain the exact release for inspection.
                _rename(parent, DESTINATION, backup)
        finally:
            os.close(fd)
        return {"action": action, "manifest": manifest, "native_activation": False}
    try:
        os.stat(DESTINATION, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        pass
    else:
        raise ValueError("INSTALL_CONFLICT")
    os.mkdir(staging, mode=0o700, dir_fd=parent)  # Existing staging is a conflict too.
    fd = os.open(staging, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
    try:
        for name, row in image["files"].items():
            target = os.open(
                name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd
            )
            try:
                view = memoryview(base64.b64decode(row["body"], validate=True))
                while view:
                    count = os.write(target, view)
                    if count <= 0:
                        raise ValueError("INSTALL_PARTIAL_WRITE")
                    view = view[count:]
                os.fchmod(target, row["mode"])
                os.fsync(target)
            finally:
                os.close(target)
        _verify(fd, image, owner)
        os.fchmod(fd, 0o755)
        os.fsync(fd)
        _rename(parent, staging, DESTINATION)
    finally:
        os.close(fd)
    # Failures retain bounded staging evidence; no recursive deletion or auto retry.
    return {"action": action, "manifest": manifest, "native_activation": False}


def _quiescent(parent: int) -> None:
    directory = os.open(DESTINATION, os.O_DIRECTORY | os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
    try:
        identities = {
            (st.st_dev, st.st_ino)
            for st in (
                os.stat(name, dir_fd=directory, follow_symlinks=False)
                for name in ("bootstrap", "broker")
            )
        }
    finally:
        os.close(directory)
    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        try:
            st = os.stat("/proc/" + name + "/exe")
        except (FileNotFoundError, ProcessLookupError):
            continue
        if (st.st_dev, st.st_ino) in identities:
            raise ValueError("INSTALL_APPLICATION_NOT_QUIESCENT")


def _verify_dependencies(image: dict) -> None:
    for row in image["dependencies"]:
        path = row["path"]
        directory, name = path.rsplit("/", 1)
        folder = _open_directory(directory, 0)
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=folder)
            try:
                _read(fd, 0, row["mode"], row["sha256"], 64 * 1024**2)
            finally:
                os.close(fd)
        finally:
            os.close(folder)


def root_main(image: dict, action: str, approval: str | None = None) -> None:
    if os.getuid() != 0 or os.geteuid() != 0 or os.getgid() != 0 or os.getegid() != 0:
        raise ValueError("INSTALL_ROOT_REQUIRED")
    if action == "rollback":
        # Quiescence is reviewed separately. No automatic Hook cleanup or deletion.
        expected = hashlib.sha256(
            b"SOC_INSTALL_ROLLBACK_V1\0" + bytes.fromhex(image["manifest_sha256"])
        ).hexdigest()
        if approval != expected:
            raise ValueError("INSTALL_ROLLBACK_APPROVAL_REQUIRED")
    parent = _open_directory("/usr/libexec", 0)
    try:
        if action == "rollback":
            _quiescent(parent)
        # Revalidate dependencies before publishing, but never block exact unpublish
        # merely because an OS update changed an unrelated dependency.
        if action != "rollback":
            _verify_dependencies(image)
        print(json.dumps(_apply(image, parent, 0, action), sort_keys=True))
    finally:
        os.close(parent)
