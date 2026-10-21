"""Embedded Root image continuation. No project imports or caller-selected commands.

Executed only as immutable bytes approved by SHA, by isolated system Python under
sudo. This module itself never invokes sudo, PAM, BPF, TC, a shell, or a GUI.
"""

import base64
import fcntl
import hashlib
import json
import os
import struct
import time

PROOF = struct.Struct("<8sIIQQ352s32s32s32s32s")
LABEL = b"SOC_UNIFIED_SESSION_V1\0"


def _ticks(pid: int) -> int:
    with open(f"/proc/{pid}/stat", "rb") as stream:
        return int(stream.read(4096).rsplit(b")", 1)[1].split()[19])


def _sudo_parent() -> bytes:
    parent = os.getppid()
    actual, trusted = os.stat(f"/proc/{parent}/exe"), os.stat("/usr/bin/sudo")
    if (actual.st_dev, actual.st_ino) != (trusted.st_dev, trusted.st_ino):
        raise ValueError("UNIFIED_OS_ENTRY_MISMATCH")
    with open(f"/proc/{parent}/cmdline", "rb") as stream:
        args = stream.read(16385).split(b"\0")
    fixed = [b"-k", b"-u", b"root", b"--", b"/usr/bin/python3", b"-I", b"-S", b"-c"]
    if len(args) != 11 or args[1:9] != fixed or args[-1] or not args[9]:
        raise ValueError("UNIFIED_OS_COMMAND_MISMATCH")
    return hashlib.sha256(args[9]).digest()


def _safe_environment(uid: int, gid: int) -> dict:
    # Retain only sudo's numeric caller identity and required account-policy name.
    user = os.environ.get("SUDO_USER", "")
    if (
        not user
        or not user.isascii()
        or any(
            c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
            for c in user
        )
    ):
        raise ValueError("UNIFIED_OS_USER_REQUIRED")
    return {
        "PATH": "/usr/bin:/bin",
        "LANG": "C",
        "SUDO_UID": str(uid),
        "SUDO_GID": str(gid),
        "SUDO_USER": user,
    }


def _candidate_policy(image: dict, uid: int, gid: int, environment: dict) -> None:
    row = image["files"]["bootstrap"]
    body = base64.b64decode(row["body"], validate=True)
    if hashlib.sha256(body).hexdigest() != row["sha256"]:
        raise ValueError("UNIFIED_POLICY_SHA_MISMATCH")
    fd = os.memfd_create("soc-reviewed-policy", os.MFD_ALLOW_SEALING | os.MFD_CLOEXEC)
    try:
        with os.fdopen(os.dup(fd), "wb") as stream:
            stream.write(body)
        os.fchmod(fd, 0o500)
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, 15)
        child = os.fork()
        if child == 0:
            try:
                os.execve(
                    fd, ["bootstrap", "--unified-policy-check", str(uid), str(gid)], environment
                )
            except BaseException:
                os._exit(125)
        _, status = os.waitpid(child, 0)
        if status != 0:
            raise ValueError("UNIFIED_PASSWORD_POLICY_REJECTED")
    finally:
        os.close(fd)


def _validate_envelope(envelope: bytes, image: dict, uid: int, gid: int) -> None:
    if len(envelope) != 352 or uid <= 0 or gid <= 0:
        raise ValueError("UNIFIED_SCOPE_SIZE")
    version, actual_uid, actual_gid = struct.unpack_from("<III", envelope)
    if version != 2 or (uid, gid) != (actual_uid, actual_gid):
        raise ValueError("UNIFIED_SCOPE_IDENTITY")
    # All resource limits, namespace, controller and release fields are checked
    # again by Bootstrap before Broker execution. Check fixed approved caps here.
    if struct.unpack_from("<IIIIIIII", envelope, 32)[1:] != (1, 300, 4096, 32, 256, 20, 0):
        raise ValueError("UNIFIED_SCOPE_BUDGET")
    if struct.unpack_from("<I", envelope, 32)[0] != 1:
        raise ValueError("UNIFIED_LOOPBACK_REQUIRED")
    if envelope[272:304].hex() != image["manifest_sha256"]:
        raise ValueError("UNIFIED_SCOPE_MANIFEST")
    release = json.loads(base64.b64decode(image["files"]["release.json"]["body"], validate=True))
    if (
        envelope[208:240].hex() != release["bundle_digest"]
        or envelope[304:320] != release["version"].encode().ljust(16, b"\0")
        or hashlib.sha256(envelope[:240] + bytes(32)).digest() != envelope[240:272]
    ):
        raise ValueError("UNIFIED_SCOPE_RELEASE_IDENTITY")
    if hashlib.sha256(envelope[:320] + bytes(32)).digest() != envelope[320:]:
        raise ValueError("UNIFIED_SCOPE_DIGEST")
    for offset, name in (
        (80, "tc.bpf.o"),
        (112, "libnative-tc.so"),
        (144, "bootstrap"),
        (176, "broker"),
    ):
        if envelope[offset : offset + 32].hex() != image["files"][name]["sha256"]:
            raise ValueError("UNIFIED_SCOPE_BINARY")


def unified_root_main(image: dict, previous: dict | None, args: list[str], engine: dict) -> None:
    if (
        len(args) != 7
        or args[1] != "run"
        or any((os.getuid(), os.geteuid(), os.getgid(), os.getegid()))
    ):
        raise ValueError("UNIFIED_ROOT_ENTRY_REQUIRED")
    uid, gid = int(args[2]), int(args[3])
    if (os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")) != (str(uid), str(gid)):
        raise ValueError("UNIFIED_CALLER_MISMATCH")
    envelope, image_sha, approval = (
        bytes.fromhex(args[4]),
        bytes.fromhex(args[5]),
        bytes.fromhex(args[6]),
    )
    old_sha = bytes.fromhex(previous["manifest_sha256"]) if previous else bytes(32)
    if (
        len(image_sha) != 32
        or hashlib.sha256(LABEL + envelope + image_sha + old_sha).digest() != approval
    ):
        raise ValueError("UNIFIED_APPROVAL_MISMATCH")
    _validate_envelope(envelope, image, uid, gid)
    pid = struct.unpack_from("<I", envelope, 12)[0]
    ticks, namespace = struct.unpack_from("<QQ", envelope, 16)
    if (
        os.stat(f"/proc/{pid}").st_uid != uid
        or _ticks(pid) != ticks
        or os.stat("/proc/self/ns/net").st_ino != namespace
        or os.stat(f"/proc/{pid}/ns/net").st_ino != namespace
    ):
        raise ValueError("UNIFIED_CONTROLLER_IDENTITY_CHANGED")
    command_sha, environment = _sudo_parent(), _safe_environment(uid, gid)
    # This policy check is read-only: reject NOPASSWD, missing TTY, account-policy
    # drift before even archiving a previous release. Never prompts a second time.
    engine["_verify_dependencies"](image)
    _candidate_policy(image, uid, gid, environment)
    if previous:
        engine["root_main"](previous, "check")
        if previous["manifest_sha256"] != image["manifest_sha256"]:
            rollback = hashlib.sha256(b"SOC_INSTALL_ROLLBACK_V1\0" + old_sha).hexdigest()
            engine["root_main"](previous, "rollback", rollback)
            engine["root_main"](image, "install")
    else:
        engine["root_main"](image, "install")
    engine["root_main"](image, "check")
    # Optional reviewed supervisor sidecar is forked before any Kernel resource
    # or authority FD exists. This process still execs Bootstrap directly under sudo.
    if "supervisor_prepare" in engine:
        engine["supervisor_prepare"](image, envelope, approval, environment)
    directory = engine["_open_directory"]("/usr/libexec/soc-agent-ebpf", 0)
    try:
        bootstrap = os.open("bootstrap", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
        engine["_read"](bootstrap, 0, 0o555, image["files"]["bootstrap"]["sha256"])
        executable = fcntl.fcntl(bootstrap, fcntl.F_DUPFD_CLOEXEC, 32)
        os.close(bootstrap)
    finally:
        os.close(directory)
    proof = PROOF.pack(
        b"SOCUNP01",
        1,
        os.getpid(),
        _ticks(os.getpid()),
        time.monotonic_ns(),
        envelope,
        image_sha,
        old_sha,
        command_sha,
        approval,
    )
    fd = os.memfd_create("soc-unified-authority", os.MFD_ALLOW_SEALING | os.MFD_CLOEXEC)
    if os.write(fd, proof) != len(proof):
        raise ValueError("UNIFIED_AUTHORITY_PARTIAL_WRITE")
    os.fchmod(fd, 0o400)
    fcntl.fcntl(fd, fcntl.F_ADD_SEALS, 15)
    os.dup2(fd, 8, inheritable=True)
    if fd != 8:
        os.close(fd)
    os.execve(
        executable,
        [
            "bootstrap",
            "--unified-handoff",
            str(uid),
            str(gid),
            envelope[64:80].hex(),
            envelope[320:].hex(),
            envelope[272:304].hex(),
            approval.hex(),
        ],
        environment,
    )
