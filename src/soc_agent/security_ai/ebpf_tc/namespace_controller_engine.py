"""Fixed Root entry: existing Namespace -> ordinary Controller, never Native authority.

Embedded only; imports do not run it. Root admission, budget reservation and the
one-use claim are repeated through the existing Root-only validator first.
"""

import ctypes
import hashlib
import json
import os
import pwd
import signal
import stat
import sys
from pathlib import Path


def controller_root_main(config):
    dns_root_main(config)  # noqa: F821 -- existing DNS-only admission and complete diagnostic
    envelope = json.loads(sys.argv[1])
    signal.alarm(10)
    if config.get("admitted_operation") != "ROOT_DNS_DIAGNOSTIC":
        raise ValueError("NAMESPACE_CONTROLLER_SCOPE_REQUIRED")
    cookie = enter_namespace(config)  # noqa: F821 -- shared held-FD/route checks
    uid, gid = config["uid"], config["gid"]
    terminal = os.fstat(0)
    if not os.isatty(0) or not stat.S_ISCHR(terminal.st_mode) or terminal.st_uid not in (0, uid):
        raise ValueError("NAMESPACE_CONTROLLER_TERMINAL")
    # sudo's private PTY can be Root-owned. Only this inherited authenticated
    # controlling terminal may be returned to the invoking user, never a path.
    if terminal.st_uid == 0:
        os.fchown(0, uid, gid)
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(47, 4, 0, 0, 0):  # clear ambient; no capability restoration
        raise OSError(ctypes.get_errno(), "NAMESPACE_CONTROLLER_CAPABILITIES")
    group = config["controller"]["docker_group"]
    groups = [] if group is None else [group]
    if group is not None:
        endpoint = os.stat("/var/run/docker.sock")
        account = pwd.getpwuid(uid).pw_name
        if (
            not stat.S_ISSOCK(endpoint.st_mode)
            or endpoint.st_uid != 0
            or endpoint.st_gid != group
            or endpoint.st_mode & 0o007
            or group not in os.getgrouplist(account, gid)
        ):
            raise ValueError("NAMESPACE_CONTROLLER_DOCKER_GROUP_NOT_PREEXISTING")
    os.setgroups(groups)
    os.setresgid(gid, gid, gid)
    os.setresuid(uid, uid, uid)
    # Preserve the ordinary user's original bounding set and NNP=0: the later
    # independent Supervisor must still perform a fresh OS sudo authentication.
    # E/P/I/A must all be zero; neither this entry nor a passed FD grants BPF.
    rows = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines())
    if (
        os.getresuid() != (uid,) * 3
        or os.getresgid() != (gid,) * 3
        or os.getgroups() != groups
        or any(int(rows[k], 16) for k in ("CapEff", "CapPrm", "CapInh", "CapAmb"))
    ):
        raise ValueError("NAMESPACE_CONTROLLER_PRIVILEGE_DROP")
    signal.alarm(0)
    if libc.prctl(4, 1, 0, 0, 0):  # ordinary Controller inspectable by its owner
        raise OSError(ctypes.get_errno(), "NAMESPACE_CONTROLLER_DUMPABLE")
    child = config["controller"] | dict(
        namespace=config["namespace"],
        cookie=cookie.hex(),
        attempt=envelope["approval_sha"],
        ledger=envelope["ledger_file"],
        ack=str(
            Path(envelope["manifest_file"]).parent
            / (envelope["approval_sha"] + ".controller-ack.json")
        ),
    )
    print(
        json.dumps(
            dict(
                state="NAMESPACE_CONTROLLER_READY",
                pid=os.getpid(),
                uid=uid,
                gid=gid,
                namespace=config["namespace"],
                cookie=cookie.hex(),
            )
        ),
        flush=True,
    )
    # The Host parent sees EOF after the READY record and settles only the Root
    # entry. This process remains in the isolated Namespace as an ordinary UID.
    tty = os.open("/dev/tty", os.O_RDWR | os.O_CLOEXEC)
    os.dup2(tty, 0)
    os.dup2(tty, 1)
    os.dup2(tty, 2)
    if tty > 2:
        os.close(tty)
    interpreter = child["interpreter"]
    fd = os.open(interpreter, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        data = os.pread(fd, 64 * 1024**2, 0)
        if hashlib.sha256(data).hexdigest() != child["interpreter_sha"]:
            raise ValueError("NAMESPACE_CONTROLLER_INTERPRETER_CHANGED")
    finally:
        os.close(fd)
    source = (
        "import sys;sys.path.insert(0," + repr(str(Path(child["project"]) / "src")) + ");"
        "from soc_agent.security_ai.ebpf_tc.namespace_controller import child_main;"
        "child_main(" + repr(child) + ")"
    )
    # No Root execution of user code: credentials have already been irreversibly
    # dropped. The fixed child accepts only the existing recovery request schema.
    os.chdir(child["project"])
    os.execve(
        interpreter, [interpreter, "-I", "-c", source], {"PATH": "/usr/bin:/bin", "LANG": "C"}
    )
