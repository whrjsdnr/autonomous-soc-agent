"""Real unprivileged PTYs; no sudo, authentication, capabilities or BPF operations."""

import os
import pty
import subprocess
import sys

import pytest


@pytest.mark.parametrize("case", ["owned", "wrong_uid", "pipe_input", "background"])
def test_controlling_terminal_identity(case):
    master, slave = pty.openpty()
    body = """
import fcntl,os,sys,termios
fcntl.ioctl(0,termios.TIOCSCTTY,0)
from soc_agent.security_ai.ebpf_tc.auth_session import open_authentication_tty
case=sys.argv[1]
if case=='pipe_input':
    read,write=os.pipe()
    os.dup2(read,0);os.close(read);os.close(write)
if case=='background':
    os.tcgetpgrp=lambda _:os.getpgrp()+1
try:
    fd=open_authentication_tty(os.getuid()+(1 if case=='wrong_uid' else 0))
except (OSError,ValueError):
    print('REJECTED')
else:
    print('VERIFIED',os.stat('/dev/tty').st_uid,os.getuid(),os.isatty(fd))
    os.close(fd)
"""
    try:
        run = subprocess.run(
            [sys.executable, "-c", body, case],
            stdin=slave,
            capture_output=True,
            text=True,
            start_new_session=True,
            timeout=10,
            check=True,
        )
    finally:
        os.close(master)
        os.close(slave)
    if case == "owned":
        # Reproduce the root-owned /dev/tty alias which the old check rejected.
        assert run.stdout.strip() == f"VERIFIED 0 {os.getuid()} True"
    else:
        assert run.stdout.strip() == "REJECTED"


def test_missing_controlling_terminal_rejected():
    run = subprocess.run(
        [
            sys.executable,
            "-c",
            "import os\n"
            "from soc_agent.security_ai.ebpf_tc.auth_session import open_authentication_tty\n"
            "try: open_authentication_tty(os.getuid())\n"
            "except OSError: print('REJECTED')\n",
        ],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        start_new_session=True,
        timeout=10,
        check=True,
    )
    assert run.stdout.strip() == "REJECTED"
