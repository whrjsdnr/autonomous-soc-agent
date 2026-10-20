"""Compiled metadata predicate only. Never read the real shadow file or authenticate."""

import os
import stat
import subprocess
from pathlib import Path

import pytest


@pytest.fixture(scope="module")
def checker(tmp_path_factory):
    root = Path(__file__).parents[2] / "src/soc_agent/security_ai/ebpf_tc"
    directory = tmp_path_factory.mktemp("shadow-metadata")
    source = directory / "check.c"
    source.write_text(
        '#include "auth_qualification.c"\n'
        "int main(int n,char **v) {if(!getuid() || n!=5)return 3;"
        "struct stat st={0};st.st_mode=strtoul(v[1],0,0);"
        "st.st_uid=strtoul(v[2],0,0);st.st_gid=strtoul(v[3],0,0);"
        "st.st_nlink=strtoul(v[4],0,0);return shadow_metadata(&st)?2:0;}\n"
    )
    executable = directory / "check"
    subprocess.run(
        [
            "cc",
            "-O2",
            "-Wall",
            "-Werror",
            "-Wno-misleading-indentation",
            "-ffunction-sections",
            "-fdata-sections",
            "-Wl,--gc-sections",
            "-I" + str(root),
            str(source),
            "-o",
            str(executable),
        ],
        check=True,
        capture_output=True,
    )
    return executable


@pytest.mark.parametrize(
    ("kind", "mode", "uid", "gid", "links", "accepted"),
    [
        (stat.S_IFREG, 0o640, 0, 42, 1, True),
        (stat.S_IFREG, 0o600, 0, 0, 1, True),
        (stat.S_IFREG, 0o640, os.getuid(), 42, 1, False),
        (stat.S_IFREG, 0o660, 0, 42, 1, False),
        (stat.S_IFREG, 0o644, 0, 42, 1, False),
        (stat.S_IFREG, 0o640, 0, 42, 2, False),
        (stat.S_IFCHR, 0o640, 0, 42, 1, False),
        (stat.S_IFLNK, 0o640, 0, 42, 1, False),
    ],
)
def test_shadow_metadata_does_not_require_executable_group(
    checker, kind, mode, uid, gid, links, accepted
):
    run = subprocess.run(
        [str(checker), str(kind | mode), str(uid), str(gid), str(links)],
        check=False,
        capture_output=True,
        timeout=5,
    )
    assert run.returncode == (0 if accepted else 2)
    assert run.stdout == run.stderr == b""
