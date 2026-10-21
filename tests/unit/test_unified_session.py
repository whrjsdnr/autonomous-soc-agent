"""Unified handoff boundaries, ordinary UID only; no sudo/PAM/BPF/TC invoked."""

import base64
import hashlib
import json
import os
import struct
import subprocess
from pathlib import Path

import pytest

from soc_agent.security_ai.ebpf_tc import unified_image_engine as engine
from soc_agent.security_ai.ebpf_tc.unified_image import UnifiedImage, pinned_command


def envelope():
    value = bytearray(352)
    struct.pack_into(
        "<IIIIQQIIIIIIII",
        value,
        0,
        2,
        os.getuid(),
        os.getgid(),
        os.getpid(),
        engine._ticks(os.getpid()),
        os.stat("/proc/self/ns/net").st_ino,
        1,
        1,
        300,
        4096,
        32,
        256,
        20,
        0,
    )
    for start in (80, 112, 144, 176, 208, 272):
        value[start : start + 32] = bytes([start % 255]) * 32
    value[240:272] = hashlib.sha256(value[:240] + bytes(32)).digest()
    value[304:320] = b"0.5.0".ljust(16, b"\0")
    value[320:] = hashlib.sha256(value[:320] + bytes(32)).digest()
    files = {
        name: {"sha256": bytes(value[offset : offset + 32]).hex()}
        for offset, name in (
            (80, "tc.bpf.o"),
            (112, "libnative-tc.so"),
            (144, "bootstrap"),
            (176, "broker"),
        )
    }
    files["release.json"] = {
        "body": base64.b64encode(
            json.dumps({"version": "0.5.0", "bundle_digest": bytes(value[208:240]).hex()}).encode()
        ).decode()
    }
    return bytes(value), {"files": files, "manifest_sha256": bytes(value[272:304]).hex()}


def test_pinned_exec_uses_verified_bytes_and_rejects_changed_image(tmp_path):
    path = tmp_path / "image.py"
    body = b"print('VERIFIED_SNAPSHOT_EXECUTED')\n"
    path.write_bytes(body)
    path.chmod(0o400)
    image = UnifiedImage(
        path=path,
        sha256=hashlib.sha256(body).hexdigest(),
        manifest="a" * 64,
        previous_manifest="b" * 64,
        version="0.5.0",
        action="UPDATE_RETAIN_PREVIOUS",
    )
    command = pinned_command(image, bytes(352), "c" * 64, os.getuid(), os.getgid())
    assert command[:9] == (
        "/usr/bin/sudo",
        "-k",
        "-u",
        "root",
        "--",
        "/usr/bin/python3",
        "-I",
        "-S",
        "-c",
    )
    # Execute only the isolated Python suffix, with our ordinary UID, no sudo.
    result = subprocess.run(command[5:], capture_output=True, check=True, text=True)
    assert result.stdout == "VERIFIED_SNAPSHOT_EXECUTED\n"
    path.chmod(0o600)
    path.write_bytes(b"raise RuntimeError('UNTRUSTED_EXECUTED')\n")
    path.chmod(0o400)
    result = subprocess.run(command[5:], capture_output=True, text=True)
    assert result.returncode != 0 and "UNTRUSTED_EXECUTED" not in result.stderr
    with pytest.raises(ValueError, match="UNIFIED_IMAGE_CHANGED"):
        image.verify()


@pytest.mark.parametrize("offset", [36, 44, 272])
def test_scope_rejects_hook_budget_or_release_change(offset):
    value, image = envelope()
    engine._validate_envelope(value, image, os.getuid(), os.getgid())
    changed = bytearray(value)
    changed[offset] ^= 3
    with pytest.raises(ValueError, match="UNIFIED_SCOPE"):
        engine._validate_envelope(bytes(changed), image, os.getuid(), os.getgid())


def test_policy_failure_precedes_install_or_handoff(monkeypatch):
    value, image = envelope()
    uid, gid = os.getuid(), os.getgid()
    identity = b"i" * 32
    approval = hashlib.sha256(engine.LABEL + value + identity + bytes(32)).hexdigest()
    monkeypatch.setenv("SUDO_UID", str(uid))
    monkeypatch.setenv("SUDO_GID", str(gid))
    monkeypatch.setenv("SUDO_USER", "fixture")
    for name in ("getuid", "geteuid", "getgid", "getegid"):
        monkeypatch.setattr(engine.os, name, lambda: 0)
    monkeypatch.setattr(engine, "_sudo_parent", lambda: bytes(32))

    def reject(*args):
        raise ValueError("UNIFIED_PASSWORD_POLICY_REJECTED")

    monkeypatch.setattr(engine, "_candidate_policy", reject)
    actions = []
    with pytest.raises(ValueError, match="PASSWORD_POLICY_REJECTED"):
        engine.unified_root_main(
            image,
            None,
            ["image", "run", str(uid), str(gid), value.hex(), identity.hex(), approval],
            {
                "_verify_dependencies": lambda _: None,
                "root_main": lambda *args: actions.append(args),
            },
        )
    assert actions == []


def test_cli_routes_once_without_old_authentication(monkeypatch):
    from soc_agent import cli
    from soc_agent.security_ai.ebpf_tc import unified_startup

    calls = []
    monkeypatch.setattr(unified_startup, "start", lambda directory: calls.append(directory) or 17)
    monkeypatch.setattr(
        cli, "terminal_authenticate", lambda **kwargs: pytest.fail("extra authentication")
    )
    assert cli.main(["start", "--gui", "--monitor", "total", "--collector", "ebpf-tcx"]) == 17
    assert calls == [None]


def test_same_broker_sequence_after_status_and_single_cleanup(tmp_path):
    from tests.unit.test_live_run_sequence import preparation

    from soc_agent.security_ai.ebpf_tc.live_run import start_live_run

    prep, commands, closes = preparation(tmp_path, 1)
    prep._os_handoff.origin = "TCX_UNIFIED_SESSION_NATIVE"
    start_live_run(prep)
    assert [c.sequence for c in commands] == [2]
    assert closes == ["closed"]


def test_c_authority_fd_cannot_be_forged_by_ordinary_controller(tmp_path):
    root = Path(__file__).parents[2] / "src/soc_agent/security_ai/ebpf_tc"
    source = tmp_path / "authority.c"
    source.write_text(
        '#define _GNU_SOURCE\n#include "unified.h"\n#include <unistd.h>\n'
        "#include <sys/mman.h>\n#include <fcntl.h>\n#include <errno.h>\n"
        "int soc_os_password_policy_only(unsigned u,unsigned g){(void)u;(void)g;return 0;}\n"
        "int main(void){if(!getuid())return 77;struct soc_unified_proof p={0};"
        'unsigned char z[32]={0};int f=memfd_create("forged",MFD_ALLOW_SEALING);'
        "if(f<0||ftruncate(f,sizeof(p))||fcntl(f,F_ADD_SEALS,15)<0||dup2(f,8)<0)return 3;"
        "return sizeof(p)==512 && "
        "soc_unified_proof_read(&p,getuid(),getgid(),z,z,z,z)==-EPERM?0:4;}\n"
    )
    executable = tmp_path / "authority"
    subprocess.run(
        [
            "cc",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-Wno-misleading-indentation",
            "-I" + str(root),
            str(source),
            *[
                str(root / name)
                for name in ("unified_proof.c", "core.c", "os.c", "trust.c", "handoff.c")
            ],
            "-lcrypto",
            "-o",
            str(executable),
        ],
        check=True,
        capture_output=True,
    )
    assert engine.PROOF.size == 512
    subprocess.run([str(executable)], check=True, timeout=5)
