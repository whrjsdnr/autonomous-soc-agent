"""Ordinary-UID static exec, policy and identity fixtures. No PAM/capability/kernel changes."""

import ctypes
import json
import os
import subprocess

import pytest

from soc_agent.security_ai.ebpf_tc.build import FLAGS, ROOT, compile_native
from soc_agent.security_ai.ebpf_tc.dependencies import elf_metadata
from soc_agent.security_ai.ebpf_tc.dynamic_trust import inspect_entry
from soc_agent.security_ai.ebpf_tc.installation import create_package, verify_package


@pytest.fixture(scope="module")
def candidate(tmp_path_factory):
    root = tmp_path_factory.mktemp("remediation")
    hashes = compile_native(root / "build")
    manifest = create_package(root / "build", root / "package", "0.2.9")
    return root, hashes, manifest


def test_entry_has_no_dynamic_loading_boundary(candidate):
    root, hashes, manifest = candidate
    entry = root / "build/entry"
    body = entry.read_bytes()
    assert inspect_entry(body)
    assert elf_metadata(body) == ((), None)
    assert manifest.payloads["entry"].sha256 == hashes["entry"]
    assert manifest.dynamic_trust.static_entry_sha256 == hashes["entry"]
    assert manifest.payloads["entry"].mode == 0o4755
    assert manifest.payloads["bootstrap"].mode == 0o555
    assert verify_package(root / "package", manifest.identity) == manifest
    result = subprocess.run([str(entry), "--inspect"], capture_output=True, timeout=3)
    assert result.returncode == 0 and b"STATIC_SYSCALL_ONLY" in result.stdout
    # Direct Native startup remains unconditionally closed, even with forged environment.
    result = subprocess.run(
        [str(entry)],
        env={"SOC_NATIVE_GATE": "1", "LD_AUDIT": "/not/a/module"},
        capture_output=True,
        timeout=3,
    )
    assert result.returncode == 2 and b"NATIVE_ENTRY_BLOCKED" in result.stderr


@pytest.mark.parametrize("kind", ["audit", "preload"])
def test_static_entry_avoids_premain_and_executes_dynamic_child_cleanly(candidate, tmp_path, kind):
    root, _, _ = candidate
    marker = tmp_path / "loaded"
    source = tmp_path / "module.c"
    callback = (
        "unsigned int la_version(unsigned int v) {mark();return v;}"
        if kind == "audit"
        else "__attribute__((constructor)) static void entered(void){mark();}"
    )
    source.write_text(
        "#include <fcntl.h>\n#include <unistd.h>\nstatic void mark(void){int fd=open("
        + json.dumps(str(marker))
        + ',O_WRONLY|O_CREAT|O_APPEND,0600);if(fd>=0){write(fd,"x",1);close(fd);}}\n'
        + callback
    )
    module = tmp_path / "module.so"
    subprocess.run(["cc", "-shared", "-fPIC", str(source), "-o", str(module)], check=True)
    env = {
        "PATH": "/usr/bin:/bin",
        "LANG": "C",
        "LD_AUDIT" if kind == "audit" else "LD_PRELOAD": str(module),
        "GLIBC_TUNABLES": "fixture",
        "LD_LIBRARY_PATH": str(tmp_path),
        "PYTHONPATH": str(tmp_path),
        "BASH_ENV": str(tmp_path / "bad"),
    }
    # Baseline: a dynamic ordinary-UID helper really executes the module before main.
    probe = subprocess.run(
        [str(root / "build/bootstrap"), "--inspect"], env=env, capture_output=True, timeout=3
    )
    assert probe.returncode == 0 and marker.read_text() == "x"
    marker.unlink()
    blocked = subprocess.run([str(root / "build/entry")], env=env, capture_output=True, timeout=3)
    assert blocked.returncode == 2 and not marker.exists()
    child_source = tmp_path / "child.c"
    child_source.write_text("""
#include <string.h>
#include <signal.h>
#include <unistd.h>
extern char **environ;
int main(void) {
    sigset_t mask;struct sigaction action;char cwd[8];
    if(sigprocmask(SIG_SETMASK,0,&mask) || sigismember(&mask,SIGALRM) ||
       sigaction(SIGINT,0,&action) || action.sa_handler!=SIG_DFL ||
       !getcwd(cwd,sizeof(cwd)) || strcmp(cwd,"/"))return 4;
    unsigned seen=0;
    for(unsigned i=0;i<3;i++) {
        if(!environ[i])return seen==3?0:3;
        unsigned flag=!strcmp(environ[i],"PATH=/usr/bin:/bin")?1:
            !strcmp(environ[i],"LANG=C")?2:0;
        if(!flag || (seen&flag))return 3;seen|=flag;
    }return 3;
}
""")
    child = tmp_path / "child"
    subprocess.run(["cc", str(child_source), "-o", str(child)], check=True)
    fixture = tmp_path / "static-fixture"
    subprocess.run(
        [
            "cc",
            *FLAGS,
            "-ffreestanding",
            "-fno-builtin",
            "-fno-stack-protector",
            "-fno-pie",
            "-no-pie",
            "-nostdlib",
            "-static",
            "-Wl,-z,noexecstack,--build-id=none",
            "-DSOC_ENTRY_FIXTURE_TARGET=" + json.dumps(str(child)),
            str(ROOT / "entry.c"),
            "-o",
            str(fixture),
        ],
        check=True,
    )
    assert inspect_entry(fixture.read_bytes())
    result = subprocess.run([str(fixture)], env=env, capture_output=True, timeout=3)
    assert result.returncode == 0 and not marker.exists()
    # The polluted dynamic parent executes one callback; neither static entry nor
    # its fresh child executes another. No privilege gain or PAM is involved.
    result = subprocess.run(
        [
            os.sys.executable,
            "-I",
            "-c",
            "import subprocess,sys;sys.exit(subprocess.run([sys.argv[1]]).returncode)",
            str(fixture),
        ],
        env=env,
        capture_output=True,
        timeout=5,
    )
    assert result.returncode == 0 and marker.read_text() == "x"
    marker.unlink()
    result = subprocess.run(
        [
            os.sys.executable,
            "-I",
            "-c",
            "import signal,subprocess,sys;"
            "signal.pthread_sigmask(signal.SIG_BLOCK,{signal.SIGALRM});"
            "signal.signal(signal.SIGINT,signal.SIG_IGN);"
            "sys.exit(subprocess.run([sys.argv[1]]).returncode)",
            str(fixture),
        ],
        env=env,
        capture_output=True,
        timeout=5,
    )
    assert result.returncode == 0 and marker.read_text() == "x"


@pytest.mark.parametrize("offset", [0, 8, 12, 16, 20, 24, 80, 375])
def test_entry_boundary_proof_is_numeric_process_and_envelope_bound(candidate, offset):
    library = ctypes.CDLL(str(candidate[0] / "build/libnative-tc.so"))
    fn = library.soc_entry_identity
    fn.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint, ctypes.c_uint, ctypes.c_int]
    import struct

    envelope = bytearray(352)
    struct.pack_into("<II", envelope, 4, 1000, 1000)
    proof = bytearray(struct.pack("<QIIII", 0x3130304945434F53, 1000, 1000, 1234, 0) + envelope)
    assert fn(bytes(proof), bytes(envelope), 1000, 1000, 1234) == 0
    proof[offset] ^= 1
    assert fn(bytes(proof), bytes(envelope), 1000, 1000, 1234) != 0
    assert fn(bytes(proof), bytes(envelope), 1000, 1000, 9999) != 0
    # Boundary proof cannot create PAM authorization or open the native gate.
    assert library.soc_native_gate() == 0
    assert library.soc_broker_privileges() != 0
    assert library.soc_work_privileges(1) != 0


@pytest.mark.parametrize("work", [0, 1])
@pytest.mark.parametrize(
    "mutation", [None, "effective", "permitted", "inheritable", "ambient", "bounding"]
)
def test_phase_scoped_capabilities_reject_missing_excess_and_exec_leakage(
    candidate, work, mutation
):
    library = ctypes.CDLL(str(candidate[0] / "build/libnative-tc.so"))
    fn = library.soc_broker_capability_contract
    fn.argtypes = [ctypes.c_uint64] * 5 + [ctypes.c_int]
    mask = (1 << 39) | (1 << 12)
    values = dict(
        effective=mask if work else 0, permitted=mask, inheritable=0, ambient=0, bounding=mask
    )
    if mutation:
        values[mutation] ^= 1 << 21  # SYS_ADMIN is never an accepted replacement/addition.
    assert (fn(*values.values(), work) == 0) is (mutation is None)


def test_nss_role_scope_keeps_missing_configuration_evidence_without_broker_name_authority(
    candidate,
):
    manifest = candidate[2]
    trust = manifest.dynamic_trust
    assert trust.nss.direct_identity_databases == ("passwd",)
    assert trust.nss.pam_account_databases == ("shadow",)
    assert "db" in trust.unresolved_nss_services and "nis" in trust.unresolved_nss_services
    assert "db" not in trust.unresolved_required_nss_services
    assert "nis" not in trust.unresolved_required_nss_services
    assert trust.unresolved_nss_databases["netgroup"] == ("nis",)
    assert trust.broker_nss_contract == "NO_DIRECT_NSS_IMPORTS_NUMERIC_AUTHORIZATION"
    assert not {"getpwuid_r", "getpwnam_r", "getgrgid_r", "pam_start"} & set(
        trust.elf["broker"].imports
    )
    assert {"getpwuid_r", "getpwnam_r", "pam_authenticate", "pam_acct_mgmt"} <= set(
        trust.elf["bootstrap"].imports
    )
    assert trust.runtime_closure.startswith("BLOCKED") and manifest.native_release == "BLOCKED"
    source = (ROOT / "bootstrap.c").read_text()
    assert "getgrgid_r" not in source and "getgrnam_r" not in source
    assert source.index("soc_entry_proof_check(&envelope)") < source.index("if(soc_password")
    assert "close(SOC_ENTRY_PROOF_FD)" in source
    # Existing held-Link-FD cleanup must not depend on entry/PAM/manifest verification.
    assert "soc_entry_proof_check" not in (ROOT / "tcx.c").read_text()
    assert "soc_release_check" not in (ROOT / "tcx.c").read_text()


@pytest.mark.parametrize("work", [-1, 2, 99])
def test_unknown_privilege_phase_is_not_a_scope_upgrade(candidate, work):
    library = ctypes.CDLL(str(candidate[0] / "build/libnative-tc.so"))
    fn = library.soc_broker_capability_contract
    fn.argtypes = [ctypes.c_uint64] * 5 + [ctypes.c_int]
    mask = (1 << 39) | (1 << 12)
    assert fn(mask, mask, 0, 0, mask, work) != 0


@pytest.mark.parametrize("offset", [16, 18, 4])
def test_static_entry_wrong_elf_type_machine_and_class_rejected(candidate, offset):
    body = bytearray((candidate[0] / "build/entry").read_bytes())
    body[offset] ^= 1
    try:
        accepted = inspect_entry(bytes(body))
    except ValueError:
        accepted = False
    assert not accepted
