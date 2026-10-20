"""Static ELF and ordinary-UID mapped-library fixtures. No authentication/load/hook."""

import ctypes
import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from soc_agent.security_ai.ebpf_tc.build import ROOT, compile_native
from soc_agent.security_ai.ebpf_tc.dependencies import elf_metadata, read_held
from soc_agent.security_ai.ebpf_tc.dynamic_trust import elf_identity, nss_policy
from soc_agent.security_ai.ebpf_tc.installation import (
    ReleaseManifest,
    canonical,
    create_package,
    verify_package,
)
from soc_agent.security_ai.ebpf_tc.trust import execution_manifest


@pytest.fixture(scope="module")
def release(tmp_path_factory):
    directory = tmp_path_factory.mktemp("dynamic-trust")
    compile_native(directory / "build")
    manifest = create_package(directory / "build", directory / "package", "0.2.8")
    library = ctypes.CDLL(str(directory / "build/libnative-tc.so"))
    library.soc_account_identity.argtypes = [ctypes.c_uint] * 4 + [ctypes.c_int]
    library.soc_mapped_dependencies.argtypes = [ctypes.c_char_p, ctypes.c_size_t]
    return directory, manifest, library


def repackage(path, value):
    """An attacker can recompute ordinary-UID hashes, never root ownership/admission."""
    manifest = ReleaseManifest.model_validate(value)
    for name, body in (
        ("release.json", canonical(value)),
        ("release.trust", execution_manifest(manifest)),
    ):
        file = path / name
        file.chmod(0o644)
        file.write_bytes(body)
        file.chmod(0o444)
    return manifest.identity


def test_actual_elf_graph_pam_nss_and_explicit_missing_modules(release):
    directory, manifest, _ = release
    assert verify_package(directory / "package", manifest.identity) == manifest
    trust = manifest.dynamic_trust
    assert len(manifest.dependencies) >= 15
    assert set(trust.elf) == {"bootstrap", "broker", "libnative-tc.so"}
    assert all(x.bind_now and x.relro and x.executable_stack is False for x in trust.elf.values())
    assert {"getpwuid_r", "getpwnam_r", "pam_authenticate", "pam_acct_mgmt"} <= set(
        trust.elf["bootstrap"].imports
    )
    assert "libnative-tc.so" not in trust.elf["bootstrap"].needed
    assert trust.pam_modules == ("/usr/lib/x86_64-linux-gnu/security/pam_unix.so",)
    assert any("libnss_systemd" in name for name in trust.nss_modules)
    assert trust.runtime_closure.startswith("BLOCKED") and trust.native_release == "BLOCKED"
    assert "db" in trust.nss.services and "nis" in trust.nss.services
    paths = {d.path for d in manifest.dependencies}
    assert set(trust.pam_modules + trust.nss_modules) <= paths
    for dep in manifest.dependencies:
        assert (
            dep.mode & 0o022 == 0
            and dep.sha256 == hashlib.sha256(read_held(Path(dep.path), owner=0)).hexdigest()
        )


@pytest.mark.parametrize(
    "body",
    [
        b"",
        b"passwd: files\n",
        b"passwd: /tmp/x\ngroup: files\nshadow: files",
        b"passwd: files\npasswd: systemd\ngroup: files\nshadow: files",
        b"passwd: files [WHAT=maybe]\ngroup: files\nshadow: files",
        b"passwd: files\x00\ngroup: files\nshadow: files",
        b"x" * 16385,
    ],
)
def test_malformed_nss_policy_is_not_a_successful_lookup(body):
    with pytest.raises(ValueError):
        nss_policy(body)


def test_nss_order_actions_preserved_not_reimplemented():
    value = nss_policy(b"passwd: files [NOTFOUND=return] systemd\ngroup: files\nshadow: files\n")
    assert value.databases["passwd"] == ("files", "[NOTFOUND=return]", "systemd")
    assert value.source == "STATIC_CONFIG_NOT_LOOKUP"


@pytest.mark.parametrize(
    "observed_uid,observed_gid,found",
    [
        (0, 1000, 1),
        (1000, 0, 1),
        (9999, 1000, 1),
        (1000, 9999, 1),
        (1000, 1000, 0),
        (1000, 1000, -1),
        (1000, 1000, 2),
    ],
)
def test_c_lookup_failure_and_uid_gid_mismatch_never_authenticate(
    release, observed_uid, observed_gid, found
):
    fn = release[2].soc_account_identity
    assert fn(1000, 1000, 1000, 1000, 1) == 0
    assert fn(1000, 1000, observed_uid, observed_gid, found) != 0
    assert fn(0, 0, 0, 0, 1) != 0


@pytest.mark.parametrize("field", ["needed", "interpreter", "imports", "soname"])
def test_recomputed_manifest_still_rejects_elf_metadata_forgery(release, tmp_path, field):
    directory, manifest, _ = release
    target = tmp_path / "package"
    shutil.copytree(directory / "package", target)
    value = manifest.model_dump(mode="json")
    value["dynamic_trust"]["elf"]["bootstrap"][field] = {
        "needed": ["libevil.so"],
        "interpreter": "/tmp/evil",
        "imports": ["evil"],
        "soname": "evil.so",
    }[field]
    expected = repackage(target, value)
    with pytest.raises(ValueError, match="DYNAMIC_TRUST_MISMATCH"):
        verify_package(target, expected)


@pytest.mark.parametrize("field", ["pam_modules", "nss_modules", "unresolved_nss_services"])
def test_module_identity_cannot_be_changed_by_editing_manifest(release, tmp_path, field):
    directory, manifest, _ = release
    target = tmp_path / "package"
    shutil.copytree(directory / "package", target)
    value = manifest.model_dump(mode="json")
    value["dynamic_trust"][field] = ["/usr/lib/evil.so"]
    expected = repackage(target, value)
    with pytest.raises(ValueError, match="DYNAMIC_TRUST_MISMATCH"):
        verify_package(target, expected)


@pytest.mark.parametrize("tag", ["rpath", "runpath", "interpreter"])
def test_real_compiled_elf_rejects_loader_injection_without_execution(tmp_path, tag):
    source = tmp_path / "x.c"
    source.write_text("int main(void){return 0;}\n")
    target = tmp_path / "x"
    flags = {
        "rpath": ["-Wl,--disable-new-dtags,-rpath,/tmp/evil"],
        "runpath": ["-Wl,--enable-new-dtags,-rpath,$ORIGIN"],
        "interpreter": ["-Wl,--dynamic-linker,/tmp/evil"],
    }[tag]
    subprocess.run(["cc", str(source), *flags, "-o", str(target)], check=True, timeout=30)
    with pytest.raises(ValueError, match="SEARCH_PATH|INTERPRETER"):
        elf_metadata(target.read_bytes())


@pytest.mark.parametrize(
    "variable",
    [
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "LD_AUDIT",
        "LD_DEBUG",
        "PYTHONPATH",
        "PATH",
        "LOCPATH",
        "OPENSSL_CONF",
    ],
)
def test_static_inspector_cleans_environment_and_uses_sealed_bytes(release, monkeypatch, variable):
    directory, _, _ = release
    original = subprocess.run
    observed = []

    def inspect(*args, **kwargs):
        observed.append(kwargs["env"])
        assert variable not in kwargs["env"] or kwargs["env"][variable] != "/tmp/evil"
        assert args[0][0] == "/usr/bin/readelf" and kwargs["pass_fds"]
        return original(*args, **kwargs)

    monkeypatch.setenv(variable, "/tmp/evil")
    monkeypatch.setattr(subprocess, "run", inspect)
    elf_identity((directory / "build/bootstrap").read_bytes())
    assert observed and all(e == {"PATH": "/usr/bin:/bin", "LANG": "C"} for e in observed)


def test_c_mapped_image_check_rejects_python_and_unmanifested_libraries(release):
    _, manifest, library = release
    body = execution_manifest(manifest)
    # Python itself and extension DSOs are not the fixed Native executable release.
    # This is a real read-only dl_iterate_phdr/proc-maps rejection, not Native execution.
    assert library.soc_mapped_dependencies(body, len(body)) != 0
    assert library.soc_native_gate() == 0


def test_c_mapping_probe_system_and_foreign_dsos(release, tmp_path):
    directory, manifest, _ = release
    source = tmp_path / "mapping.c"
    source.write_text("""
#include "native.h"
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>
#include <stdlib.h>
extern char **environ;
int main(int argc,char **argv) {
    if(argc==4 && !strcmp(argv[3],"clean")) {
        char *args[]={argv[0],argv[1],"unused","verify",NULL};
        int self=open("/proc/self/exe",O_RDONLY);
        fexecve(self,args,soc_clean_environment());return 4;
    }
    if(argc==4 && !strcmp(argv[3],"verify")) {
        if(soc_environment_contract(environ))return 6;argc=2;
    }
    if(argc==4) {
        int fd=-1;
        if(!strcmp(argv[3],"memfd")) {fd=memfd_create("fixture",0);ftruncate(fd,4096);}
        else if(!strcmp(argv[3],"deleted")) {
            char file[]="/tmp/soc-mapping-XXXXXX";fd=mkstemp(file);unlink(file);ftruncate(fd,4096);
        }
        void *map=mmap(NULL,4096,PROT_READ|PROT_EXEC,
            fd<0?MAP_PRIVATE|MAP_ANONYMOUS:MAP_PRIVATE,fd,0);
        if(map==MAP_FAILED)return 5;argc=2;
    }
    unsigned char body[232+72*304];if(argc!=2)return 2;
    int fd=open(argv[1],O_RDONLY);if(fd<0)return 2;
    ssize_t n=read(fd,body,sizeof(body));close(fd);
    return n>0 && !soc_mapped_dependencies(body,n)?0:3;
}
""")
    executable = tmp_path / "mapping-probe"
    # A standalone read-only fixture, no broker, PAM or kernel entry call.
    subprocess.run(
        [
            "cc",
            "-I" + str(ROOT),
            str(source),
            str(ROOT / "trust.c"),
            str(ROOT / "core.c"),
            str(ROOT / "os.c"),
            "-lcrypto",
            "-o",
            str(executable),
        ],
        check=True,
        timeout=30,
    )
    descriptor = directory / "package/release.trust"
    env = {"PATH": "/usr/bin:/bin", "LANG": "C"}
    result = subprocess.run([str(executable), str(descriptor)], env=env, timeout=3)
    assert result.returncode == 0
    library_source = tmp_path / "foreign.c"
    library_source.write_text("int soc_foreign_marker(void){return 1;}\n")
    foreign = tmp_path / "foreign.so"
    subprocess.run(["cc", "-shared", "-fPIC", str(library_source), "-o", str(foreign)], check=True)
    for variable in ("LD_PRELOAD", "LD_AUDIT"):
        result = subprocess.run(
            [str(executable), str(descriptor)],
            env=env | {variable: str(foreign)},
            capture_output=True,
            timeout=3,
        )
        # An invalid audit module can be discarded by ld.so; rejection is only
        # evidence if a foreign DSO actually remains mapped. No setuid claim.
        if variable == "LD_PRELOAD":
            assert result.returncode == 3
    # A real audit namespace can be invisible to dl_iterate_phdr's base namespace.
    # Process-wide executable maps must reject it; pre-main execution still happened.
    marker = tmp_path / "audit-loaded"
    audit_source = tmp_path / "audit.c"
    audit_source.write_text(
        "#include <fcntl.h>\n#include <unistd.h>\n"
        "unsigned int la_version(unsigned int v) {"
        "int fd=open(" + json.dumps(str(marker)) + ",O_WRONLY|O_CREAT|O_EXCL,0600);"
        'if(fd>=0){write(fd,"fixture",7);close(fd);}return v;}\n'
    )
    audit = tmp_path / "audit.so"
    subprocess.run(["cc", "-shared", "-fPIC", str(audit_source), "-o", str(audit)], check=True)
    result = subprocess.run(
        [str(executable), str(descriptor)],
        env=env | {"LD_AUDIT": str(audit)},
        capture_output=True,
        timeout=3,
    )
    assert marker.read_text() == "fixture" and result.returncode == 3
    # A NEW exec with the production fixed env does not load the parent audit DSO.
    # The polluted parent's pre-main execution still happens: never a prevention claim.
    marker.unlink()
    clean = subprocess.run(
        [str(executable), str(descriptor), "unused", "clean"],
        env=env | {"LD_AUDIT": str(audit)},
        capture_output=True,
        timeout=3,
    )
    assert marker.read_text() == "fixture" and clean.returncode == 0
    # Parent before-main constructors are not undone: the clean child is isolated.
    preload_marker = tmp_path / "preload-loaded"
    library_source.write_text(
        "#include <fcntl.h>\n#include <unistd.h>\n"
        "__attribute__((constructor)) static void entered(void){"
        "int fd=open(" + json.dumps(str(preload_marker)) + ",O_WRONLY|O_CREAT|O_EXCL,0600);"
        'if(fd>=0){write(fd,"fixture",7);close(fd);}}\n'
    )
    subprocess.run(["cc", "-shared", "-fPIC", str(library_source), "-o", str(foreign)], check=True)
    clean = subprocess.run(
        [str(executable), str(descriptor), "unused", "clean"],
        env=env | {"LD_PRELOAD": str(foreign)},
        capture_output=True,
        timeout=3,
    )
    assert preload_marker.read_text() == "fixture" and clean.returncode == 0
    pollution = {
        name: "fixture"
        for name in (
            "LD_LIBRARY_PATH",
            "GLIBC_TUNABLES",
            "LD_BIND_NOW",
            "LD_ORIGIN_PATH",
            "LD_PROFILE",
            "PYTHONPATH",
            "PYTHONHOME",
            "BASH_ENV",
            "ENV",
        )
    }
    clean = subprocess.run(
        [str(executable), str(descriptor), "unused", "clean"],
        env=env | pollution,
        capture_output=True,
        timeout=3,
    )
    assert clean.returncode == 0
    for mode in ("anonymous", "memfd", "deleted"):
        rejected = subprocess.run(
            [str(executable), str(descriptor), "unused", mode], env=env, timeout=3
        )
        assert rejected.returncode == 3, mode
    target = os.environ.get("SOC_AUDIT_NAMESPACE_EVIDENCE")
    if target:
        Path(target).write_text(
            json.dumps(
                {
                    "source": "ORDINARY_UID_NO_AUTH_NO_KERNEL",
                    "audit_module_executed": True,
                    "process_wide_verifier_exit": result.returncode,
                    "parent_pre_main_execution_blocked": False,
                    "sanitized_exec_child_exit": clean.returncode,
                    "rejected_executable_mappings": ["anonymous", "memfd", "deleted"],
                    "complete_dynamic_loader_trust": "BLOCKED",
                    "native_authentication": False,
                    "native_release": "BLOCKED",
                },
                indent=2,
            )
        )


def test_source_enforces_pam_scope_and_mapping_checks_before_authentication():
    source = (ROOT / "bootstrap.c").read_text()
    assert "getauxval(AT_SECURE)!=1" in source
    assert "getpwuid_r" in source and "getpwnam_r" in source
    assert "soc_account_identity" in source
    assert source.index("soc_release_check(p,") < source.index("pam_start(")
    assert source.index("if(rc==PAM_SUCCESS && soc_release_check") < source.index(
        "pam_authenticate("
    )
    assert (
        b"/usr/lib/x86_64-linux-gnu/security/pam_unix.so" in (ROOT / "pam-policy.conf").read_bytes()
    )
    assert "soc_mapped_dependencies(body,descriptor_size)" in (ROOT / "trust.c").read_text()
    assert "soc_release_check" not in (ROOT / "tcx.c").read_text()  # owned-FD cleanup unaffected
    assert "B2A_CLOSED" in (ROOT / "bridge.py").read_text()


@pytest.mark.parametrize("index", range(7))
def test_saved_root_ids_supplementary_groups_cannot_cross_broker_boundary(release, index):
    fn = release[2].soc_process_identity
    fn.argtypes = [ctypes.c_uint] * 6 + [ctypes.c_int]
    values = [1000] * 6 + [0]
    assert fn(*values) == 0
    values[index] = 0 if index < 6 else 1
    assert fn(*values) != 0


@pytest.mark.parametrize("role", ["pam", "nss"])
def test_missing_pam_or_nss_module_never_becomes_runtime_verified(release, monkeypatch, role):
    from soc_agent.security_ai.ebpf_tc import dependencies
    from soc_agent.security_ai.ebpf_tc.dynamic_trust import dependency_trust

    directory, manifest, _ = release
    bodies = {n: (directory / "package" / n).read_bytes() for n in manifest.payloads}
    original = dependencies._library

    def lookup(name):
        if (role == "pam" and name == "security/pam_unix.so") or (
            role == "nss" and name == "libnss_systemd.so.2"
        ):
            raise ValueError("DEPENDENCY_UNRESOLVED")
        return original(name)

    monkeypatch.setattr(dependencies, "_library", lookup)
    if role == "pam":
        with pytest.raises(ValueError, match="UNRESOLVED"):
            dependency_trust(bodies, manifest.dependencies)
    else:
        trust = dependency_trust(bodies, manifest.dependencies)
        assert "systemd" in trust.unresolved_nss_services and trust.native_release == "BLOCKED"


def test_dependency_replacement_and_transitive_metadata_are_rejected(release, tmp_path):
    directory, manifest, _ = release
    target = tmp_path / "package"
    shutil.copytree(directory / "package", target)
    value = manifest.model_dump(mode="json")
    value["dependencies"][0]["needed"] = ["libforged.so"]
    expected = repackage(target, value)
    with pytest.raises(ValueError, match="CLOSURE_MISMATCH"):
        verify_package(target, expected)


@pytest.mark.parametrize(
    "variable",
    [
        "LD_AUDIT",
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "LD_DEBUG",
        "LD_PROFILE",
        "LD_ORIGIN_PATH",
        "LD_BIND_NOW",
        "GLIBC_TUNABLES",
        "PYTHONPATH",
        "PYTHONHOME",
        "BASH_ENV",
        "ENV",
        "HOME",
        "LC_ALL",
    ],
)
def test_fixed_exec_environment_rejects_inherited_variables(release, variable):
    library = release[2]
    library.soc_environment_contract.argtypes = [ctypes.POINTER(ctypes.c_char_p)]
    clean = (ctypes.c_char_p * 3)(b"PATH=/usr/bin:/bin", b"LANG=C", None)
    assert library.soc_environment_contract(clean) == 0
    polluted = (ctypes.c_char_p * 4)(clean[0], clean[1], (variable + "=fixture").encode(), None)
    assert library.soc_environment_contract(polluted) != 0


@pytest.mark.parametrize(
    "values",
    [
        [],
        [b"LANG=C"],
        [b"LANG=C", b"LANG=C"],
        [b"PATH=.", b"LANG=C"],
        [b"PATH=/usr/bin:/bin", b"LANG=en_US"],
    ],
)
def test_environment_missing_duplicate_and_mutated_values(release, values):
    array = (ctypes.c_char_p * (len(values) + 1))(*values, None)
    assert release[2].soc_environment_contract(array) != 0


def test_nss_database_scope_never_silently_excludes_missing_unused_module(release):
    trust = release[1].dynamic_trust
    assert trust.nss.direct_identity_databases == ("passwd", "group")
    assert trust.nss.pam_account_databases == ("shadow", "gshadow")
    assert trust.nss.scope_policy == "ALL_CONFIGURED_NO_IMPLICIT_EXCLUSION"
    assert trust.nss_exclusion_policy == "UNUSED_BY_DIRECT_CODE_IS_NOT_PROOF_UNUSED_BY_PAM"
    assert trust.environment_contract == "NEW_EXEC_FIXED_PATH_LANG_ONLY_AT_SECURE_ENTRY_REQUIRED"
    assert trust.mapping_contract == "PROCESS_WIDE_EXECUTABLE_SNAPSHOT_NOT_EXECUTION_HISTORY"
    source = (ROOT / "bootstrap.c").read_text()
    assert "getgrgid_r" in source and "getgrnam_r" in source
    assert "group_named->gr_gid!=p->gid" in source
    assert "fexecve(7,args,soc_clean_environment())" in source
    for name in ("broker.c", "loader.c"):
        assert "soc_environment_contract(environ)" in (ROOT / name).read_text()


@pytest.mark.parametrize(
    "field", ["environment_contract", "mapping_contract", "nss_exclusion_policy"]
)
def test_manifest_cannot_claim_a_weaker_exec_or_nss_contract(release, field):
    value = release[1].model_dump(mode="json")
    value["dynamic_trust"][field] = "VERIFIED_OR_IGNORE"
    with pytest.raises(ValueError):
        ReleaseManifest.model_validate(value)


def test_recomputed_manifest_cannot_erase_missing_database_evidence(release, tmp_path):
    directory, manifest, _ = release
    target = tmp_path / "package"
    shutil.copytree(directory / "package", target)
    value = manifest.model_dump(mode="json")
    value["dynamic_trust"]["unresolved_nss_databases"] = {"passwd": ["forged"]}
    expected = repackage(target, value)
    with pytest.raises(ValueError, match="DYNAMIC_TRUST_MISMATCH"):
        verify_package(target, expected)
