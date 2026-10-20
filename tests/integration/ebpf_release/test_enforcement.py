"""Ordinary-UID adversarial C/Python execution-schema fixtures. Never PAM/BPF/capset."""

import ctypes
import hashlib
import json
import os
import subprocess

import pytest
from tests.ebpf_broker_support import plan as broker_plan

from soc_agent.security_ai.ebpf_tc.build import ROOT, compile_native
from soc_agent.security_ai.ebpf_tc.contracts import NativePlan
from soc_agent.security_ai.ebpf_tc.installation import create_package, verify_package
from soc_agent.security_ai.ebpf_tc.journal import RC_ROW, recover_native
from soc_agent.security_ai.ebpf_tc.trust import (
    ENVELOPE_SIZE,
    HEADER,
    candidate_snapshot,
    execution_manifest,
    release_approval,
)


@pytest.fixture(scope="module")
def release(tmp_path_factory):
    directory = tmp_path_factory.mktemp("b2f-c-fixture")
    compile_native(directory / "build")
    manifest = create_package(directory / "build", directory / "package", "0.2.6")
    broker = broker_plan()
    scope = broker.application.scope.model_copy(
        update={"program_sha256": manifest.payloads["tc.bpf.o"].sha256}
    )
    broker = broker.model_copy(
        update={"application": broker.application.model_copy(update={"scope": scope})}
    )
    plan = NativePlan(
        broker=broker,
        bootstrap_sha256=manifest.payloads["bootstrap"].sha256,
        native_broker_sha256=manifest.payloads["broker"].sha256,
        loader_sha256=manifest.payloads["libnative-tc.so"].sha256,
        program_sha256=manifest.payloads["tc.bpf.o"].sha256,
        bundle_digest=manifest.bundle_digest,
        mode="B2D_TCX_BLOCKED",
    )
    library = ctypes.CDLL(str(directory / "build/libnative-tc.so"))
    library.soc_trust_parse.argtypes = [
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_char_p,
    ]
    library.soc_envelope_validate.argtypes = [ctypes.c_char_p]
    library.soc_capability_contract.argtypes = [ctypes.c_uint64] * 5
    return directory, manifest, plan, library


def parse(release, body):
    _, manifest, plan, library = release
    return library.soc_trust_parse(
        body,
        len(body),
        plan.wire(),
        bytes.fromhex(manifest.identity),
        manifest.version.encode().ljust(16, b"\0"),
    )


def test_strict_json_and_c_execution_schema_agree(release):
    directory, manifest, plan, library = release
    assert verify_package(directory / "package", manifest.identity) == manifest
    body = execution_manifest(manifest)
    assert len(body) <= 232 + 72 * 304 and parse(release, body) == 0
    envelope = release_approval(plan, manifest)
    assert len(envelope) == ENVELOPE_SIZE and library.soc_envelope_validate(envelope) == 0
    assert envelope[-32:] == hashlib.sha256(envelope[:-32] + bytes(32)).digest()
    assert not library.soc_native_gate()


@pytest.mark.parametrize("offset", [0, 8, 12, 16, 20, 24, 56, 88, 120, 152, 184, 216, 232])
def test_c_rejects_manifest_schema_hash_version_gate_or_path_tampering(release, offset):
    body = bytearray(execution_manifest(release[1]))
    body[offset] ^= 0xFF
    assert parse(release, bytes(body)) != 0


@pytest.mark.parametrize(
    "offset",
    [0, 4, 8, 16, 24, 32, 36, 40, 44, 48, 52, 56, 64, 80, 112, 144, 176, 208, 240, 272, 304, 320],
)
def test_approval_envelope_binds_every_scope_and_release_field(release, offset):
    _, manifest, plan, library = release
    body = bytearray(release_approval(plan, manifest))
    body[offset] ^= 1
    assert library.soc_envelope_validate(bytes(body)) != 0


@pytest.mark.parametrize("size", [0, 1, 231, 232, 233, 65536])
def test_c_rejects_truncated_or_oversized_execution_schema(release, size):
    body = execution_manifest(release[1])
    assert parse(release, body[:size] if size < len(body) else body + bytes(size)) != 0


@pytest.mark.parametrize("set_index", range(5))
@pytest.mark.parametrize("extra", [False, True])
def test_c_all_five_capability_sets_are_exact(release, set_index, extra):
    library = release[3]
    mask = (1 << 39) | (1 << 12)
    values = [mask] * 5
    assert library.soc_capability_contract(*values) == 0
    values[set_index] = mask | (1 << 21) if extra else mask & ~(1 << 39)
    assert library.soc_capability_contract(*values) != 0


@pytest.mark.parametrize(
    "path",
    [b"/tmp/evil.so", b"/usr/lib/../evil", b"/etc/passwd", b"/usr/lib//evil", b"/usr/lib/./evil"],
)
def test_dependency_and_configuration_path_allowlist(release, path):
    body = bytearray(execution_manifest(release[1]))
    body[HEADER.size : HEADER.size + 256] = path.ljust(256, b"\0")
    assert parse(release, bytes(body)) != 0


def test_native_entrypoints_enforce_release_and_do_not_offer_runtime_override(release):
    directory, _, _, library = release
    # The public root verifier has no configurable path, owner, environment or gate input.
    library.soc_release_check.argtypes = [
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_int,
    ]
    assert (
        library.soc_release_check(release[2].wire(), bytes(32), b"0.2.6".ljust(16, b"\0"), 1) != 0
    )
    for name in ("bootstrap", "broker"):
        result = subprocess.run(
            [str(directory / "build" / name)],
            capture_output=True,
            env={"PATH": "/does-not-exist", "PYTHONPATH": "/tmp/untrusted", "SOC_NATIVE_GATE": "1"},
            timeout=3,
        )
        assert result.returncode == 2 and b"NATIVE_EXECUTION_BLOCKED" in result.stderr
    source = (ROOT / "bootstrap.c").read_text()
    assert source.index("soc_release_check") < source.index("if(soc_password")
    assert "fexecve(7,args,env)" in source and "clearenv()" in source
    assert "release.trust" in (ROOT / "trust.c").read_text()
    for name in ("broker.c", "loader.c"):
        assert "soc_release_check" in (ROOT / name).read_text()
    assert "system(" not in (ROOT / "trust.c").read_text()


def test_tampered_execution_manifest_is_not_just_preparation_metadata(release, tmp_path):
    import shutil

    directory, manifest, _, _ = release
    package = tmp_path / "package"
    shutil.copytree(directory / "package", package)
    file = package / "release.trust"
    file.chmod(0o644)
    file.write_bytes(file.read_bytes()[:-1])
    with pytest.raises(ValueError, match="EXECUTION_MANIFEST_MISMATCH"):
        verify_package(package, manifest.identity)


def test_release_digest_audit_is_append_only_claim_and_never_restores_authority(release, tmp_path):
    _, manifest, plan, _ = release
    owner = (
        bytes.fromhex(manifest.identity)
        + b"0.2.6".ljust(16, b"\0")
        + hashlib.sha256(plan.wire()).digest()
    )
    body = RC_ROW.pack(
        bytes.fromhex(plan.approval),
        b"RC_RELEASE_VERIFIED".ljust(32, b"\0"),
        owner,
        0,
        1,
        bytes(32),
        bytes(32),
    )
    body = body[:-32] + hashlib.sha256(body[:-32]).digest()
    path = tmp_path / "journal"
    path.write_bytes(body)
    before = path.read_bytes()
    result = recover_native(path, plan.approval)
    assert result["release_manifest_digest"] == manifest.identity
    assert not result["authentication_restored"] and not result["automatic_attach"]
    assert not result["automatic_inference"] and path.read_bytes() == before
    path.write_bytes(body + body)
    with pytest.raises(ValueError, match="INTEGRITY"):
        recover_native(path, plan.approval)


def test_manifest_and_candidate_never_grant_native_authority(release):
    manifest = release[1]
    value = json.loads((release[0] / "package/release.json").read_text())
    value["native_release"] = "VERIFIED"
    with pytest.raises(ValueError):
        type(manifest).model_validate(value)
    candidate = candidate_snapshot(manifest.identity)
    assert candidate["native_release"] == "BLOCKED" and not candidate["automatic_attach"]
    assert os.getuid() != 0


@pytest.mark.parametrize("field", ["path", "sha256", "mode", "size"])
def test_system_configuration_is_anchored_in_json_and_execution_manifest(release, tmp_path, field):
    import shutil

    from soc_agent.security_ai.ebpf_tc.installation import canonical

    directory, manifest, _, _ = release
    target = tmp_path / "config-package"
    shutil.copytree(directory / "package", target)
    value = manifest.model_dump(mode="json")
    item = value["system_configuration"][0]
    item[field] = {
        "path": "/tmp/evil",
        "sha256": "f" * 64,
        "mode": 0o666,
        "size": item["size"] + 1,
    }[field]
    body = canonical(value)
    file = target / "release.json"
    file.chmod(0o644)
    file.write_bytes(body)
    with pytest.raises(ValueError):
        verify_package(target, hashlib.sha256(body).hexdigest())


def test_approval_cannot_retarget_program_release_or_application(release):
    _, manifest, plan, library = release
    with pytest.raises(ValueError, match="SCOPE_MISMATCH"):
        release_approval(plan.model_copy(update={"bundle_digest": "f" * 64}), manifest)
    other = plan.model_copy(update={"broker": plan.broker.model_copy(update={"uid": 9999})})
    with pytest.raises(ValueError, match="UID_MISMATCH"):
        release_approval(other, manifest)
    from uuid import uuid4

    application = plan.broker.application.model_copy(update={"application_session": uuid4()})
    other = plan.model_copy(
        update={"broker": plan.broker.model_copy(update={"application": application})}
    )
    assert release_approval(other, manifest) != release_approval(plan, manifest)
    original = bytearray(release_approval(plan, manifest))
    original[272] ^= 1
    # Recomputing the outer approval alone cannot make a manifest match a different digest.
    original[-32:] = hashlib.sha256(original[:-32] + bytes(32)).digest()
    assert library.soc_envelope_validate(bytes(original)) == 0
    assert (
        library.soc_release_check(
            plan.wire(), bytes(original[272:304]), b"0.2.6".ljust(16, b"\0"), 2
        )
        != 0
    )


def test_actual_c_journal_writer_decodes_without_restoring_authority(release, tmp_path):
    directory, manifest, plan, _ = release
    source = tmp_path / "journal-fixture.c"
    source.write_text("""
#include "native.h"
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
int main(int argc,char **argv) {
    if(argc!=3)return 2;
    struct soc_release_envelope envelope;
    int input=open(argv[1],O_RDONLY);if(input<0)return 2;
    int ok=read(input,&envelope,sizeof(envelope))==sizeof(envelope);close(input);
    if(!ok || soc_envelope_validate(&envelope))return 2;
    struct soc_state state={0};state.plan=envelope.plan;
    memcpy(state.release_sha,envelope.manifest_sha,32);
    memcpy(state.release_version,envelope.release_version,16);
    state.audit_fd=open(argv[2],O_WRONLY|O_CREAT|O_EXCL|O_APPEND,0600);
    if(state.audit_fd<0)return 2;
    int rc=soc_release_record(&state);close(state.audit_fd);
    return rc || state.audit_records!=1;
}
""")
    executable = tmp_path / "journal-fixture"
    build = directory / "build"
    subprocess.run(
        [
            "cc",
            "-I" + str(ROOT),
            str(source),
            "-L" + str(build),
            "-lnative-tc",
            "-Wl,-rpath," + str(build),
            "-o",
            str(executable),
        ],
        check=True,
        timeout=30,
    )
    envelope = tmp_path / "approval.bin"
    envelope.write_bytes(release_approval(plan, manifest))
    journal = tmp_path / "journal.bin"
    subprocess.run([str(executable), str(envelope), str(journal)], check=True, timeout=3)
    result = recover_native(journal, plan.approval)
    assert journal.stat().st_size == 216 and result["records"] == 1
    assert result["release_manifest_digest"] == manifest.identity
    assert not result["authentication_restored"] and result["native_ai"] == "BLOCKED"
