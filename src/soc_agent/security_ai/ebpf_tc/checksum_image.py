"""Prepare diagnostic-only image using the existing SHA-pinned sudo entry.

Preparation never authenticates, installs, captures, loads BPF, or sends traffic.
"""

import ast
import hashlib
import json
import os
from pathlib import Path

from soc_agent.security_ai.collectors import checksum_evidence
from soc_agent.security_ai.ebpf_tc import install_engine, unified_image_engine
from soc_agent.security_ai.ebpf_tc.dependencies import read_held
from soc_agent.security_ai.ebpf_tc.install_image import payload_from_release
from soc_agent.security_ai.ebpf_tc.unified_image import UnifiedImage, installed_release

ENTRY = """
def checksum_root_main():
    import sys, resource
    root_entry_started = time.monotonic()
    global diagnostic_stage, diagnostic_api
    diagnostic_stage, diagnostic_api = "ROOT_ENTRY", "credential_checks"
    args = sys.argv
    if (len(args) != 7 or args[1] != 'run'
            or any((os.getuid(), os.geteuid(), os.getgid(), os.getegid()))):
        raise ValueError('CHECKSUM_ROOT_ENTRY_REQUIRED')
    uid, gid = int(args[2]), int(args[3])
    if (os.environ.get('SUDO_UID'), os.environ.get('SUDO_GID')) != (str(uid), str(gid)):
        raise ValueError('CHECKSUM_CALLER_MISMATCH')
    envelope, image_sha, approval = map(bytes.fromhex, args[4:7])
    expected = hashlib.sha256(
        LABEL + envelope + image_sha + bytes.fromhex(IMAGE['manifest_sha256'])).digest()
    if len(image_sha) != 32 or expected != approval:
        raise ValueError('CHECKSUM_APPROVAL_MISMATCH')
    diagnostic_stage, diagnostic_api = "SCOPE_VERIFY", "_validate_envelope"
    _validate_envelope(envelope, IMAGE, uid, gid)
    pid = struct.unpack_from('<I', envelope, 12)[0]
    ticks, namespace = struct.unpack_from('<QQ', envelope, 16)
    if (os.stat(f'/proc/{pid}').st_uid != uid or _ticks(pid) != ticks
            or namespace != 4026531833
            or os.stat(f'/proc/{pid}/ns/net').st_ino != namespace
            or os.stat('/proc/self/ns/net').st_ino != namespace):
        raise ValueError('CHECKSUM_CONTROLLER_IDENTITY')
    diagnostic_stage, diagnostic_api = "OS_ENTRY_VERIFY", "_sudo_parent"
    _sudo_parent()
    environment = _safe_environment(uid, gid)
    diagnostic_stage, diagnostic_api = "DEPENDENCY_VERIFY", "_verify_dependencies"
    _verify_dependencies(IMAGE)
    diagnostic_stage, diagnostic_api = "INSTALLATION_VERIFY", "root_main(check)"
    root_main(IMAGE, 'check')
    diagnostic_stage, diagnostic_api = "PASSWORD_POLICY", "_candidate_policy"
    _candidate_policy(IMAGE, uid, gid, environment)
    os.environ.clear()
    os.environ.update(environment)
    diagnostic_stage, diagnostic_api = "RESOURCE_LIMITS", "setrlimit"
    resource.setrlimit(resource.RLIMIT_AS, (256 * 1024**2, 256 * 1024**2))
    resource.setrlimit(resource.RLIMIT_CPU, (20, 20))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    diagnostic_stage, diagnostic_api = "CAPTURE_PREPARE", "capture"
    start_context = (dict(controller_pid=pid, binding=start_binding(
        envelope, args[5], IMAGE["manifest_sha256"], args[6], SCOPE_DIGEST))
        if "start_binding" in globals() else None)
    result = (capture(uid, gid, session_started=root_entry_started, start_context=start_context)
              if 'capture_analysis' in globals() else capture(uid, gid))
    result.update(image_sha256=args[5], manifest=IMAGE['manifest_sha256'],
                  scope_digest=SCOPE_DIGEST)
    if 'emit_result' in globals():
        emit_result(result)
    else:
        print(json.dumps(result, sort_keys=True), flush=True)

def checksum_dispatch():
    import sys
    if 'root_error' not in globals():
        checksum_root_main()
    else:
        try:
            checksum_root_main()
        except Exception as exc:
            emit_result(root_error(exc, globals().get('diagnostic_stage', 'ROOT_ENTRY'),
                                   globals().get('diagnostic_api', 'checksum_root_main')))
            print('DNS_COPY_ROOT_ERROR', file=sys.stderr, flush=True)
            sys.exit(1)

if __name__ == '__main__':
    checksum_dispatch()
"""


def prepare(output: Path, *, analysis: bool = False) -> UnifiedImage:
    release = installed_release()
    if release is None or release.version != "0.5.16":
        raise ValueError("CHECKSUM_INSTALLED_0516_REQUIRED")
    image = payload_from_release(Path("/usr/libexec/soc-agent-ebpf"), release)
    for path in (Path("/usr/bin/python3").resolve(strict=True), Path("/usr/bin/sudo")):
        body = read_held(path, owner=0, limit=64 * 1024**2)
        image["dependencies"].append(
            dict(
                path=str(path),
                sha256=hashlib.sha256(body).hexdigest(),
                mode=path.stat().st_mode & 0o7777,
            )
        )
    source = b"\n".join(
        Path(module.__file__).read_bytes()
        for module in (install_engine, unified_image_engine, checksum_evidence)
    )
    if analysis:
        from soc_agent.security_ai.collectors import offload_copy, start_channel
        from soc_agent.security_ai.ebpf_tc import dns_copy_engine

        source += b"\n" + Path(offload_copy.__file__).read_bytes()
        source += b"\n" + Path(start_channel.__file__).read_bytes()
        source += b"\n" + Path(dns_copy_engine.__file__).read_bytes()
        source += (
            b"\nSCOPE_DIGEST = hashlib.sha256("
            b"b'DNS_LOCAL_PARTIAL_COPY_V4:net4026531833:lo:7s:32:512:prewarm:shared10s:tty:seqpacket').hexdigest()\n"
            b"\ndef capture(uid, gid, session_started=None, start_context=None):\n"
            b"    return capture_analysis(uid, gid, attach_filter,\n"
            b"                            restrict_process, analysis_copy, chain_receipt,\n"
            b"                            SCOPE_DIGEST, start_gate=True,\n"
            b"                            session_started=session_started,\n"
            b"                            start_context=start_context)\n"
        )
    if analysis:
        tree = ast.parse(source.decode() + "\n" + ENTRY)
        codes = sorted(
            {
                node.exc.args[0].value
                for node in ast.walk(tree)
                if isinstance(node, ast.Raise)
                and isinstance(node.exc, ast.Call)
                and node.exc.args
                and isinstance(node.exc.args[0], ast.Constant)
                and isinstance(node.exc.args[0].value, str)
            }
        )
        source += b"\nROOT_ERROR_CODES = frozenset(" + repr(codes).encode() + b")\n"
    source += (
        b"\nIMAGE = json.loads("
        + repr(json.dumps(image, sort_keys=True)).encode()
        + b")\n"
        + ENTRY.encode()
    )
    compile(source, "<checksum-diagnostic-candidate>", "exec")
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(source)
        stream.flush()
        os.fsync(stream.fileno())
    return UnifiedImage(
        path=output.absolute(),
        sha256=hashlib.sha256(source).hexdigest(),
        manifest=release.identity,
        previous_manifest=release.identity,
        version=release.version,
        action="DNS_ANALYSIS_COPY_NO_INSTALL" if analysis else "CHECKSUM_CAPTURE_ONLY_NO_INSTALL",
    )
