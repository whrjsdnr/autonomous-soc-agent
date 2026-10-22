"""Single approved local DNS capture -> in-memory copies -> existing Zeek pipeline.

Preparation is read-only/unprivileged. execute() requires exact new image/manifest
approval and a real terminal. No TCX, installs, traffic retries, or global policy.
"""

import base64
import hashlib
import json
import os
import struct
import subprocess
import threading
import time
from pathlib import Path

from soc_agent.security_ai.collectors.analysis_feed import AnalysisFeed
from soc_agent.security_ai.collectors.live_contract import bundle, new_plan
from soc_agent.security_ai.collectors.live_process import StreamProcess
from soc_agent.security_ai.collectors.live_stream import Stream, decode
from soc_agent.security_ai.collectors.models import Source
from soc_agent.security_ai.collectors.offline import IMAGE, OfflineZeek
from soc_agent.security_ai.collectors.offload_copy import analysis_copy, chain_receipt
from soc_agent.security_ai.ebpf_broker.contracts import BrokerPlan
from soc_agent.security_ai.ebpf_native.contracts import ApplicationPlan, Scope, local_controller
from soc_agent.security_ai.ebpf_tc.checksum_image import prepare as prepare_image
from soc_agent.security_ai.ebpf_tc.contracts import NativePlan
from soc_agent.security_ai.ebpf_tc.dependencies import read_held
from soc_agent.security_ai.ebpf_tc.installation import canonical
from soc_agent.security_ai.ebpf_tc.trust import release_approval
from soc_agent.security_ai.ebpf_tc.unified_image import (
    UnifiedImage,
    installed_release,
    pinned_command,
)
from soc_agent.security_ai.ebpf_tc.unified_image_engine import LABEL

PROBE_SHA = "1b466afcb1fbaf0b5d9a56744640140ef07389342537f5d1bbb9245a2e403f8f"
PROBE_APPROVAL = "0b6c59f501489f67da18e5a7f671b80853542376a8df7a2b0495cd9fbdeb5757"


def sources() -> dict[str, str]:
    from soc_agent.security_ai.collectors import analysis_feed, checksum_evidence, offload_copy
    from soc_agent.security_ai.ebpf_tc import checksum_image, dns_copy_engine

    result = bundle()
    for module in (analysis_feed, checksum_evidence, offload_copy, checksum_image, dns_copy_engine):
        result[module.__name__] = hashlib.sha256(Path(module.__file__).read_bytes()).hexdigest()
    result["soc_agent.security_ai.collectors.offload_session"] = hashlib.sha256(
        Path(__file__).read_bytes()
    ).hexdigest()
    return result


def publish(path: Path, value: dict) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(canonical(value))
        stream.flush()
        os.fsync(stream.fileno())


def prepare(directory: Path) -> dict:
    local_controller()
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    image = prepare_image(directory / "capture-image.py", analysis=True)
    source = sources()
    value = dict(
        contract="soc-dns-analysis-sidecar-release:v1",
        version="0.5.19",
        installed_tcx_release="0.5.16_PRESERVED_NO_INSTALL",
        base_manifest=image.manifest,
        image=image.model_dump(mode="json"),
        bundle_digest=hashlib.sha256(canonical(source)).hexdigest(),
        sources=source,
        zeek_image=IMAGE,
        capture_scope_digest=hashlib.sha256(
            b"DNS_LOCAL_PARTIAL_COPY_V3:net4026531833:lo:7s:32:512:prewarm:shared10s"
        ).hexdigest(),
        scope=dict(
            namespace="net:[4026531833]",
            interface="lo",
            ifindex=1,
            capture_seconds=7,
            max_seconds=10,
            records=32,
            snaplen=512,
            target="127.0.0.53:53",
            qname="native-0516.localhost.",
            qtype="A",
            udp_queries=1,
            tcp_queries=1,
            raw_payload_persistence=False,
        ),
        transformation="KERNEL_PARTIAL_AND_SEED_MATCH_ONLY_ANALYSIS_COPY",
        native_ai="BLOCKED",
        dns9="BLOCKED",
        operational_promotion="BLOCKED",
    )
    publish(directory / "release.json", value)
    return dict(
        manifest=hashlib.sha256(canonical(value)).hexdigest(),
        bundle=value["bundle_digest"],
        image=image.sha256,
        version=value["version"],
    )


def envelope(release) -> bytes:
    controller = local_controller()
    scope = Scope(
        ifindex=1,
        net_namespace="net:[4026531833]",
        hook="INGRESS",
        program_sha256=release.payloads["tc.bpf.o"].sha256,
        loader_sha256=release.payloads["libnative-tc.so"].sha256,
        bundle_digest=release.bundle_digest,
    )
    application = ApplicationPlan(controller=controller, scope=scope, mode="PHASE_A_FIXTURE")
    broker = BrokerPlan(
        application=application,
        uid=os.getuid(),
        gid=os.getgid(),
        broker_sha256=release.payloads["broker"].sha256,
        bundle_digest=release.bundle_digest,
    )
    plan = NativePlan(
        broker=broker,
        bootstrap_sha256=release.payloads["bootstrap"].sha256,
        native_broker_sha256=release.payloads["broker"].sha256,
        loader_sha256=scope.loader_sha256,
        program_sha256=scope.program_sha256,
        bundle_digest=release.bundle_digest,
        mode="B2D_TCX_BLOCKED",
    )
    return release_approval(plan, release)


def verify_frame(row: dict) -> bytes | None:
    """Independently reconstruct original bytes from the two-byte copy change."""
    receipt = row["receipt"]
    if "analysis_frame" not in row:
        if receipt["analysis_sha256"] is not None:
            raise ValueError("DNS_COPY_REJECTION_HAS_ANALYSIS_DIGEST")
        return None
    packet = base64.b64decode(row["analysis_frame"], validate=True)
    if not 20 <= len(packet) <= 512 or receipt["status"] not in {
        "CHECKSUM_VALID",
        "CHECKSUM_PARTIAL_CONFIRMED",
    }:
        raise ValueError("DNS_COPY_FRAME_BOUND_OR_STATUS")
    if packet[0] >> 4 != 4:
        raise ValueError("DNS_COPY_NATIVE_IPV4_SCOPE")
    ihl = (packet[0] & 15) * 4
    offset = ihl + (6 if packet[9] == 17 else 16)
    if ihl < 20 or offset + 2 > len(packet):
        raise ValueError("DNS_COPY_FRAME_OFFSET")
    original = (
        packet[:offset] + struct.pack("!H", receipt["original_checksum"]) + packet[offset + 2 :]
    )
    result = analysis_copy(original, bytes.fromhex(row["auxiliary_hex"]))
    if result.receipt() != receipt or result.packet != packet:
        raise ValueError("DNS_COPY_TRANSFORM_DIGEST_MISMATCH")
    return packet


def execute(directory: Path, manifest_sha: str, image_sha: str, *, probe: Path) -> dict:
    """Only invoke after new SHA and two-query traffic approval; never auto-retry."""
    local_controller()
    body = read_held(directory / "release.json", owner=os.getuid(), limit=65536)
    if hashlib.sha256(body).hexdigest() != manifest_sha:
        raise ValueError("DNS_COPY_MANIFEST_MISMATCH")
    candidate = json.loads(body)
    image = UnifiedImage.model_validate(candidate["image"])
    image.verify()
    if image.sha256 != image_sha or candidate["sources"] != sources():
        raise ValueError("DNS_COPY_IMAGE_OR_SOURCE_CHANGED")
    release = installed_release()
    if release.identity != candidate["base_manifest"]:
        raise ValueError("DNS_COPY_BASE_RELEASE_CHANGED")
    if (
        os.readlink("/proc/self/ns/net") != "net:[4026531833]"
        or not os.isatty(0)
        or not os.isatty(2)
    ):
        raise ValueError("DNS_COPY_NAMESPACE_OR_TERMINAL")
    probe_body = read_held(probe.absolute(), owner=os.getuid(), limit=16384)
    if hashlib.sha256(probe_body).hexdigest() != PROBE_SHA:
        raise ValueError("DNS_COPY_PROBE_SHA")
    OfflineZeek().environment()  # Read-only Docker image lookup, before authentication.
    listeners = subprocess.run(
        ["/usr/bin/ss", "-lnut", "sport = :53"],
        capture_output=True,
        text=True,
        check=True,
        timeout=2,
    )
    if not all(text in listeners.stdout for text in ("127.0.0.53", "tcp", "udp")):
        raise ValueError("DNS_COPY_EXISTING_LOCAL_SERVICE_REQUIRED")
    out = directory / "live-attempt-1"
    out.mkdir(mode=0o700, exist_ok=False)  # Failed attempts cannot silently repeat.
    wire = envelope(release)
    approval = hashlib.sha256(
        LABEL + wire + bytes.fromhex(image.sha256) + bytes.fromhex(image.manifest)
    ).hexdigest()
    command = pinned_command(image, wire, approval, os.getuid(), os.getgid())
    publish(
        out / "reserved.json",
        dict(manifest=manifest_sha, image=image_sha, auto_retry=False, scope=candidate["scope"]),
    )
    child = None
    feed = AnalysisFeed()
    analysis_worker = None
    runner = None
    stream = None
    analysis_errors: list[BaseException] = []
    zeek_ready = threading.Event()
    times: dict[str, float] = {}

    def analyze():
        try:

            def accept(line):
                message = decode(line)
                stream.accept(message)
                if message.kind == "ready":
                    zeek_ready.set()

            runner.run(on_line=accept)
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            analysis_errors.append(exc)
            zeek_ready.set()  # Wake the controller to report the failure, not READY.

    received = accepted = rejected = 0
    probe_ports: set[tuple[int, int]] = set()
    excluded = 0
    chain = "0" * 64
    authenticated = ready = closed = None
    active_started = active_deadline = None
    first_failure = None
    try:
        child = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        with (out / "transformations.jsonl").open("x") as audit:
            while line := child.stdout.readline(4097):
                if len(line) > 4096 or not line.endswith("\n"):
                    raise ValueError("DNS_COPY_MESSAGE_BOUND")
                row = json.loads(line)
                if row.get("state") == "DNS_COPY_AUTHENTICATED":
                    if authenticated or row["scope_digest"] != candidate["capture_scope_digest"]:
                        raise ValueError("DNS_COPY_AUTHENTICATED_SCOPE")
                    authenticated = row
                    active_started = row["session_started"]
                    active_deadline = row["deadline"]
                    if (
                        not 0 < active_deadline - time.monotonic() <= 10
                        or active_deadline - active_started != 10
                    ):
                        raise ValueError("DNS_COPY_SESSION_DEADLINE")
                    times["authenticated"] = active_started
                    plan = new_plan()
                    source = Source(
                        session_id=plan.session_id,
                        source_digest=manifest_sha,
                        origin="ZEEK_NATIVE_LIVE",
                        capture_integrity="UNVERIFIED",
                    )
                    stream = Stream(source)
                    zeek = out / "zeek"
                    zeek.mkdir(mode=0o700)
                    runner = StreamProcess(
                        zeek, plan, analysis_feed=feed, analysis_deadline=active_deadline - 0.5
                    )
                    analysis_worker = threading.Thread(target=analyze, name="bounded-zeek-analysis")
                    analysis_worker.start()
                    if not zeek_ready.wait(max(0, active_deadline - time.monotonic() - 0.75)):
                        raise ValueError("DNS_COPY_ZEEK_READY_DEADLINE")
                    if analysis_errors:
                        raise analysis_errors[0]
                    times["zeek_ready"] = time.monotonic()
                    child.stdin.write("START\n")
                    child.stdin.flush()
                    child.stdin.close()
                elif row.get("state") == "DNS_COPY_READY":
                    if (
                        not authenticated
                        or ready
                        or set(row["capabilities"]) != {"CapEff", "CapPrm", "CapInh", "CapAmb"}
                        or any(row["capabilities"].values())
                        or row["scope_digest"] != candidate["capture_scope_digest"]
                    ):
                        raise ValueError("DNS_COPY_DUPLICATE_READY_OR_CAPABILITIES")
                    ready = row
                    times["capture_ready"] = time.monotonic()
                    # Execute the SHA-held probe snapshot, not a reopened mutable path.
                    result = subprocess.run(
                        [
                            "/usr/bin/python3",
                            "-I",
                            "-S",
                            "-c",
                            probe_body.decode(),
                            "--execute",
                            "--approve",
                            PROBE_APPROVAL,
                            "--receipt",
                            str(out / "probe.json"),
                        ],
                        capture_output=True,
                        text=True,
                        timeout=8,
                    )
                    publish(
                        out / "probe-process.json",
                        dict(
                            returncode=result.returncode,
                            stdout=result.stdout,
                            stderr=result.stderr,
                            invocations=1,
                        ),
                    )
                    if result.returncode:
                        first_failure = "DNS_COPY_PROBE_FAILED"
                    else:
                        receipt = json.loads((out / "probe.json").read_text())
                        if receipt["state"] != "COMPLETED" or len(receipt["records"]) != 2:
                            raise ValueError("DNS_COPY_PROBE_RECEIPT")
                        for test in receipt["records"]:
                            if test["source"][0] != "127.0.0.1" or test["destination"] != [
                                "127.0.0.53",
                                53,
                            ]:
                                raise ValueError("DNS_COPY_PROBE_ENDPOINT")
                            probe_ports.add(
                                (17 if test["transport"] == "UDP" else 6, test["source"][1])
                            )
                elif row.get("state") == "DNS_COPY_PACKET":
                    if not ready or closed or row["sequence"] != received + 1 or received >= 32:
                        raise ValueError("DNS_COPY_SEQUENCE")
                    packet = verify_frame(row)
                    chain = chain_receipt(chain, row)
                    if row["chain"] != chain:
                        raise ValueError("DNS_COPY_CHAIN_MISMATCH")
                    received += 1
                    if packet is not None:
                        accepted += 1
                        ihl = (packet[0] & 15) * 4
                        source_port, target_port = struct.unpack("!HH", packet[ihl : ihl + 4])
                        client_port = target_port if source_port == 53 else source_port
                        if (packet[9], client_port) in probe_ports:
                            feed.put(row["timestamp_ns"], packet)
                        else:
                            excluded += 1
                    else:
                        rejected += 1
                    row.pop("analysis_frame", None)  # Raw bytes must never be persisted.
                    audit.write(json.dumps(row, sort_keys=True) + "\n")
                    audit.flush()
                    os.fsync(audit.fileno())
                elif row.get("state") == "CLOSED":
                    if closed:
                        raise ValueError("DNS_COPY_DUPLICATE_CLOSED")
                    closed = row
                    times["capture_closed_received"] = time.monotonic()
                    feed.close()
                elif row.get("state") == "DNS_COPY_ERROR":
                    publish(out / "capture-error.json", row)
                    first_failure = first_failure or "DNS_COPY_CAPTURE_FAILED"
                elif row.get("action") != "check":
                    raise ValueError("DNS_COPY_MESSAGE_SCHEMA")
        code = child.wait(timeout=12)
        if (
            code
            or not closed
            or not ready
            or closed.get("image_sha256") != image_sha
            or closed.get("manifest") != candidate["base_manifest"]
            or closed.get("scope_digest") != candidate["capture_scope_digest"]
            or (closed["received"], closed["accepted"], closed["rejected"], closed["final_chain"])
            != (received, accepted, rejected, chain)
        ):
            raise ValueError(first_failure or "DNS_COPY_TERMINAL_MISMATCH")
        publish(out / "capture-closed.json", closed)
        if first_failure:
            raise ValueError(first_failure)
        feed.close()
        analysis_worker.join(timeout=max(0, active_deadline - time.monotonic()))
        if analysis_worker.is_alive():
            raise ValueError("DNS_COPY_ANALYSIS_JOIN_DEADLINE")
        if analysis_errors:
            raise analysis_errors[0]
        times["analysis_cleanup_complete"] = time.monotonic()
        result = dict(
            source="NATIVE_AUXDATA_CAPTURE_ANALYSIS_COPY",
            forwarded_probe_packets=feed.count,
            queue_peak=feed.peak,
            phase_times=times,
            zeek_phase_times=runner.phase_times,
            other_local_dns_excluded=excluded,
            capture_accounting_consistent=(
                closed["socket_packets"] == received
                and closed["socket_drops"] == 0
                and rejected == 0
            ),
            capture=closed,
            dns=stream.dns_preprocessing.snapshot(),
            stream=stream.diagnostics(),
            zeek_exit=json.loads((zeek / "exit.json").read_text()),
            capture_integrity="PARTIAL_PROVENANCE_NOT_END_TO_END_PAYLOAD_ATTESTATION",
            native_ai="BLOCKED",
            dns9="BLOCKED",
            operational_promotion="BLOCKED",
        )
        stages = stream.dns_stages
        dns_complete = (
            stages is not None
            and stages.query_parsed == 2
            and stages.response_parsed == 2
            and stages.transaction_matched == 2
            and stages.transport_checksum_rejected == 0
            and stream.dns_count == 2
            and stream.dns_adapter_rejected == 0
        )
        result["active_elapsed_seconds"] = time.monotonic() - active_started
        result["active_time_budget_met"] = result["active_elapsed_seconds"] <= 10
        result["verdict"] = (
            "DNS_NATIVE_ANALYSIS_COPY_E2E_VERIFIED"
            if dns_complete
            and result["active_time_budget_met"]
            and result["capture_accounting_consistent"]
            and result["zeek_exit"]["cleanup_verified"]
            and result["zeek_exit"]["protocol_finalized"]
            else "DNS_NATIVE_ANALYSIS_COPY_E2E_INCOMPLETE"
        )
    except (OSError, ValueError, EOFError, subprocess.SubprocessError) as exc:
        publish(
            out / "failure.json",
            dict(
                code=type(exc).__name__,
                detail=str(exc),
                errno=getattr(exc, "errno", None),
                first_failure=first_failure,
                auto_retry=False,
            ),
        )
        raise
    finally:
        feed.close()
        if analysis_worker is not None and analysis_worker.is_alive():
            runner.stop()
            analysis_worker.join(timeout=12)
        feed.clear()  # Memory-only analysis copies, no raw PCAP path.
        times["finalization_started"] = time.monotonic()
        if child is not None:
            child.stdout.close()
            if not child.stdin.closed:
                child.stdin.close()
            # Closing the pipe ends a failed sender; do not start another capture.
            try:
                code = child.wait(timeout=12)
                publish(
                    out / "capture-process-exit.json", dict(pid=child.pid, code=code, exited=True)
                )
            except subprocess.TimeoutExpired:
                publish(
                    out / "capture-process-exit.json",
                    dict(pid=child.pid, exited=False, cleanup="UNVERIFIED"),
                )
        if runner is not None:
            try:
                publish(out / "container-timing.json", runner.analysis_container_timing())
            except (OSError, ValueError, subprocess.SubprocessError) as exc:
                publish(
                    out / "container-timing.json",
                    dict(
                        verified=False, code=type(exc).__name__, errno=getattr(exc, "errno", None)
                    ),
                )
        times["cleanup_complete"] = time.monotonic()
        publish(
            out / "session-timing.json",
            dict(
                phase_times=times,
                zeek_phase_times=runner.phase_times if runner else {},
                active_elapsed_seconds=time.monotonic() - active_started
                if active_started
                else None,
                whole_deadline_met=time.monotonic() <= active_deadline
                if active_deadline
                else False,
                worker_exited=analysis_worker is None or not analysis_worker.is_alive(),
                queue_peak=feed.peak,
                forwarded_probe_packets=feed.count,
            ),
        )
    # Final qualification is after socket/process/worker cleanup, not before finally.
    result["active_elapsed_seconds"] = time.monotonic() - active_started
    result["active_time_budget_met"] = time.monotonic() <= active_deadline
    result["capture_time_budget_met"] = closed["capture_elapsed_seconds"] <= 7
    if not result["active_time_budget_met"] or not result["capture_time_budget_met"]:
        result["verdict"] = "DNS_NATIVE_ANALYSIS_COPY_E2E_INCOMPLETE"
    publish(out / "completion.json", result)
    if time.monotonic() > active_deadline:
        publish(
            out / "deadline-failure.json",
            dict(
                code="DNS_COPY_ACTIVE_SESSION_DEADLINE",
                actual_elapsed_seconds=time.monotonic() - active_started,
                auto_retry=False,
            ),
        )
        raise ValueError("DNS_COPY_ACTIVE_SESSION_DEADLINE")
    return result


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--manifest")
    parser.add_argument("--image")
    parser.add_argument("--probe", type=Path)
    args = parser.parse_args()
    if not args.execute:
        print(json.dumps(prepare(args.directory), indent=2))
        return
    if not args.manifest or not args.image or args.probe is None:
        parser.error("execution needs approved --manifest --image --probe")
    print(
        json.dumps(execute(args.directory, args.manifest, args.image, probe=args.probe), indent=2)
    )


if __name__ == "__main__":
    main()
