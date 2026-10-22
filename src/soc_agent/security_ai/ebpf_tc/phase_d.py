"""Prepare-only Phase D release; execute requires separate exact-image approval."""

import hashlib
import json
import os
from pathlib import Path

from soc_agent.security_ai.collectors import offload_session
from soc_agent.security_ai.ebpf_tc import supervisor_startup
from soc_agent.security_ai.ebpf_tc.installation import canonical, verify_package
from soc_agent.security_ai.ebpf_tc.supervisor import SupervisorImage, prepare_supervisor_image
from soc_agent.security_ai.ebpf_tc.unified_image import UnifiedImage
from soc_agent.security_ai.ebpf_tc.unified_startup import prepare_candidate

DNS_BASELINE_IMAGE = "a2ad9ecccb569f185323f78d62a4cf7fc805a9670a84e4b0d4e35e34ab571e39"
SCOPE = dict(
    namespace="net:[4026531833]",
    interface="lo",
    hook="INGRESS",
    duration=300,
    events=4096,
    queue=32,
    address_space_mib=256,
    cpu_seconds=20,
)
DNS_SCOPE = dict(
    namespace="net:[4026531833]",
    interface="lo",
    capture_seconds=7,
    max_seconds=10,
    records=32,
    snaplen=512,
    target="127.0.0.53:53",
    qname="native-0516.localhost.",
    qtype="A",
    udp_queries=1,
    tcp_queries=1,
)


def runtime_bundle():
    result = offload_session.sources()
    root = Path(__file__).parent.parent
    result["soc_agent.security_ai.native_campaign"] = hashlib.sha256(
        (root / "native_campaign.py").read_bytes()
    ).hexdigest()
    for package in ("ebpf", "ebpf_tc", "ebpf_broker"):
        for path in sorted((root / package).glob("*.py")):
            name = "soc_agent.security_ai." + package + "." + path.stem
            result[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def prepare(directory: Path) -> dict:
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    _, _, package, manifest = prepare_candidate(directory, version="0.6.1", inspector=True)
    image = prepare_supervisor_image(
        package, manifest, directory / "supervisor-image.py", dns_sidecar=True
    )
    (directory / "supervisor-image.json").write_text(image.model_dump_json(indent=2) + "\n")
    sidecar = directory / "dns-sidecar"
    sidecar.mkdir(mode=0o700)
    base = UnifiedImage.model_validate(
        {k: v for k, v in image.model_dump(mode="json").items() if k in UnifiedImage.model_fields}
    )
    dns = dict(
        contract="soc-dns-analysis-sidecar-release:v1",
        version="0.6.1_INTEGRATED_DNS_0520",
        base_manifest=manifest,
        image=base.model_dump(mode="json"),
        sources=offload_session.sources(),
        bundle_digest=hashlib.sha256(canonical(offload_session.sources())).hexdigest(),
        capture_scope_digest=hashlib.sha256(
            b"DNS_LOCAL_PARTIAL_COPY_V4:net4026531833:lo:7s:32:512:prewarm:shared10s:tty:seqpacket"
        ).hexdigest(),
        scope=DNS_SCOPE,
    )
    offload_session.publish(sidecar / "release.json", dns)
    release = verify_package(package, manifest)
    value = dict(
        contract="SOC_PHASE_D_UNIFIED_V1",
        version="0.6.1",
        tcx_manifest=manifest,
        tcx_program=release.payloads["tc.bpf.o"].sha256,
        dns_baseline_image=DNS_BASELINE_IMAGE,
        image=image.sha256,
        dns_manifest=hashlib.sha256(canonical(dns)).hexdigest(),
        bundle=hashlib.sha256(canonical(runtime_bundle())).hexdigest(),
        sources=runtime_bundle(),
        collectors=["TCX_KERNEL_METADATA", "DNS_PARTIAL_ANALYSIS_COPY"],
        capabilities=dict(
            inspector=["CAP_SYS_ADMIN"],
            broker=["CAP_BPF", "CAP_NET_ADMIN"],
            dns_pre_bind=["CAP_NET_RAW", "CAP_SETUID", "CAP_SETGID"],
            dns_post_bind="E_P_I_A_ZERO_BOUNDING_PRE_BIND_MASK_NO_NEW_PRIVS",
            gui="ZERO",
        ),
        scope=SCOPE,
        native_ai="BLOCKED",
        dns9="BLOCKED",
        operational_promotion="BLOCKED",
    )
    offload_session.publish(directory / "phase-d.json", value)
    return dict(
        manifest=hashlib.sha256(canonical(value)).hexdigest(),
        bundle=value["bundle"],
        image=image.sha256,
        tcx_manifest=manifest,
    )


def validate(directory: Path, manifest: str, image_sha: str) -> dict:
    body = (directory / "phase-d.json").read_bytes()
    value = json.loads(body)
    image = SupervisorImage.model_validate_json((directory / "supervisor-image.json").read_bytes())
    image.verify()
    if (
        hashlib.sha256(body).hexdigest() != manifest
        or value["image"] != image_sha
        or image.sha256 != image_sha
        or not image.dns_sidecar
        or value["sources"] != runtime_bundle()
        or value["bundle"] != hashlib.sha256(canonical(runtime_bundle())).hexdigest()
        or value["contract"] != "SOC_PHASE_D_UNIFIED_V1"
        or value["scope"] != SCOPE
        or any(value[k] != "BLOCKED" for k in ("native_ai", "dns9", "operational_promotion"))
    ):
        raise ValueError("PHASE_D_RELEASE_OR_SOURCE_MISMATCH")
    release = verify_package(directory / "release", value["tcx_manifest"])
    dns_body = (directory / "dns-sidecar/release.json").read_bytes()
    dns = json.loads(dns_body)
    if (
        hashlib.sha256(dns_body).hexdigest() != value["dns_manifest"]
        or dns["base_manifest"] != release.identity
        or dns["image"]["sha256"] != image_sha
        or dns["sources"] != offload_session.sources()
        or dns["scope"] != DNS_SCOPE
        or value["dns_baseline_image"] != DNS_BASELINE_IMAGE
        or release.payloads["tc.bpf.o"].sha256 != value["tcx_program"]
        or os.readlink("/proc/self/ns/net") != value["scope"]["namespace"]
    ):
        raise ValueError("PHASE_D_COLLECTOR_SCOPE_MISMATCH")
    return value


def execute(directory: Path, manifest: str, image_sha: str, *, gui=False):
    value = validate(directory, manifest, image_sha)  # No auth before the complete contract.
    return supervisor_startup.execute(
        directory, value["tcx_manifest"], image_sha, gui=gui, phase_d=value
    )


def main():
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--manifest")
    parser.add_argument("--image")
    parser.add_argument("--gui", action="store_true")
    parser.add_argument("--campaign", type=Path)
    parser.add_argument("--approval-file", type=Path)
    parser.add_argument("--approval-sha")
    args = parser.parse_args()
    if args.execute:
        if not all(
            (args.manifest, args.image, args.campaign, args.approval_file, args.approval_sha)
        ):
            parser.error("execution requires exact release, campaign and explicit approval receipt")
        from soc_agent.security_ai.native_campaign import execute_phase_d

        print(
            execute_phase_d(
                args.directory,
                args.manifest,
                args.image,
                campaign=args.campaign,
                approval_file=args.approval_file,
                approval_sha=args.approval_sha,
                gui=args.gui,
            )
        )
    else:
        print(json.dumps(prepare(args.directory), indent=2))


if __name__ == "__main__":
    main()
