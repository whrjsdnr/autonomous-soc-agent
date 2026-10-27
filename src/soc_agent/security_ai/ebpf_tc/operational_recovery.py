"""CLI/Supervisor preparation projection over existing validators; no second executor."""

import argparse
import json
import subprocess
from pathlib import Path

from soc_agent.security_ai.ebpf_tc import phase_d
from soc_agent.security_ai.ebpf_tc.installation import verify_package
from soc_agent.security_ai.ebpf_tc.r2_diagnostic import LaunchApproval, R2Launcher
from soc_agent.security_ai.ebpf_tc.reassessment_admission import (
    ReassessedCampaign,
    preview_reservation,
)
from soc_agent.security_ai.ebpf_tc.recovery_policy import validate_image_recovery
from soc_agent.security_ai.ebpf_tc.supervisor import SupervisorImage


def source_git_identity() -> tuple[str, str]:
    root = Path(__file__).parents[4]
    result = subprocess.run(
        ["/usr/bin/git", "rev-parse", "HEAD", "HEAD^{tree}"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
        timeout=5,
    ).stdout.splitlines()
    if len(result) != 2:
        raise ValueError("OPERATIONAL_GIT_IDENTITY")
    return result[0], result[1]


def readiness(
    directory: Path,
    manifest: str,
    image: str,
    *,
    campaign: Path | None = None,
    amendment_file: Path | None = None,
    amendment_sha: str | None = None,
    approval_file: Path | None = None,
    approval_sha: str | None = None,
    traffic_file: Path | None = None,
    traffic_sha: str | None = None,
    claim_file: Path | None = None,
    management_file: Path | None = None,
    management_sha: str | None = None,
) -> dict:
    """Non-consuming current readiness, never permission for later unchecked use."""
    states = {
        name: "BLOCKED"
        for name in (
            "SOURCE_VERIFIED",
            "RUNTIME_VERIFIED",
            "POLICY_APPROVED",
            "R1_REASSESSMENT_VERIFIED",
            "R2_SCOPE_APPROVED",
            "ROOT_INSTALL_APPROVED",
            "NATIVE_EXECUTION_APPROVED",
        )
    }
    try:
        value = phase_d.validate(directory, manifest, image)
        states["SOURCE_VERIFIED"] = states["RUNTIME_VERIFIED"] = "VERIFIED"
        descriptor = SupervisorImage.model_validate_json(
            (directory / "supervisor-image.json").read_bytes()
        )
        if descriptor.recovery_binding is not None:
            release = verify_package(directory / "release", value["tcx_manifest"])
            validate_image_recovery(descriptor, release, require_policy=True)
        states["POLICY_APPROVED"] = "VERIFIED" if descriptor.recovery_binding else "NOT_APPLICABLE"
        if campaign is None or amendment_file is None or amendment_sha is None:
            raise ValueError("R1_AMENDMENT_REQUIRED")
        ledger = ReassessedCampaign(
            campaign, amendment_file=amendment_file, amendment_sha=amendment_sha
        )
        binding = ledger.amendment.binding
        if management_file is not None or management_sha is not None:
            from soc_agent.security_ai.ebpf_tc.execution_management import verify_policy

            if management_file is None or management_sha is None:
                raise ValueError("EXECUTION_MANAGEMENT_POLICY_REQUIRED")
            verify_policy(management_file, management_sha, ledger, binding)
        if binding.previous_artifact.root_manifest != descriptor.previous_manifest:
            raise ValueError("OPERATIONAL_PREVIOUS_ARTIFACT_BINDING")
        a = binding.next_artifact
        if source_git_identity() != (a.git_commit, a.git_tree):
            raise ValueError("OPERATIONAL_GIT_BINDING")
        identity = dict(
            manifest=manifest,
            image=image,
            bundle=value["bundle"],
            tcx_manifest=value["tcx_manifest"],
        )
        if identity != dict(
            manifest=a.manifest, image=a.image, bundle=a.bundle, tcx_manifest=a.root_manifest
        ):
            raise ValueError("OPERATIONAL_ARTIFACT_BINDING")
        if traffic_file is None or traffic_sha is None or claim_file is None:
            raise ValueError("R2_TRAFFIC_APPROVAL_REQUIRED")
        launch = LaunchApproval(
            traffic_file, traffic_sha, binding.next_session, a, claim_file, campaign
        )
        R2Launcher(launch)  # Read-only: never claims or generates traffic.
        if claim_file.exists() or claim_file.is_symlink():
            raise ValueError("R2_CLAIM_ALREADY_EXISTS")
        states["R2_SCOPE_APPROVED"] = "VERIFIED"
        if approval_file is None or approval_sha is None:
            raise ValueError("EXACT_ROOT_NATIVE_APPROVAL_REQUIRED")
        from soc_agent.security_ai.ebpf_tc.reassessment import held_json

        receipt = held_json(approval_file, approval_sha)
        if receipt.get("r2_receipt_sha") != traffic_sha:
            raise ValueError("R2_EXECUTION_RECEIPT_MISMATCH")
        dns = json.loads((directory / "dns-sidecar/release.json").read_bytes())["scope"]
        cost = int(descriptor.previous_manifest != value["tcx_manifest"])
        preview_reservation(
            campaign,
            amendment_file=amendment_file,
            amendment_sha=amendment_sha,
            identity=identity,
            scope=value["scope"],
            dns_scope=dns,
            approval_file=approval_file,
            approval_sha=approval_sha,
            root_cost=cost,
            git_commit=a.git_commit,
        )
        states["R1_REASSESSMENT_VERIFIED"] = "VERIFIED"
        states["ROOT_INSTALL_APPROVED"] = states["NATIVE_EXECUTION_APPROVED"] = "VERIFIED"
    except (ValueError, OSError) as exc:
        return dict(
            status="BLOCKED",
            stages=states,
            error=str(exc),
            errno=getattr(exc, "errno", None),
            reserved=False,
            executed=False,
        )
    return dict(
        status="EXECUTION_READY",
        stages=states,
        reserved=False,
        executed=False,
        admission_is_snapshot_only=True,
    )


def main(argv=None) -> int:
    from soc_agent.security_ai.ebpf_native.contracts import local_controller
    from soc_agent.security_ai.ebpf_tc.recovery_policy import RecoveryBuild

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("prepare", "reassess", "check", "execute"))
    parser.add_argument("directory", type=Path)
    for name in (
        "installed-manifest",
        "abi-sha",
        "policy-sha",
        "manifest",
        "image-sha",
        "amendment-sha",
        "approval-sha",
        "traffic-sha",
        "procedure-sha",
        "review-sha",
        "evidence-sha",
        "management-sha",
        "settlement-sha",
        "request-sha",
        "attempt-id",
    ):
        parser.add_argument("--" + name)
    for name in (
        "abi-file",
        "policy-file",
        "campaign",
        "amendment-file",
        "approval-file",
        "traffic-file",
        "claim-file",
        "procedure-file",
        "review-file",
        "evidence-file",
        "management-file",
        "settlement-file",
        "request-file",
    ):
        parser.add_argument("--" + name, type=Path)
    args = parser.parse_args(argv)
    local_controller()  # Never a Root CLI or capability-bearing controller.
    directory = args.directory.absolute()
    try:
        if args.request_file is not None or args.request_sha is not None:
            from soc_agent.security_ai.ebpf_tc.execution_request import load_request

            if (
                args.mode not in {"check", "execute"}
                or not args.request_file
                or not args.request_sha
            ):
                raise ValueError("EXECUTION_REQUEST_MODE_OR_PIN")
            fields = load_request(args.request_file, args.request_sha, directory)
            if any(getattr(args, k) is not None for k in fields):
                raise ValueError("EXECUTION_REQUEST_ARGUMENT_OVERRIDE")
            for key, value in fields.items():
                setattr(args, key, value)
        if args.attempt_id:
            from soc_agent.security_ai.ebpf_tc.execution_management import inspect_reservation
            from soc_agent.security_ai.stabilization_campaign import StabilizationCampaign

            if args.mode != "check" or not args.campaign:
                raise ValueError("EXECUTION_INSPECTION_MODE")
            print(
                json.dumps(
                    inspect_reservation(
                        StabilizationCampaign(args.campaign, "BATCH2"), args.attempt_id
                    ),
                    indent=2,
                )
            )
            return 0
        if args.settlement_file is not None or args.settlement_sha is not None:
            from soc_agent.security_ai.ebpf_tc.execution_management import settle
            from soc_agent.security_ai.stabilization_campaign import StabilizationCampaign

            if args.mode != "reassess" or not all(
                (
                    args.campaign,
                    args.settlement_file,
                    args.settlement_sha,
                    args.evidence_file,
                    args.evidence_sha,
                )
            ):
                raise ValueError("EXECUTION_SETTLEMENT_APPROVAL_REQUIRED")
            print(
                json.dumps(
                    settle(
                        StabilizationCampaign(args.campaign, "BATCH2"),
                        receipt_file=args.settlement_file,
                        receipt_sha=args.settlement_sha,
                        evidence_file=args.evidence_file,
                        evidence_sha=args.evidence_sha,
                        policy_file=args.management_file,
                        policy_sha=args.management_sha,
                    ),
                    indent=2,
                )
            )
            return 0
        if args.mode == "reassess":
            from soc_agent.security_ai.ebpf_tc.reassessment import (
                Binding,
                CleanupEvidence,
                held_json,
                reassess,
            )
            from soc_agent.security_ai.stabilization_campaign import StabilizationCampaign

            if not all(
                (
                    args.campaign,
                    args.procedure_file,
                    args.procedure_sha,
                    args.review_file,
                    args.review_sha,
                    args.evidence_file,
                    args.evidence_sha,
                )
            ):
                parser.error(
                    "reassess requires pinned procedure/review/evidence files and --campaign"
                )
            packet = held_json(args.evidence_file, args.evidence_sha)
            result = reassess(
                StabilizationCampaign(args.campaign, "BATCH2"),
                procedure_file=args.procedure_file,
                procedure_sha=args.procedure_sha,
                receipt_file=args.review_file,
                receipt_sha=args.review_sha,
                evidence=CleanupEvidence.model_validate(packet["evidence"]),
                source_paths={k: Path(v) for k, v in packet["source_paths"].items()},
                expected_binding=Binding.model_validate(packet["binding"]),
            )
        elif args.mode == "prepare":
            if not all((args.installed_manifest, args.abi_file, args.abi_sha)):
                parser.error("prepare requires --installed-manifest --abi-file --abi-sha")
            recovery = RecoveryBuild(
                installed_manifest=args.installed_manifest,
                abi_file=args.abi_file,
                abi_sha=args.abi_sha,
                policy_file=args.policy_file,
                policy_sha=args.policy_sha,
            )
            result = phase_d.prepare(directory, recovery=recovery)
            result["status"] = (
                "RUNTIME_APPROVED" if args.policy_file else "POLICY_APPROVAL_REQUIRED"
            )
            result["executed"] = False
        else:
            if not args.manifest or not args.image_sha:
                parser.error("check/execute requires --manifest --image-sha")
            keys = (
                "campaign",
                "amendment_file",
                "amendment_sha",
                "approval_file",
                "approval_sha",
                "traffic_file",
                "traffic_sha",
                "claim_file",
                "management_file",
                "management_sha",
            )
            grants = {k: getattr(args, k) for k in keys}
            result = readiness(directory, args.manifest, args.image_sha, **grants)
            if args.mode == "execute" and result["status"] == "EXECUTION_READY":
                from soc_agent.security_ai.ebpf_tc.reassessment_admission import execute

                result = execute(directory, args.manifest, args.image_sha, **grants)
                failed = bool(result.get("last_error") or result.get("first_failure")) or (
                    result.get("cleanup_status") != "PROCESS_AND_AUDIT_VERIFIED"
                )
                print(json.dumps(result, indent=2))
                return 1 if failed else 0
            elif args.mode == "execute":
                print(json.dumps(result, indent=2))
                return 2
    except (ValueError, OSError) as exc:
        print(
            json.dumps(
                dict(
                    status="BLOCKED",
                    error=str(exc),
                    errno=getattr(exc, "errno", None),
                    executed=False,
                )
            )
        )
        return 2
    print(json.dumps(result, indent=2))
    return 0 if result.get("status") != "BLOCKED" else 2


if __name__ == "__main__":
    raise SystemExit(main())
