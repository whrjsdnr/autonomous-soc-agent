"""CLI/Supervisor preparation projection over existing validators; no second executor."""

import argparse
import json
import subprocess
import traceback
from collections.abc import Callable
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


def _failure_origin(exc: BaseException) -> list[dict]:
    return [
        dict(file=Path(frame.filename).name, function=frame.name, line=frame.lineno)
        for frame in traceback.extract_tb(exc.__traceback__)[-12:]
    ]


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
    preparation_only: bool = False,
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
    context = {}
    try:
        descriptor = SupervisorImage.model_validate_json(
            (directory / "supervisor-image.json").read_bytes()
        )
        if descriptor.namespace_preview:
            phase_d.validate_preparation(directory, manifest, image)
            states["SOURCE_VERIFIED"] = "VERIFIED"
            states["RUNTIME_VERIFIED"] = "BUILD_INTEGRITY_VERIFIED_ONLY"
            raise ValueError("ISOLATED_NAMESPACE_POLICY_NOT_ACTIVATED")
        value = (phase_d.validate_preparation if preparation_only else phase_d.validate)(
            directory, manifest, image
        )
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
        context = dict(
            session=binding.next_session,
            release=binding.next_artifact.release,
            artifact=binding.next_artifact.model_dump(mode="json"),
        )
        if management_file is not None or management_sha is not None:
            from soc_agent.security_ai.ebpf_tc.execution_management import verify_policy

            if management_file is None or management_sha is None:
                raise ValueError("EXECUTION_MANAGEMENT_POLICY_REQUIRED")
            verify_policy(management_file, management_sha, ledger, binding)
        # The failed run and the currently installed release have independent
        # identities. R1 validates the former; installation verifies the latter.
        from soc_agent.security_ai.ebpf_tc.unified_image import installed_release

        if descriptor.recovery_binding is not None:
            from soc_agent.security_ai.ebpf_tc.runtime_recovery import inspect_retained

            installed_identity = inspect_retained(descriptor.previous_manifest).manifest
        else:
            installed = installed_release()
            installed_identity = installed.identity if installed is not None else None
        if installed_identity != descriptor.previous_manifest:
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
        launcher = R2Launcher(launch)  # Read-only: never claims or generates traffic.
        if launcher.receipt.scenario.namespace != value["scope"]["namespace"] or getattr(
            launcher.receipt.scenario, "namespace_policy_sha", None
        ) != (descriptor.namespace_runtime or {}).get("policy_sha"):
            raise ValueError("R2_NAMESPACE_SCOPE_MISMATCH")
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
            failure_origin=_failure_origin(exc),
            admission_context=context,
            reserved=False,
            executed=False,
        )
    return dict(
        status="REQUEST_PREPARATION_VERIFIED" if preparation_only else "EXECUTION_READY",
        admission_context=context,
        stages=states,
        reserved=False,
        executed=False,
        admission_is_snapshot_only=True,
    )


def main(argv=None, *, result_observer: Callable[[dict], None] | None = None) -> int:
    def emit(result: dict) -> None:
        if result_observer is not None:
            result_observer(result)
        print(json.dumps(result, indent=2))

    from soc_agent.security_ai.ebpf_native.contracts import local_controller
    from soc_agent.security_ai.ebpf_tc.recovery_policy import RecoveryBuild

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("prepare", "reassess", "check", "execute"))
    parser.add_argument("directory", type=Path)
    parser.add_argument(
        "--namespace-preview",
        help="Prepare guarded isolated Namespace review bytes only; never execution permission",
    )
    parser.add_argument("--namespace-config", type=Path)
    parser.add_argument("--namespace-config-sha")
    parser.add_argument("--review-git-commit")
    parser.add_argument("--review-git-tree")
    parser.add_argument("--namespace-controller-file", type=Path)
    parser.add_argument("--namespace-controller-sha")
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
        "root-governance-sha",
        "dns-operation-sha",
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
        "root-governance-file",
        "dns-operation-file",
    ):
        parser.add_argument("--" + name, type=Path)
    parser.add_argument("--request-preparation-file", type=Path)
    parser.add_argument("--request-preparation-sha")
    args = parser.parse_args(argv)
    local_controller()  # Never a Root CLI or capability-bearing controller.
    directory = args.directory.absolute()
    try:
        if args.request_preparation_file is not None or args.request_preparation_sha is not None:
            from soc_agent.security_ai.ebpf_tc.execution_request import ExecutionRequest
            from soc_agent.security_ai.ebpf_tc.installation import canonical
            from soc_agent.security_ai.ebpf_tc.reassessment import held_json
            from soc_agent.security_ai.ebpf_tc.request_handoff import (
                atomic_publish,
                prepare_r1,
                publish_request,
            )

            if (
                args.mode != "prepare"
                or not args.request_preparation_file
                or not args.request_preparation_sha
            ):
                raise ValueError("REQUEST_PREPARATION_REQUIRES_PINNED_PREPARE_PACKET")
            packet = held_json(args.request_preparation_file, args.request_preparation_sha)
            if packet["kind"] == "R1_REVIEW_PREPARATION":
                result = prepare_r1(directory, packet)
                atomic_publish(Path(packet["output_file"]), canonical(result))
            elif packet["kind"] == "EXECUTION_REQUEST_PUBLICATION":
                request = ExecutionRequest.model_validate(packet["request"])
                request.arguments(directory)
                result = publish_request(Path(packet["request_file"]), request)
            else:
                raise ValueError("REQUEST_PREPARATION_KIND")
            print(json.dumps(result, indent=2))
            return 0
        if args.namespace_controller_file is not None or args.namespace_controller_sha is not None:
            from soc_agent.security_ai.ebpf_tc.namespace_controller import run_packet
            from soc_agent.security_ai.ebpf_tc.reassessment import held_json

            allowed = {"mode", "directory", "namespace_controller_file", "namespace_controller_sha"}
            if (
                not args.namespace_controller_file
                or not args.namespace_controller_sha
                or any(v is not None for k, v in vars(args).items() if k not in allowed)
            ):
                raise ValueError("NAMESPACE_CONTROLLER_PIN_OR_ARGUMENT_OVERRIDE")
            result = run_packet(
                args.mode,
                directory,
                held_json(args.namespace_controller_file, args.namespace_controller_sha),
            )
            emit(result)
            return (
                0
                if result.get("status") not in {"BLOCKED", "FAILED", "UNKNOWN"}
                and result.get("returncode", 0) == 0
                else 2
            )
        if (
            args.namespace_config is not None or args.namespace_config_sha is not None
        ) and args.mode != "prepare":
            raise ValueError("NAMESPACE_CONFIG_PREPARE_ONLY")
        if args.namespace_preview is not None:
            # Do not let review mode swallow authority-bearing argument bundles.
            if args.mode != "prepare" or any(
                v is not None
                for k, v in vars(args).items()
                if k not in {"mode", "directory", "namespace_preview"}
            ):
                raise ValueError("NAMESPACE_PREVIEW_PREPARE_ONLY_NO_GRANTS")
            result = phase_d.prepare_namespace_preview(directory, args.namespace_preview)
            emit(result)
            return 0
        if args.dns_operation_file is not None or args.dns_operation_sha is not None:
            from soc_agent.security_ai.ebpf_tc.dns_diagnostic import run_packet
            from soc_agent.security_ai.ebpf_tc.reassessment import held_json

            if not args.dns_operation_file or not args.dns_operation_sha:
                raise ValueError("DNS_OPERATION_PACKET_PIN_REQUIRED")
            packet = held_json(args.dns_operation_file, args.dns_operation_sha)
            result = run_packet(args.mode, directory, packet)
            emit(result)
            return 0 if result.get("status") not in ("BLOCKED", "FAILED", "UNKNOWN") else 2
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
        if args.root_governance_file is not None or args.root_governance_sha is not None:
            from soc_agent.security_ai.ebpf_tc.reassessment import held_json
            from soc_agent.security_ai.ebpf_tc.root_governance import apply_packet
            from soc_agent.security_ai.stabilization_campaign import StabilizationCampaign

            if args.mode != "reassess" or not all(
                (args.campaign, args.root_governance_file, args.root_governance_sha)
            ):
                raise ValueError("ROOT_GOVERNANCE_MODE_OR_PIN")
            packet = held_json(args.root_governance_file, args.root_governance_sha)
            print(
                json.dumps(
                    apply_packet(StabilizationCampaign(args.campaign, "BATCH3"), packet), indent=2
                )
            )
            return 0
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
            if "preparation_ledger" in packet:
                from soc_agent.security_ai.ebpf_tc.request_handoff import ledger_snapshot

                if packet["preparation_ledger"] != ledger_snapshot(args.campaign):
                    raise ValueError("R1_PREPARATION_STALE_LEDGER")
            result = reassess(
                StabilizationCampaign(args.campaign, packet["binding"]["batch"]),
                procedure_file=args.procedure_file,
                procedure_sha=args.procedure_sha,
                receipt_file=args.review_file,
                receipt_sha=args.review_sha,
                evidence=CleanupEvidence.model_validate(packet["evidence"]),
                source_paths={k: Path(v) for k, v in packet["source_paths"].items()},
                expected_binding=Binding.model_validate(packet["binding"]),
            )
        elif args.mode == "prepare":
            namespace_build = None
            if args.namespace_config is not None or args.namespace_config_sha is not None:
                from soc_agent.security_ai.ebpf_tc.namespace_runtime import NamespaceBuild
                from soc_agent.security_ai.ebpf_tc.reassessment import held_json

                if not args.namespace_config or not args.namespace_config_sha:
                    raise ValueError("NAMESPACE_CONFIG_PIN_REQUIRED")
                namespace_build = NamespaceBuild.model_validate_json(
                    json.dumps(held_json(args.namespace_config, args.namespace_config_sha))
                )
            recovery = None
            recovery_values = (
                args.installed_manifest,
                args.abi_file,
                args.abi_sha,
                args.policy_file,
                args.policy_sha,
            )
            if namespace_build is None or any(v is not None for v in recovery_values):
                if not all((args.installed_manifest, args.abi_file, args.abi_sha)):
                    parser.error("prepare requires --installed-manifest --abi-file --abi-sha")
                recovery = RecoveryBuild(
                    installed_manifest=args.installed_manifest,
                    abi_file=args.abi_file,
                    abi_sha=args.abi_sha,
                    policy_file=args.policy_file,
                    policy_sha=args.policy_sha,
                )
            result = phase_d.prepare(directory, recovery=recovery, namespace_build=namespace_build)
            descriptor = SupervisorImage.model_validate_json(
                (directory / "supervisor-image.json").read_bytes()
            )
            result["status"] = (
                "POLICY_APPROVAL_REQUIRED"
                if descriptor.namespace_preview or (recovery is not None and not args.policy_file)
                else "RUNTIME_APPROVED"
            )
            result["executed"] = False
            if args.review_git_commit is not None or args.review_git_tree is not None:
                from soc_agent.security_ai.ebpf_tc.development_session import (
                    prepare_artifact_review,
                )

                if not args.review_git_commit or not args.review_git_tree:
                    raise ValueError("ARTIFACT_REVIEW_GIT_PAIR_REQUIRED")
                result["development_metering"] = prepare_artifact_review(
                    directory,
                    result["manifest"],
                    result["image"],
                    git_commit=args.review_git_commit,
                    git_tree=args.review_git_tree,
                )
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
                emit(result)
                return 1 if failed else 0
            elif args.mode == "execute":
                emit(result)
                return 2
    except (ValueError, OSError) as exc:
        emit(
            dict(
                status="BLOCKED",
                error=str(exc),
                errno=getattr(exc, "errno", None),
                failure_origin=_failure_origin(exc),
                executed=False,
            )
        )
        return 2
    emit(result)
    return 0 if result.get("status") != "BLOCKED" else 2


if __name__ == "__main__":
    raise SystemExit(main())
