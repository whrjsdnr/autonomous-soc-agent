"""Pinned offline input; external LLM requires explicit scoped authorization and env file."""

import argparse
import asyncio
import hashlib
import json
from pathlib import Path

from soc_agent.approval import ApprovalRequest
from soc_agent.security_ai.api_investigation import APIRunAuthorization, settings_from_env_file
from soc_agent.security_ai.offline_workflow import OfflineWorkflow, verify_result
from soc_agent.security_ai.research.environment import Paths, defaults, read_local
from soc_agent.security_ai.workflow_models import submitted_job


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path)
    parser.add_argument("--input-sha256")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--research-ml-root", type=Path)
    parser.add_argument("--api-authorization", type=Path)
    parser.add_argument("--api-env-file", type=Path)
    parser.add_argument("--tcx-namespace")
    parser.add_argument("--tcx-session")
    parser.add_argument("--tcx-release-manifest")
    parser.add_argument("--tcx-approval", type=Path)
    parser.add_argument("--tcx-approval-sha256")
    args = parser.parse_args(argv)
    try:
        if args.verify:
            if any(
                (
                    args.tcx_namespace,
                    args.tcx_session,
                    args.tcx_release_manifest,
                    args.tcx_approval,
                    args.tcx_approval_sha256,
                )
            ):
                raise ValueError("VERIFY_HAS_NO_NEW_TCX_AUTHORITY")
            if args.input or args.input_sha256 or args.api_authorization or args.api_env_file:
                raise ValueError("VERIFY_HAS_NO_NEW_INPUT")
            outcome = verify_result(args.output)
        else:
            if not args.input or not args.input_sha256:
                raise ValueError("EXACT_OFFLINE_INPUT_FILE_AND_SHA_REQUIRED")
            body = read_local(args.input, 1024 * 1024)
            if hashlib.sha256(body).hexdigest() != args.input_sha256:
                raise ValueError("OFFLINE_INPUT_SHA_MISMATCH")
            submitted = dict(sha256=args.input_sha256, utf8=body.decode())
            scope = (args.tcx_namespace, args.tcx_session, args.tcx_release_manifest)
            if any(scope):
                if not all(scope):
                    raise ValueError("TCX_EXPECTED_SCOPE_REQUIRED")
                submitted["tcx_scope"] = dict(
                    namespace=args.tcx_namespace,
                    session=args.tcx_session,
                    release_manifest=args.tcx_release_manifest,
                )
            job = submitted_job(submitted)
            tcx_approval = None
            if bool(args.tcx_approval) != bool(args.tcx_approval_sha256):
                raise ValueError("TCX_APPROVAL_EXPLICIT_SHA_REQUIRED")
            if args.tcx_approval:
                approval_bytes = read_local(args.tcx_approval, 32768)
                if hashlib.sha256(approval_bytes).hexdigest() != args.tcx_approval_sha256:
                    raise ValueError("TCX_APPROVAL_SHA_MISMATCH")
                tcx_approval = ApprovalRequest.model_validate_json(approval_bytes)
            authorization = settings = None
            if bool(args.api_authorization) != bool(args.api_env_file):
                raise ValueError("API_AUTHORIZATION_AND_ENV_FILE_REQUIRED")
            if args.api_authorization:
                authorization = APIRunAuthorization.model_validate_json(
                    read_local(args.api_authorization, 16384)
                )
                authorization.active()
                if authorization.input_sha256 != args.input_sha256:
                    raise ValueError("API_INPUT_SCOPE_MISMATCH")
                # Read validates ownership/permissions without displaying credential values.
                read_local(args.api_env_file, 16384)
                settings = settings_from_env_file(args.api_env_file, authorization)
            paths = None
            if job.kind in ("network14_replay", "packet_window", "dns_fixture", "tcx_analysis"):
                if args.research_ml_root:
                    ml = args.research_ml_root.absolute()
                    base = Paths(
                        ml,
                        ml.parent / "autonomous-soc-agent/.security-ai-demo/inference/bin/python",
                        Path("src"),
                    )
                else:
                    base = defaults()
                # Retain existing pinned project-local backend; bind current SOC source.
                paths = Paths(base.ml, base.python, Path(__file__).resolve().parents[2])
            workflow = OfflineWorkflow(
                args.output,
                paths=paths,
                api_authorization=authorization,
                api_settings=settings,
                tcx_approval=tcx_approval,
            )
            workflow.write("submitted-input.json", submitted)
            workflow.event("OFFLINE_SUBMITTED_INPUT_RETAINED", submitted)
            outcome = asyncio.run(workflow.run(job))
        print(
            json.dumps(
                dict(
                    status="COMPLETED_OFFLINE",
                    classification=outcome.classification,
                    eligibility=outcome.eligibility,
                    inferences=len(outcome.inference),
                    investigation=(outcome.investigation or {}).get("status"),
                    response=(outcome.response or {}).get("postcondition"),
                    llm_mode=outcome.llm_mode,
                    native_executed=False,
                    result=str(args.output / "result.json"),
                )
            )
        )
        return 0
    except (ValueError, OSError) as exc:
        print(json.dumps(dict(status="BLOCKED", code=type(exc).__name__, native_executed=False)))
        return 2
