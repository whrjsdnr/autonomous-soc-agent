"""Pinned offline input only. Never selects live collectors or paid LLM clients."""

import argparse
import asyncio
import hashlib
import json
from pathlib import Path

from soc_agent.security_ai.offline_workflow import OfflineWorkflow, verify_result
from soc_agent.security_ai.research.environment import Paths, defaults, read_local
from soc_agent.security_ai.workflow_models import JOB


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path)
    parser.add_argument("--input-sha256")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--research-ml-root", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.verify:
            if args.input or args.input_sha256:
                raise ValueError("VERIFY_HAS_NO_NEW_INPUT")
            outcome = verify_result(args.output)
        else:
            if not args.input or not args.input_sha256:
                raise ValueError("EXACT_OFFLINE_INPUT_FILE_AND_SHA_REQUIRED")
            body = read_local(args.input, 1024 * 1024)
            if hashlib.sha256(body).hexdigest() != args.input_sha256:
                raise ValueError("OFFLINE_INPUT_SHA_MISMATCH")
            job = JOB.validate_json(body)
            paths = None
            if job.kind in ("network14_replay", "dns_fixture"):
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
            workflow = OfflineWorkflow(args.output, paths=paths)
            submitted = dict(sha256=args.input_sha256, utf8=body.decode())
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
