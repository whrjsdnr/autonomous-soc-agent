"""Fixed offline native inference command. No arbitrary module, shell or model code input."""

import argparse
from pathlib import Path

from soc_agent.review.persistence.secure_storage import validate_database_files
from soc_agent.security_ai.external.inference import InferenceUnavailable, infer
from soc_agent.security_ai.external.service import InferenceRequest, NativeResult


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--request", type=Path, required=True)
    parser.add_argument("--result", type=Path, required=True)
    args = parser.parse_args()
    validate_database_files(args.request)
    validate_database_files(args.result)
    if args.request.stat().st_size > 256 * 1024 or args.result.stat().st_size:
        raise ValueError("Invalid native request/result boundary")
    request = InferenceRequest.model_validate_json(args.request.read_text(encoding="utf-8"))
    try:
        runs = tuple(
            infer(
                args.artifacts,
                item.binding,
                item.observation,
                required=item.required,
                incident=request.incident,
            )
            for item in request.inputs
        )
        response = NativeResult(status="SUCCESS", runs=runs)
    except InferenceUnavailable as error:
        codes = {
            "RUNTIME_BACKEND_UNAVAILABLE",
            "ARTIFACT_OR_BACKEND_UNAVAILABLE",
            "INVALID_INFERENCE_CONTRACT",
            "MODEL_NOT_CONFIGURED",
            "ARTIFACT_PATH_CHANGED",
            "UNSAFE_ARTIFACT_PATH",
        }
        code = str(error) if str(error) in codes else "NATIVE_INFERENCE_FAILED"
        response = NativeResult(status="ERROR", code=code)
    args.result.write_text(response.model_dump_json(), encoding="utf-8")
    validate_database_files(args.result)
    return 0 if response.status == "SUCCESS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
