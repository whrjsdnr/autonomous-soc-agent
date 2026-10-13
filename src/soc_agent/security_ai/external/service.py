"""Official native predictors -> existing adapter -> persisted advisory context.

An optional explicit interpreter isolates incompatible native dependencies. It is
not an LLM-generated command and never executes tools or response operations.
"""

import os
import subprocess
import tempfile
from pathlib import Path
from typing import Literal

from soc_agent.review.identity import content_digest
from soc_agent.review.models import StoredIncident
from soc_agent.review.persistence import ledger
from soc_agent.review.persistence.secure_storage import (
    create_private_directory,
    create_private_file,
    validate_database_files,
)
from soc_agent.security_ai.external.assembly import ExternalModelContext, assemble
from soc_agent.security_ai.external.inference import InferenceUnavailable, ModelRun, infer
from soc_agent.security_ai.external.models import (
    Snapshot,
    SourceFeatureObservation,
    TrustedExternalModelBinding,
)
from soc_agent.security_ai.external.runtime_guard import RuntimeBoundary
from soc_agent.security_ai.external.runtime_store import RuntimeRequirement, audit


class ModelInput(Snapshot):
    binding: TrustedExternalModelBinding
    observation: SourceFeatureObservation
    required: bool = True


class InferenceRequest(Snapshot):
    incident: StoredIncident
    inputs: tuple[ModelInput, ...]


class NativeResult(Snapshot):
    contract_version: Literal["soc-native-inference-result:v1"] = "soc-native-inference-result:v1"
    status: Literal["SUCCESS", "ERROR"]
    runs: tuple[ModelRun, ...] = ()
    code: str = "OK"


class ExternalSecurityAIService:
    def __init__(
        self, boundary: RuntimeBoundary, *, artifacts: Path, interpreter: Path | None = None
    ):
        self.boundary, self.artifacts, self.interpreter = boundary, Path(artifacts), interpreter
        if interpreter is not None and not Path(interpreter).is_absolute():
            raise ValueError("Explicit absolute native interpreter required")

    def analyze(self, incident_id, inputs: tuple[ModelInput, ...]) -> ExternalModelContext:
        request = InferenceRequest(incident=self.boundary.store.load(incident_id), inputs=inputs)
        required = RuntimeRequirement(
            incident_id=incident_id,
            request_digest=content_digest(request),
            required_models=tuple(item.binding.binding_id for item in inputs if item.required),
            status="PENDING",
        )
        with self.boundary.store.database.transaction() as connection:
            connection.execute(
                "INSERT INTO external_runtime_requirements VALUES (?,?,?)",
                (str(incident_id), ledger.serialize(required), content_digest(required)),
            )
            audit(connection, "INFERENCE_REQUIRED")
        try:
            result = self._analyze(incident_id, inputs)
        except (InferenceUnavailable, ValueError, OSError):
            with self.boundary.store.database.transaction() as connection:
                failed = required.model_copy(update={"status": "FAILED"})
                connection.execute(
                    "UPDATE external_runtime_requirements SET payload=?,digest=? "
                    "WHERE incident_id=?",
                    (ledger.serialize(failed), content_digest(failed), str(incident_id)),
                )
                audit(connection, "INFERENCE_FAILED")
            raise
        return result

    def _analyze(self, incident_id, inputs: tuple[ModelInput, ...]) -> ExternalModelContext:
        if not inputs or len(inputs) > 16:
            raise ValueError("Bounded explicit model inputs required")
        stored = self.boundary.store.load(incident_id)
        request = InferenceRequest(incident=stored, inputs=inputs)
        if len(request.model_dump_json().encode("utf-8")) > 256 * 1024:
            raise ValueError("Native request size exceeded")
        native_environment = {
            key: value
            for key, value in os.environ.items()
            if key
            in {
                "PATH",
                "SYSTEMROOT",
                "WINDIR",
                "HOME",
                "USERPROFILE",
                "LOCALAPPDATA",
                "APPDATA",
                "TEMP",
                "TMP",
                "LD_LIBRARY_PATH",
                "CONDA_PREFIX",
            }
        }
        native_environment.update(
            PYTHONPATH=str(Path(__file__).resolve().parents[3]),
            RUN_LIVE_LLM_TESTS="0",
            OMP_NUM_THREADS="1",
        )
        if self.interpreter is None:
            runs = tuple(
                infer(
                    self.artifacts,
                    item.binding,
                    item.observation,
                    required=item.required,
                    incident=stored,
                )
                for item in request.inputs
            )
        else:
            with tempfile.TemporaryDirectory(prefix="soc-native-") as parent:
                private = Path(parent) / "private"
                create_private_directory(private, exist_ok=False)
                source, result = private / "request.json", private / "result.json"
                for path in (source, result):
                    create_private_file(path)
                source.write_text(request.model_dump_json(), encoding="utf-8")
                try:
                    process = subprocess.run(
                        [
                            str(self.interpreter),
                            "-m",
                            "soc_agent.security_ai.external.inference_worker",
                            "--artifacts",
                            str(self.artifacts),
                            "--request",
                            str(source),
                            "--result",
                            str(result),
                        ],
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        timeout=180,
                        check=False,
                        env=native_environment,
                    )
                except (OSError, subprocess.TimeoutExpired):
                    raise InferenceUnavailable("NATIVE_PROCESS_UNAVAILABLE") from None
                if result.stat().st_size > 512 * 1024:
                    raise InferenceUnavailable("NATIVE_RESULT_OVERSIZED")
                validate_database_files(source)
                validate_database_files(result)
                try:
                    response = NativeResult.model_validate_json(result.read_text(encoding="utf-8"))
                    if process.returncode != 0 or response.status != "SUCCESS":
                        safe_codes = {
                            "RUNTIME_BACKEND_UNAVAILABLE",
                            "ARTIFACT_OR_BACKEND_UNAVAILABLE",
                            "INVALID_INFERENCE_CONTRACT",
                            "MODEL_NOT_CONFIGURED",
                            "ARTIFACT_PATH_CHANGED",
                            "UNSAFE_ARTIFACT_PATH",
                        }
                        code = (
                            response.code
                            if response.code in safe_codes
                            else "NATIVE_INFERENCE_FAILED"
                        )
                        raise InferenceUnavailable(code)
                    if response.code != "OK":
                        raise InferenceUnavailable("INVALID_NATIVE_RESULT")
                    runs = response.runs
                except InferenceUnavailable:
                    raise
                except (ValueError, TypeError):
                    raise InferenceUnavailable("INVALID_NATIVE_RESULT") from None
                if len(runs) != len(inputs) or any(
                    run.binding != item.binding
                    or (run.result is not None and run.result.observation != item.observation)
                    for run, item in zip(runs, inputs, strict=True)
                ):
                    raise InferenceUnavailable("NATIVE_RESULT_BINDING_MISMATCH")
        context = assemble(runs, incident=stored)
        if not context.results:
            raise InferenceUnavailable("NO_INCIDENT_LINKED_RESULTS")
        self.boundary.attach(context)
        return context
