"""Read-only linkage of retained API results to the original Native task.

This is a display projection. It neither mutates the capture store nor grants
model/API authority, and never relabels the API runtime as a new capture.
"""

from copy import deepcopy
from pathlib import Path

from soc_agent.continuous.cli import observation


def attach_api_results(native_directory: Path, api_directory: Path, current: dict) -> dict:
    native = observation(native_directory)
    retained = observation(api_directory) if api_directory.exists() else None
    result = deepcopy(current)
    if retained is None:
        result["api_investigation"] = dict(status="WAITING_AUTHORIZED_API_RESULT", calls=0)
        return result
    api = retained["snapshot"]
    if (
        native is None
        or native["configuration"]["source"] != "NATIVE_SERVICE"
        or api.get("original_capture_session") != native["store_id"]
        or api.get("investigation_input_origin") != "RETAINED_REAL_NATIVE_NO_NEW_CAPTURE"
        or api.get("collection_live") is not False
        or api.get("collector") != "NOT_STARTED"
    ):
        raise ValueError("GUI_API_NATIVE_SESSION_BINDING_MISMATCH")
    orchestration = result.setdefault("orchestration", {})
    tasks = orchestration.get("tasks", [])
    external = api.get("orchestration", {})
    matched = []
    for task in external.get("tasks", []):
        selected = next(
            (
                row
                for row in tasks
                if row["task_id"] == task["task_id"]
                and row["incident_id"] == task["incident_id"]
                and row["evidence_revision"] == task["evidence_revision"]
                and row["sources"] == task["sources"]
            ),
            None,
        )
        if selected is None:
            raise ValueError("GUI_API_TASK_REVISION_BINDING_MISMATCH")
        investigation = task.get("investigation") or {}
        if investigation.get("llm_mode") != "EXTERNAL_API_ADAPTER_LOCAL_COORDINATION":
            raise ValueError("GUI_API_PROVIDER_PROVENANCE_MISMATCH")
        selected["native_investigation"] = selected.get("investigation")
        selected["investigation"] = deepcopy(investigation)
        selected["api_task_state"] = task["state"]
        selected["investigation_result_origin"] = "RETAINED_NATIVE_EXTERNAL_API"
        matched.append(task["task_id"])
    api_status = external.get("worker", {}).get("api_status")
    if api_status is not None:
        orchestration.setdefault("worker", {})["api_status"] = deepcopy(api_status)
    result["api_investigation"] = dict(
        status="ATTACHED_BOUND_RETAINED_NATIVE_RESULT",
        source_runtime=str(api_directory),
        source_session=retained["store_id"],
        original_capture_session=native["store_id"],
        task_ids=matched,
        calls=api.get("api_calls"),
        api_status=api_status,
        cleanup=api.get("cleanup", "UNKNOWN"),
        capture_started=False,
        scope="DISPLAY_ONLY_ORIGINAL_NATIVE_STORE_UNCHANGED",
    )
    return result
