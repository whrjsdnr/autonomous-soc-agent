"""Read verified completed reports for older compact Runtime publications.

This never starts an analysis or grants a model action. The running service and
its source stay untouched; only the GUI's view of immutable results is enriched.
"""

from collections import OrderedDict
from pathlib import Path

from soc_agent.gui.analysis_service import project_result
from soc_agent.review.persistence.models import StorageError
from soc_agent.security_ai.offline_workflow import verify_result


class ResultViews:
    def __init__(self):
        self.cache: OrderedDict[Path, tuple[tuple, dict]] = OrderedDict()
        self.latest: tuple[Path, dict] | None = None

    def enrich(self, runtime: Path, snapshot: dict) -> dict:
        rows = []
        for original in snapshot.get("recent_results", [])[-32:]:
            row = dict(original)
            try:
                output = Path(row["output"])
                if output.parent != runtime.absolute() / "analysis" or output.is_symlink():
                    raise ValueError("RESULT_VIEW_PATH_SCOPE")
                # Completed reports are immutable. Any changed file or extra receipt
                # invalidates this bounded cache and runs the existing full verifier.
                paths = sorted(output.rglob("*"))
                if len(paths) > 128 or any(p.is_symlink() for p in paths):
                    raise ValueError("RESULT_VIEW_FILE_SCOPE")
                signature = tuple(
                    (
                        str(p.relative_to(output)),
                        p.stat().st_ino,
                        p.stat().st_size,
                        p.stat().st_mtime_ns,
                    )
                    for p in paths
                    if p.is_file()
                )
                database = output / "soc/external-validation.sqlite"
                if not database.is_file():
                    raise ValueError("RESULT_VIEW_AUDIT_MISSING")
                cached = self.cache.get(output)
                if cached is None or cached[0] != signature:
                    verified = project_result(verify_result(output))
                    self.latest = (output, verified)
                    self.cache[output] = (
                        signature,
                        {key: value for key, value in verified.items() if key != "detail"},
                    )
                    if len(self.cache) > 32:
                        self.cache.popitem(last=False)
                verified = self.cache[output][1]
                self.cache.move_to_end(output)
                if verified["incident_id"] != row["incident_id"]:
                    raise ValueError("RESULT_VIEW_INCIDENT_MISMATCH")
                row.update(
                    predictions=verified["predictions"],
                    investigation_detail=verified["investigation_detail"],
                    report_view="VERIFIED_REPORT_AND_AUDIT",
                )
            except (KeyError, ValueError, OSError, StorageError):
                # Do not turn missing/tampered reports into apparently verified graphs.
                row.update(predictions=[], investigation_detail={}, report_view="UNVERIFIED")
            rows.append(row)
        return snapshot | dict(recent_results=rows)

    def analysis(self, snapshot: dict) -> dict | None:
        rows = snapshot.get("recent_results", [])
        if (
            not self.latest
            or not rows
            or rows[-1].get("report_view") != "VERIFIED_REPORT_AND_AUDIT"
        ):
            return None
        path, result = self.latest
        if str(path) != rows[-1].get("output"):
            return None
        return dict(
            state="COMPLETED_VERIFIED_REPORT",
            mode="ATTACHED_CONTINUOUS_RESULT",
            result=result,
            output=str(path),
            cleanup="VERIFIED_ANALYSIS_CHILD_ONLY",
            collection_live=False,
            worker_running=False,
            capture_started_by_gui=False,
            last_error=None,
        )
