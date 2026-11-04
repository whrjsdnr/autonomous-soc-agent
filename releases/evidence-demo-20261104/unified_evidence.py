"""Read projections for a presentation, with independent historical source identities."""

import json
from dataclasses import dataclass
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, JsonValue


class Source(BaseModel):
    model_config = ConfigDict(frozen=True)
    name: str
    trial_date: str
    execution: str
    session: str | None
    capture_sessions: dict[str, list[str]] = Field(default_factory=dict)
    identity: str
    path: str
    note: str


@dataclass(frozen=True)
class Evidence:
    sources: dict[str, Source]
    reports: dict[str, dict]
    flows: list[dict]
    native: dict
    replay: dict
    api: dict
    authentication: dict
    authentication_parent: dict
    authentication_if: dict


@dataclass(frozen=True)
class Stage:
    title: str
    source: str
    seconds: int
    explanation: str


STAGES = (
    Stage("Packet · DNS", "native", 35, "Native Packet과 DNS의 보존된 수집 결과를 확인합니다."),
    Stage("Window Seal · Eligibility", "native", 30, "입력 무결성과 모델 실행 자격을 구분합니다."),
    Stage(
        "Network14 RF / LR",
        "native",
        40,
        "검증된 추론 영수증 8건입니다. 점수는 공격 확률이 아닙니다.",
    ),
    Stage(
        "Incident", "native", 30, "Incident 2건의 분류와 증거를 확인합니다. 공격 확정이 아닙니다."
    ),
    Stage(
        "SOCRuntime Task",
        "native",
        45,
        "SCRIPTED 조사 5개: 도구 결과와 사람 검토 대기를 확인합니다.",
    ),
    Stage(
        "LLM Plan · Tool · Assessment",
        "api",
        60,
        "별도 API 시험으로 전환합니다. Native Incident와 연결된 실행이 아닙니다.",
    ),
    Stage(
        "Authentication",
        "authentication_if",
        30,
        "Authentication Window → Isolation Forest → Investigation 결과를 확인합니다.",
    ),
    Stage(
        "Audit · Cleanup",
        "native",
        30,
        "시험별 Audit과 Cleanup 범위를 구분합니다. 전역 Cleanup은 UNKNOWN입니다.",
    ),
)


class ReplayClock:
    def __init__(self) -> None:
        self.index = 0
        self.remaining = float(STAGES[0].seconds)
        self.playing = False
        self.finished = False

    def select(self, index: int) -> None:
        if not 0 <= index < len(STAGES):
            raise ValueError("UNIFIED_STAGE_OUT_OF_RANGE")
        self.index, self.remaining = index, float(STAGES[index].seconds)
        self.finished = False

    def advance(self, seconds: float) -> bool:
        if seconds < 0:
            raise ValueError("UNIFIED_CLOCK_NEGATIVE")
        if not self.playing:
            return False
        previous = self.index
        self.remaining -= seconds
        while self.remaining <= 0 and not self.finished:
            if self.index == len(STAGES) - 1:
                self.remaining, self.playing, self.finished = 0, False, True
            else:
                self.index += 1
                self.remaining += STAGES[self.index].seconds
        return self.index != previous


def revealed_count(total: int, stage: int, clock: ReplayClock) -> int:
    """Presentation pacing only; never an acquisition timestamp or evidence counter."""
    if clock.index < stage:
        return 0
    if clock.index > stage:
        return total
    elapsed = STAGES[stage].seconds - clock.remaining
    return min(total, int(total * max(0, elapsed) / (STAGES[stage].seconds * 0.75)))


def model_revealed_count(clock: ReplayClock) -> int:
    """First receipt at 6.5 seconds, all eight by 24; display timing, not inference latency."""
    elapsed = sum(s.seconds for s in STAGES[: clock.index + 1]) - clock.remaining
    return min(8, max(0, int((elapsed - 4) / 2.5)))


def source_path(manifest: dict, name: str, flag: str) -> Path:
    args = manifest["views"][name]["gui_args"]
    return Path(args[args.index(flag) + 1])


def load_evidence(manifest: dict) -> Evidence:
    """Use existing verifiers/readers; never instantiate a service or analysis worker."""
    from soc_agent.continuous.cli import observation
    from soc_agent.gui.analysis_service import project_result, verify_result
    from soc_agent.gui.continuous_projection import project
    from soc_agent.gui.result_views import ResultViews

    from soc_agent.gui.queries import stored_counts
    from soc_agent.linux_runtime.__main__ import status
    from soc_agent.linux_runtime.store import RuntimeStore

    sources = {}
    reports = {}
    continuous = {}
    for name, date in (("native", "2026-10-30"), ("replay", "2026-11-02")):
        path = source_path(manifest, name, "--continuous-runtime")
        record = observation(path)
        if record is None:
            raise ValueError("UNIFIED_OBSERVATION_MISSING")
        current = ResultViews().enrich(path, record["snapshot"])
        if any(
            r.get("report_view") != "VERIFIED_REPORT_AND_AUDIT" for r in current["recent_results"]
        ):
            raise ValueError("UNIFIED_REPORT_UNVERIFIED")
        continuous[name] = project({"continuous": current})
        sessions = {
            e["capture_session"]
            for e in current["dns"]["recent_events"]
            if e.get("capture_session")
        }
        sources[name] = Source(
            name=name,
            trial_date=date,
            execution=current["source"] + " / SCRIPTED",
            session=next(iter(sessions)) if len(sessions) == 1 else None,
            identity="store_id=" + record["store_id"] + "; clock_epoch=" + current["clock_epoch"],
            path=str(path),
            note=manifest["views"][name]["description"],
        )
    native_path = Path(sources["native"].path)
    flows = {}
    tcx_sessions = set()
    for path in sorted((native_path / "inputs").glob("*.json")):
        if str(path) not in manifest["files"]:
            raise ValueError("UNIFIED_UNPINNED_INPUT")
        document = json.loads(path.read_text())
        if document.get("kind") != "tcx_analysis":
            continue
        tcx_sessions.add(document["session"])
        for flow in document["result"]["tcx"]["data_plane"]["processing"]["feature_tail"]:
            flows[(document["session"], flow["flow_id"])] = flow | {
                "source_file": str(path),
                "capture_session": document["session"],
            }
    ordered_flows = sorted(flows.values(), key=lambda f: f["lifecycle"]["last_event_ns"])
    if (
        sum(f["packet_count"] for f in ordered_flows)
        != continuous["native"]["continuous"]["metrics"]["packets"]
    ):
        raise ValueError("UNIFIED_FLOW_COUNT_MISMATCH")
    dns_sessions = sorted(
        {e["capture_session"] for e in continuous["native"]["dns"]["recent_events"]}
    )
    sources["native"] = sources["native"].model_copy(
        update={
            "session": None,
            "capture_sessions": {"TCX": sorted(tcx_sessions), "DNS": dns_sessions},
        }
    )
    for row in continuous["native"]["continuous"]["recent_results"]:
        reports[row["output"]] = project_result(verify_result(Path(row["output"])))
    path = source_path(manifest, "api", "--analysis-result")
    api = project_result(verify_result(path))
    reports[str(path)] = api
    sources["api"] = Source(
        name="api",
        trial_date="2026-10-27",
        execution="OFFLINE_PCAP / " + api["llm_mode"],
        session=None,
        identity="incident_id=" + api["incident_id"],
        path=str(path),
        note="Separate actual API trial. No Native session link; original session field is null. "
        "PCAP event time 2018-07-31 is distinct from trial time.",
    )
    path = source_path(manifest, "authentication", "--runtime")
    auth = status(path) | stored_counts(path)
    store = RuntimeStore(path)
    parent = observation(path.parent)
    if parent is None:
        raise ValueError("UNIFIED_AUTHENTICATION_PARENT_MISSING")
    sources["authentication"] = Source(
        name="authentication",
        trial_date="2026-11-04",
        execution="FAILED_RUNTIME / " + auth["assessment_mode"],
        session=None,
        identity="incident_id=" + str(store.config.incident_id),
        path=str(path),
        note="Runtime identity is retained in details; no invented Session UUID. "
        "Later standalone Host read success does not repair this failed Runtime.",
    )
    path = Path(manifest["supplemental_views"]["authentication_if"]["path"])
    auth_if = project_result(verify_result(path))
    # Classifier confidence is intentionally null for IF. Expose the actual normalized
    # anomaly rank stored in its receipt, with its original non-probability semantics.
    receipt = auth_if["detail"]["inference"][0]["receipt"]
    scores = json.loads(receipt["result"]["scores"])
    auth_if["predictions"][0]["score"] = scores["normalized_anomaly_score"]
    auth_if["predictions"][0]["score_semantics"] = (
        "IF normalized anomaly rank; not attack probability"
    )
    reports[str(path)] = auth_if
    sources["authentication_if"] = Source(
        name="authentication_if",
        trial_date="2026-10-27",
        execution="FIXTURE / SCRIPTED",
        session=None,
        identity="incident_id=" + auth_if["incident_id"],
        path=str(path),
        note=manifest["supplemental_views"]["authentication_if"]["description"],
    )
    return Evidence(
        sources,
        reports,
        ordered_flows,
        continuous["native"],
        continuous["replay"],
        api,
        auth | {"recorded_runtime_state": store.state()},
        parent["snapshot"],
        auth_if,
    )


def stage_data(evidence: Evidence, index: int) -> dict[str, JsonValue]:
    """Each displayed result carries source context, including in the raw-detail tab."""
    native = evidence.native["continuous"]
    data = (
        {
            "metrics": native["metrics"],
            "dns": native["dns"],
            "packet_producer": native["producer"],
            "dns_transport": native["dns_transport"],
        },
        {
            "capture_window": native["capture_window"],
            "eligibility": {k: native["metrics"][k] for k in ("eligible", "incomplete", "flows")},
        },
        {"predictions": evidence.native["research"]["records"]},
        {"incidents": native["recent_results"]},
        {"orchestration": native["orchestration"]},
        {"api_result": evidence.api},
        {
            "authentication_if": evidence.authentication_if,
            "failed_runtime_source": evidence.sources["authentication"].model_dump(),
            "authentication": evidence.authentication,
            "parent_authentication": evidence.authentication_parent.get("authentication"),
            "parent_cleanup": evidence.authentication_parent.get("cleanup"),
        },
        {
            "separate_trials": {
                name: {
                    "source": evidence.sources[name].model_dump(),
                    "audit": current.get("audit"),
                    "cleanup": current.get("cleanup"),
                    "queue": current.get("queue"),
                    "collector_cleanup": current.get("collector_cleanup"),
                }
                for name, current in (
                    ("native", native),
                    ("replay", evidence.replay["continuous"]),
                    ("authentication", evidence.authentication_parent),
                )
            },
            "api": {"source": evidence.sources["api"].model_dump(), "audit": evidence.api["audit"]},
            "global_cleanup": "UNKNOWN",
            "viewer": "READ_ONLY_PRESENTATION",
        },
    )[index]
    return {"source": evidence.sources[STAGES[index].source].model_dump(), "result": data}
