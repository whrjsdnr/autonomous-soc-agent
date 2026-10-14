"""Window/rule evaluation, not attack truth or a second detector. No live LLM calls."""

import argparse
import json
import subprocess
from collections import Counter
from datetime import timedelta
from pathlib import Path
from statistics import median
from tempfile import TemporaryDirectory
from time import perf_counter
from typing import Literal, Self
from uuid import NAMESPACE_URL, UUID, uuid5

from pydantic import Field, model_validator

from soc_agent.demo.scenario_models import PAM, START, Scenario, ssh
from soc_agent.demo.scenario_pipeline import fixture_event, open_pipeline
from soc_agent.linux_runtime.findings import correlate
from soc_agent.linux_runtime.models import RuntimeConfig
from soc_agent.realtime.models import CommonEvent
from soc_agent.runtime_lock import exclusive_runtime_lock
from soc_agent.security_ai.external.models import Hash, Snapshot, content_digest_payload
from soc_agent.state.evidence import UTCTimestamp

RULES = (
    "REPEATED_AUTH_FAILURE",
    "REPEATED_ACCOUNT_FAILURE",
    "MULTI_ACCOUNT_FAILURE",
    "FAILURE_THEN_SUCCESS",
    "SUDO_PAM_MODULE_FAILURE",
)
DATASET = "authentication-advisory-fixtures:1.0.0"


class GroundTruth(Snapshot):
    dataset_id: str
    scenario_id: str
    incident_id: UUID
    event_ids: tuple[UUID, ...] = Field(min_length=1)
    ground_truth_label: Literal["EXPECTED_ADVISORY", "NO_ADVISORY_EXPECTED"]
    expected_rule_id: Literal[
        "REPEATED_AUTH_FAILURE",
        "REPEATED_ACCOUNT_FAILURE",
        "MULTI_ACCOUNT_FAILURE",
        "FAILURE_THEN_SUCCESS",
        "SUDO_PAM_MODULE_FAILURE",
    ]
    event_timestamp: UTCTimestamp
    window_start: UTCTimestamp
    window_end: UTCTimestamp
    source_origin: Literal["FIXTURE", "NATIVE_OS"]
    evidence_references: tuple[Hash, ...] = Field(min_length=1)
    label_provenance: str = Field(min_length=1)

    @model_validator(mode="after")
    def window(self) -> Self:
        if self.window_start.timestamp() % 300 or self.window_end - self.window_start != timedelta(
            seconds=300
        ):
            raise ValueError("Ground truth must use a UTC five-minute half-open window")
        if not self.window_start <= self.event_timestamp < self.window_end:
            raise ValueError("Ground truth event time outside observation window")
        return self


class EvaluationCase(Snapshot):
    case_id: str
    description: str
    incident_id: UUID
    events: tuple[CommonEvent, ...] = Field(min_length=1)
    arrival_order: tuple[int, ...] = Field(min_length=1)
    labels: tuple[GroundTruth, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def binding(self) -> Self:
        if len({e.event_id for e in self.events}) != len(self.events):
            raise ValueError("Duplicate source identity in case; replay uses arrival_order")
        if set(self.arrival_order) != set(range(len(self.events))):
            raise ValueError("Arrival order must cover exactly the declared event indices")
        keys = set()
        for label in self.labels:
            events = [
                e for e in self.events if label.window_start <= e.event_timestamp < label.window_end
            ]
            key = (label.window_start, label.expected_rule_id)
            if (
                key in keys
                or label.incident_id != self.incident_id
                or label.scenario_id != self.case_id
            ):
                raise ValueError("Duplicate label or Incident/Scenario mismatch")
            keys.add(key)
            if (
                tuple(e.event_id for e in events) != label.event_ids
                or tuple(e.source_digest for e in events) != label.evidence_references
            ):
                raise ValueError("Ground truth source/digest mismatch")
            if any(
                (e.provenance == "explicit_log_fixture") != (label.source_origin == "FIXTURE")
                for e in events
            ):
                raise ValueError("Ground truth origin mismatch")
        windows = {int(e.event_timestamp.timestamp()) // 300 for e in self.events}
        if keys != {
            (START.fromtimestamp(w * 300, START.tzinfo), rule) for w in windows for rule in RULES
        }:
            raise ValueError("Each observed window needs a label for every evaluated rule")
        return self


class EvaluationDataset(Snapshot):
    dataset_id: str = DATASET
    cases: tuple[EvaluationCase, ...] = Field(min_length=1)
    label_semantics: Literal["INDEPENDENT_ADVISORY_UTILITY_NOT_ATTACK_TRUTH"] = (
        "INDEPENDENT_ADVISORY_UTILITY_NOT_ATTACK_TRUTH"
    )
    ground_truth_digest: Hash

    @model_validator(mode="after")
    def integrity(self) -> Self:
        if len({c.incident_id for c in self.cases}) != len(self.cases):
            raise ValueError("Duplicate evaluation incident")
        if any(label.dataset_id != self.dataset_id for c in self.cases for label in c.labels):
            raise ValueError("Dataset label binding mismatch")
        if self.ground_truth_digest != content_digest_payload(
            {"cases": [c.model_dump(mode="json") for c in self.cases]}
        ):
            raise ValueError("Ground truth digest mismatch")
        return self


def fixture_dataset() -> EvaluationDataset:
    # Labels are authored BEFORE replay, never read from detection output or scenario expectations.
    specs = [
        ("normal", "Controlled normal authentication", [ssh("Accepted")], [0], set()),
        ("single", "Single test failure is not an attack", [ssh("Failed")], [0], set()),
        (
            "repeated",
            "Candidate repeat pattern, not proven malicious",
            [ssh("Failed")] * 5,
            list(range(5)),
            {"REPEATED_AUTH_FAILURE", "REPEATED_ACCOUNT_FAILURE"},
        ),
        (
            "multiple",
            "Multiple account candidate",
            [ssh("Failed", f"fixture-{i}") for i in range(3)],
            list(range(3)),
            {"MULTI_ACCOUNT_FAILURE"},
        ),
        (
            "transition",
            "Failure followed by success candidate",
            [ssh("Failed"), ssh("Accepted")],
            [0, 1],
            {"FAILURE_THEN_SUCCESS"},
        ),
        (
            "sudo",
            "PAM module failure, not final sudo denial",
            [PAM],
            [0],
            {"SUDO_PAM_MODULE_FAILURE"},
        ),
        (
            "boundary",
            "Below threshold in each of two windows",
            [ssh("Failed")] * 4,
            [0, 1, 300, 301],
            set(),
        ),
        (
            "late",
            "Reference repeat pattern but arrivals quarantined as late",
            [ssh("Failed")] * 5 + [ssh("Accepted")],
            [0, 1, 2, 3, 4, 120],
            {"REPEATED_AUTH_FAILURE", "REPEATED_ACCOUNT_FAILURE"},
        ),
        (
            "duplicate",
            "Same repeat records replayed twice",
            [ssh("Failed")] * 5,
            list(range(5)),
            {"REPEATED_AUTH_FAILURE", "REPEATED_ACCOUNT_FAILURE"},
        ),
        (
            "unsupported",
            "Untrusted logger record is not authentication evidence",
            ["unsupported session message"],
            [0],
            set(),
        ),
        (
            "benign-burst",
            "Operator-labelled authorized failure test; alert is undesired",
            [ssh("Failed")] * 5,
            list(range(5)),
            set(),
        ),
    ]
    cases = []
    for name, description, messages, seconds, positive in specs:
        scenario = Scenario(scenario_id=name, messages=tuple(messages))
        identity = uuid5(NAMESPACE_URL, DATASET + ":" + name)
        events = []
        for i, second in enumerate(seconds):
            event = fixture_event(
                scenario, i, identity, timestamp=START + timedelta(seconds=second)
            )
            events.append(
                CommonEvent.model_validate(
                    event.model_dump()
                    | {"ingestion_timestamp": START + timedelta(seconds=max(seconds) + 30)}
                )
            )
        labels = []
        windows = sorted({int(e.event_timestamp.timestamp()) // 300 for e in events})
        for window in windows:
            begin = START.fromtimestamp(window * 300, START.tzinfo)
            selected = [
                e for e in events if begin <= e.event_timestamp < begin + timedelta(seconds=300)
            ]
            for rule in RULES:
                labels.append(
                    GroundTruth(
                        dataset_id=DATASET,
                        scenario_id=name,
                        incident_id=identity,
                        event_ids=tuple(e.event_id for e in selected),
                        ground_truth_label="EXPECTED_ADVISORY"
                        if rule in positive
                        else "NO_ADVISORY_EXPECTED",
                        expected_rule_id=rule,
                        event_timestamp=selected[-1].event_timestamp,
                        window_start=begin,
                        window_end=begin + timedelta(seconds=300),
                        source_origin="FIXTURE",
                        evidence_references=tuple(e.source_digest for e in selected),
                        label_provenance="developer-authored-independent-advisory-spec:1.0.0",
                    )
                )
        order = tuple(range(len(events)))
        if name == "late":
            order = (5, 0, 1, 2, 3, 4)
        if name == "duplicate":
            order += order
        cases.append(
            EvaluationCase(
                case_id=name,
                description=description,
                incident_id=identity,
                events=tuple(events),
                arrival_order=order,
                labels=tuple(labels),
            )
        )
    payload = [c.model_dump(mode="json") for c in cases]
    return EvaluationDataset(
        cases=tuple(cases), ground_truth_digest=content_digest_payload({"cases": payload})
    )


def metrics(counts: dict[str, int]) -> dict[str, float | None]:
    if any(type(value) is not int or value < 0 for value in counts.values()):
        raise ValueError("Invalid confusion matrix count")
    tp, fp, tn, fn = (counts.get(key, 0) for key in ("TP", "FP", "TN", "FN"))

    def divide(n, d):
        return n / d if d else None

    return {
        "precision": divide(tp, tp + fp),
        "recall": divide(tp, tp + fn),
        "f1": divide(2 * tp, 2 * tp + fp + fn),
        "false_positive_rate": divide(fp, fp + tn),
        "false_negative_rate": divide(fn, fn + tp),
    }


def evaluate(
    dataset: EvaluationDataset, *, repeated_failures: int = 5, multiple_accounts: int = 3
) -> dict:
    dataset = EvaluationDataset.model_validate_json(dataset.model_dump_json())
    totals = Counter()
    per_rule = {rule: Counter() for rule in RULES}
    cases = []
    for case in dataset.cases:
        with TemporaryDirectory(prefix="soc-detection-eval-") as temp:
            root = Path(temp) / "private"
            pipeline = open_pipeline(root, case.incident_id, create=True)
            config = RuntimeConfig(
                incident_id=case.incident_id,
                repeated_failures=repeated_failures,
                multiple_accounts=multiple_accounts,
            )
            elapsed = perf_counter()
            duplicate_events = 0
            with exclusive_runtime_lock(root / "writer.lock"):
                for index in case.arrival_order:
                    duplicate_events += not pipeline.queue.enqueue(case.events[index])
                    pipeline.step()
                findings = correlate(pipeline, config)  # The real Continuous Runtime engine.
            elapsed = perf_counter() - elapsed
            # Fixed fixture processing clock; never presented as measured production latency.
            processed_at = max(e.event_timestamp for e in case.events) + timedelta(seconds=10)
            detected = {(int(f.first_seen.timestamp()) // 300, f.rule_id) for f in findings}
            labelled = {
                (int(label.window_start.timestamp()) // 300, label.expected_rule_id)
                for label in case.labels
            }
            if not detected <= labelled:
                raise ValueError("Detection lacks independent ground-truth coverage")
            outcomes = []
            for label in case.labels:
                key = (int(label.window_start.timestamp()) // 300, label.expected_rule_id)
                expected = label.ground_truth_label == "EXPECTED_ADVISORY"
                present = key in detected
                kind = (
                    "TP"
                    if expected and present
                    else "FN"
                    if expected
                    else "FP"
                    if present
                    else "TN"
                )
                totals[kind] += 1
                per_rule[label.expected_rule_id][kind] += 1
                outcomes.append(
                    {
                        "window_start": label.window_start.isoformat(),
                        "rule": label.expected_rule_id,
                        "classification": kind,
                        "label_provenance": label.label_provenance,
                    }
                )
            cases.append(
                {
                    "case_id": case.case_id,
                    "outcomes": outcomes,
                    "finding_count": len(findings),
                    "unique_rule_window_detections": len(detected),
                    "duplicate_events": duplicate_events,
                    "fixture_latency_seconds": [
                        (processed_at - f.last_seen).total_seconds() for f in findings
                    ],
                    "replay_elapsed_seconds": elapsed,
                }
            )
    counts = {k: totals[k] for k in ("TP", "FP", "TN", "FN")}
    try:
        revision = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    except (OSError, subprocess.CalledProcessError):
        revision = "UNKNOWN"
    sources = (
        Path(__file__),
        Path(__file__).parents[1] / "linux_runtime/findings.py",
        Path(__file__).parents[1] / "security_ai/operational/authentication_detection.py",
        Path(__file__).parents[1] / "security_ai/operational/native_authentication.py",
        Path(__file__).parents[1] / "security_ai/operational/source_store.py",
        Path(__file__).parents[1] / "demo/scenario_pipeline.py",
        Path(__file__).parents[1] / "demo/scenario_models.py",
        Path(__file__).parents[1] / "realtime/queue.py",
    )
    import hashlib

    core = {
        "dataset_id": dataset.dataset_id,
        "ground_truth_digest": dataset.ground_truth_digest,
        "source_origin": sorted({label.source_origin for c in dataset.cases for label in c.labels}),
        "unit": "INCIDENT_UTC_FIVE_MINUTE_WINDOW_RULE",
        "deduplication": "OR per rule/window",
        "label_semantics": dataset.label_semantics,
        "case_count": len(cases),
        "unit_count": sum(counts.values()),
        "label_distribution": {
            "positive": counts["TP"] + counts["FN"],
            "negative": counts["TN"] + counts["FP"],
        },
        "configuration": {
            "repeated_failures": repeated_failures,
            "multiple_accounts": multiple_accounts,
            "assurance": "EXAMPLE_UNVALIDATED",
        },
        "code_version": revision,
        "source_sha256": {
            str(p.relative_to(Path(__file__).parents[2])): hashlib.sha256(
                p.read_bytes()
            ).hexdigest()
            for p in sources
        },
        "confusion_matrix": counts,
        "metrics": metrics(counts),
        "per_rule": {
            rule: {"counts": {k: v[k] for k in ("TP", "FP", "TN", "FN")}, "metrics": metrics(v)}
            for rule, v in per_rule.items()
        },
        "cases": [{k: v for k, v in c.items() if k != "replay_elapsed_seconds"} for c in cases],
        "latency_assurance": "SIMULATED_FIXTURE_CLOCK_NOT_PRODUCTION_LATENCY",
    }
    latencies = sorted(x for c in cases for x in c["fixture_latency_seconds"])
    core["detection_latency_distribution"] = {
        "sample_count": len(latencies),
        "min": min(latencies) if latencies else None,
        "max": max(latencies) if latencies else None,
        "median": median(latencies) if latencies else None,
    }
    core["false_positives"] = [
        {"case_id": c["case_id"], **o}
        for c in cases
        for o in c["outcomes"]
        if o["classification"] == "FP"
    ]
    core["false_negatives"] = [
        {"case_id": c["case_id"], **o}
        for c in cases
        for o in c["outcomes"]
        if o["classification"] == "FN"
    ]
    return core | {
        "evaluation_digest": content_digest_payload(core),
        "measured_replay_seconds": [c["replay_elapsed_seconds"] for c in cases],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    dataset = fixture_dataset()
    result = evaluate(dataset)
    args.output.with_suffix(".ground-truth.json").write_text(
        dataset.model_dump_json(indent=2) + "\n"
    )
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    report = args.output.with_suffix(".md")
    report.write_text(
        "# Fixture Authentication Detection Evaluation\n\n"
        + "Unit: Incident × UTC five-minute window × rule. Not attack accuracy.\n\n"
        + f"Confusion Matrix: {result['confusion_matrix']}\n\nMetrics: {result['metrics']}\n\n"
        + f"FP: {result['false_positives']}\n\nFN: {result['false_negatives']}\n\n"
        + f"Ground Truth Digest: {result['ground_truth_digest']}\n"
    )
    print(
        json.dumps(
            {
                "cases": result["case_count"],
                "units": result["unit_count"],
                "counts": result["confusion_matrix"],
                "metrics": result["metrics"],
            }
        )
    )


if __name__ == "__main__":
    main()
