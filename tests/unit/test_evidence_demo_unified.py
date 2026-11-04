"""Presentation timing and read-only boundary regressions; no live API/model execution."""

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

RELEASE = Path(__file__).resolve().parents[2] / "releases/evidence-demo-20261104"
PYTHON = RELEASE.parent / "research-mvp/.venv/bin/python"


def module(name):
    path = RELEASE / f"{name}.py"
    if not path.exists():
        pytest.skip("Local frozen Evidence Demo is not installed")
    spec = importlib.util.spec_from_file_location(name, path)
    loaded = importlib.util.module_from_spec(spec)
    sys.modules[name] = loaded
    spec.loader.exec_module(loaded)
    return loaded


@pytest.fixture(scope="module")
def viewer():
    return module("unified_evidence")


def test_auto_replay_is_exactly_five_minutes_and_stops(viewer):
    clock = viewer.ReplayClock()
    assert sum(stage.seconds for stage in viewer.STAGES) == 300
    clock.playing = True
    for i, stage in enumerate(viewer.STAGES):
        assert clock.index == i
        clock.advance(stage.seconds - 0.5)
        assert clock.index == i
        clock.advance(0.5)
    assert clock.finished and not clock.playing and clock.remaining == 0
    clock.advance(1000)
    assert clock.index == 7


def test_pause_resume_manual_navigation_and_delayed_ticks(viewer):
    clock = viewer.ReplayClock()
    clock.advance(200)
    assert clock.index == 0 and clock.remaining == 35
    clock.playing = True
    clock.advance(70)
    assert clock.index == 2 and clock.remaining == 35
    clock.playing = False
    clock.advance(500)
    assert clock.remaining == 35
    clock.select(5)
    assert clock.remaining == 60 and not clock.playing
    clock.playing = True
    clock.advance(10000)
    assert clock.finished and clock.index == 7
    clock.select(0)
    assert not clock.finished and clock.remaining == 35
    with pytest.raises(ValueError):
        clock.select(8)
    with pytest.raises(ValueError):
        clock.advance(-1)


def test_stage_sources_do_not_join_api_to_native(viewer):
    assert [s.source for s in viewer.STAGES] == ["native"] * 5 + [
        "api",
        "authentication_if",
        "native",
    ]


def test_tampered_manifest_files_fail_closed(tmp_path):
    entry = module("evidence_viewer")
    data = tmp_path / "record.json"
    data.write_text("original")
    manifest = {
        "purpose": "PRESERVED_EVIDENCE_VIEW_ONLY",
        "files": {"record.json": entry.sha256(data)},
    }
    (tmp_path / "manifest.json").write_text(json.dumps(manifest))
    assert entry.verify(tmp_path) == manifest
    data.write_text("modified")
    with pytest.raises(ValueError, match="DEMO_INTEGRITY_MISMATCH"):
        entry.verify(tmp_path)


def test_guard_denies_mutation_execution_network_and_sqlite_writes(tmp_path):
    if not PYTHON.exists():
        pytest.skip("Pinned interpreter not installed")
    script = r"""
import sys, sqlite3, socket, subprocess
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from evidence_viewer import install_read_only_guard
root=Path(sys.argv[2]); db=root/'evidence.sqlite'
with sqlite3.connect(db) as c:
    c.execute('CREATE TABLE proof (value TEXT)')
violations=install_read_only_guard([root])
for operation in (lambda: (root/'new').write_text('x'),
                  lambda: db.unlink(),
                  lambda: subprocess.run(['/bin/true']),
                  lambda: socket.socket().connect(('127.0.0.1',9))):
    try: operation()
    except PermissionError: pass
    else: raise AssertionError('boundary allowed a forbidden operation')
with sqlite3.connect(db) as c:
    assert c.execute('SELECT COUNT(*) FROM proof').fetchone()[0] == 0
    try: c.execute("INSERT INTO proof VALUES ('forbidden')")
    except sqlite3.OperationalError as error: assert 'readonly' in str(error)
    else: raise AssertionError('SQLite write allowed')
assert len(violations)==4
"""
    result = subprocess.run(
        [str(PYTHON), "-I", "-B", "-c", script, str(RELEASE), str(tmp_path)],
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert result.returncode == 0, result.stderr


def test_original_evidence_projection_and_failure_states():
    if not PYTHON.exists() or not (RELEASE / "manifest.json").exists():
        pytest.skip("Pinned local evidence not installed")
    script = r"""
import json, sys
from pathlib import Path
release=Path(sys.argv[1]);sys.path[:0]=[str(release),str(release/'python')]
from evidence_viewer import install_read_only_guard, verify
manifest=verify(release)
violations=install_read_only_guard([Path(p) for p in manifest['protected']])
from unified_evidence import load_evidence, stage_data
value=load_evidence(manifest)
n=value.native['continuous']
assert n['metrics']['packets']==54 and n['dns']['counts']['MATCHED_RESPONSE']==3
assert len(value.native['research']['records'])==8
assert len(n['recent_results'])==2 and len(n['orchestration']['tasks'])==5
classes={r['classification'] for r in n['recent_results']}
assert classes=={'UNKNOWN_ANOMALY','DATA_QUALITY_FAILURE'}
assert {r['investigation']['llm_mode'] for r in n['orchestration']['tasks']}=={'SCRIPTED'}
assert value.api['llm_mode']=='REAL_API' and value.api['external_provider_calls']==2
assert value.api['incident_id'] not in {r['incident_id'] for r in n['recent_results']}
assert value.sources['api'].session is None
assert value.sources['native'].session is None
assert len(value.sources['native'].capture_sessions['TCX'])==2
assert sum(f['packet_count'] for f in value.flows)==54
assert value.authentication_if['audit']=='VERIFIED'
assert value.authentication_if['predictions'][0]['prediction']=='anomaly'
assert value.authentication_if['predictions'][0]['score']==0.9666666666666667
assert value.authentication['collector_state']=='SOURCE_UNAVAILABLE'
assert value.authentication['inference_status']=='NOT_INFERABLE'
assert value.authentication_parent['cleanup']=='UNVERIFIED'
assert value.replay['continuous']['metrics']['predictions']==406
assert value.replay['continuous']['queue']['PENDING']==4
for i in range(8):
    detail=stage_data(value,i)
    assert detail['source']['trial_date'] and detail['source']['identity']
assert not violations
"""
    result = subprocess.run(
        [str(PYTHON), "-I", "-B", "-c", script, str(RELEASE)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr


def test_cosmetic_telemetry_is_deterministic_and_separate_from_evidence():
    metrics = module("unified_metrics")
    first = metrics.demo_telemetry()
    assert first == metrics.demo_telemetry()
    assert len(first) == 60
    assert all(0 <= p.values["cpu"] <= 100 for p in first)
    assert all(p.values["rss"] > 0 for p in first)
    assert "prediction" not in first[0].values


def test_progressive_reveal_waits_for_each_stage_and_freezes_on_pause(viewer):
    clock = viewer.ReplayClock()
    assert viewer.revealed_count(54, 0, clock) == 0
    assert viewer.revealed_count(8, 2, clock) == 0
    clock.playing = True
    counts = []
    for _ in range(26):
        clock.advance(1)
        counts.append(viewer.revealed_count(54, 0, clock))
    assert counts == sorted(set(counts)) and 0 < counts[0] < counts[-1] < 54
    clock.playing = False
    clock.advance(20)
    assert viewer.revealed_count(54, 0, clock) == counts[-1]
    clock.select(2)
    assert viewer.revealed_count(54, 0, clock) == 54
    assert viewer.revealed_count(8, 2, clock) == 0
    clock.playing = True
    clock.advance(30)
    assert viewer.revealed_count(8, 2, clock) == 8
    assert viewer.revealed_count(2, 3, clock) == 0


def test_model_receipts_appear_early_without_waiting_for_model_page(viewer):
    clock = viewer.ReplayClock()
    clock.playing = True
    clock.advance(6.5)
    assert clock.index == 0 and viewer.model_revealed_count(clock) == 1
    clock.advance(17.5)
    assert clock.index == 0 and viewer.model_revealed_count(clock) == 8
    clock.playing = False
    clock.advance(999)
    assert viewer.model_revealed_count(clock) == 8


def test_llm_replay_reveals_saved_plan_tool_and_assessment_without_mutation(viewer):
    from copy import deepcopy
    from types import SimpleNamespace

    metrics = module("unified_metrics")
    report = {
        "investigation_detail": {
            "plan": {
                "goal": "Inspect evidence",
                "steps": [{"tool_name": "read_local_source_report", "status": "completed"}],
            },
            "assessment": {
                "threat_assessment": {
                    "severity": "info",
                    "confidence": 0.5,
                    "summary": "Saved assessment",
                }
            },
        }
    }
    original = deepcopy(report)
    clock = viewer.ReplayClock()
    clock.playing = True
    app = SimpleNamespace(
        clock=clock, presentation_animated=True, evidence=SimpleNamespace(api=report)
    )
    assert "Inspect evidence" not in metrics.llm_body(app)
    clock.advance(24)
    assert "Inspect evidence" in metrics.llm_body(app)
    assert "read_local_source_report" not in metrics.llm_body(app)
    clock.advance(10)
    assert "read_local_source_report" in metrics.llm_body(app)
    assert "Saved assessment" not in metrics.llm_body(app)
    clock.advance(14)
    assert "Saved assessment" in metrics.llm_body(app)
    assert "separate trial" in metrics.llm_body(app)
    assert report == original


def test_presentation_queue_accumulates_then_drains():
    metrics = module("unified_metrics")
    assert metrics.presentation_queue(0, 0) == 0
    assert metrics.presentation_queue(16, 1) > 0
    assert metrics.presentation_queue(30, 3) > 0
    assert metrics.presentation_queue(54, 8) == 0
    assert metrics.presentation_queue(0, 8) == 0
