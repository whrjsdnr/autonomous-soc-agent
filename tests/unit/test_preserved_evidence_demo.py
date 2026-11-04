"""Presentation guards must not grant execution or mutate retained results."""

import importlib.util
import json
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts/demo/evidence_viewer.py"
spec = importlib.util.spec_from_file_location("evidence_viewer", SCRIPT)
viewer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(viewer)


def test_changed_retained_result_blocks_view(tmp_path):
    evidence = tmp_path / "result.json"
    evidence.write_text('{"mode":"REAL_API","historical":true}')
    manifest = {
        "purpose": "PRESERVED_EVIDENCE_VIEW_ONLY",
        "files": {"result.json": viewer.sha256(evidence)},
    }
    (tmp_path / "manifest.json").write_text(json.dumps(manifest))
    assert viewer.verify(tmp_path) == manifest
    evidence.write_text('{"historical":false}')
    with pytest.raises(ValueError, match="DEMO_INTEGRITY_MISMATCH"):
        viewer.verify(tmp_path)


@pytest.mark.parametrize(
    "operation",
    [
        "(root/'result').write_text('changed')",
        "(root/'result').unlink()",
        "subprocess.run([sys.executable, '-c', 'raise AssertionError()'])",
        "socket.socket().connect(('127.0.0.1', 53))",
        "os.kill(os.getpid(), 0)",
        "sys.audit('pickle.find_class', 'sklearn.ensemble', 'IsolationForest')",
    ],
)
def test_demo_denies_mutation_and_new_execution(tmp_path, operation):
    (tmp_path / "result").write_text("preserved")
    code = f"""
import os,runpy,socket,subprocess,sys
from pathlib import Path
module=runpy.run_path({str(SCRIPT)!r})
root=Path({str(tmp_path)!r})
blocked=module['install_read_only_guard']([root])
try:
    {operation}
except PermissionError:
    assert blocked
else:
    raise AssertionError('Execution or mutation was allowed')
assert (root/'result').read_text()=='preserved'
"""
    subprocess.run([sys.executable, "-B", "-c", code], check=True, timeout=10)


def test_sqlite_is_read_only_without_modifying_original(tmp_path):
    database = tmp_path / "evidence.sqlite"
    with sqlite3.connect(database) as connection:
        connection.execute("CREATE TABLE evidence (value TEXT)")
        connection.execute("INSERT INTO evidence VALUES ('preserved')")
    before = viewer.sha256(database)
    code = f"""
import runpy,sqlite3
from pathlib import Path
module=runpy.run_path({str(SCRIPT)!r})
root=Path({str(tmp_path)!r})
module['install_read_only_guard']([root])
with sqlite3.connect((root/'evidence.sqlite').as_uri()+'?mode=rw', uri=True) as c:
    assert c.execute('SELECT value FROM evidence').fetchone()==('preserved',)
    try:
        c.execute("DELETE FROM evidence")
    except sqlite3.OperationalError as error:
        assert 'readonly' in str(error)
    else:
        raise AssertionError('SQL mutation allowed')
"""
    subprocess.run([sys.executable, "-B", "-c", code], check=True, timeout=10)
    assert viewer.sha256(database) == before
