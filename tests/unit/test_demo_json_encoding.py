"""UTF-8 manifests remain portable under a CP949 default text encoding."""

from pathlib import Path
from uuid import uuid4

import pytest
from pydantic import ValidationError

from soc_agent.demo.command_center import MARKER, DemoManifest, manifest, prepare
from soc_agent.live import publish


@pytest.fixture
def cp949_default(monkeypatch):
    original = Path.open

    def open_with_cp949(self, mode="r", buffering=-1, encoding=None, errors=None, newline=None):
        if "b" not in mode and encoding is None:
            encoding = "cp949"
        return original(self, mode, buffering, encoding, errors, newline)

    monkeypatch.setattr(Path, "open", open_with_cp949)


def test_snapshot_and_live_manifest_utf8_round_trip(tmp_path, cp949_default):
    prepare(tmp_path)
    snapshot = DemoManifest()
    assert "—" in snapshot.label
    assert (tmp_path / MARKER).read_bytes() == snapshot.model_dump_json().encode("utf-8")
    assert manifest(tmp_path) == snapshot
    prepare(tmp_path)  # Reopen, without resetting the existing manifest.
    live = DemoManifest(mode="live-local", incidents=(uuid4(),))
    publish(tmp_path, live)
    assert (tmp_path / MARKER).read_bytes() == live.model_dump_json().encode("utf-8")
    assert manifest(tmp_path) == live
    assert not (tmp_path / (MARKER + ".pending")).exists()


@pytest.mark.parametrize("label", ("합성 데모 — 未確認", "DEMO / SYNTHETIC"))
def test_utf8_decoding_keeps_exact_label_validation(tmp_path, label):
    (tmp_path / MARKER).write_text(DemoManifest(label=label).model_dump_json(), encoding="utf-8")
    with pytest.raises(ValueError, match="Explicit synthetic demo directory required"):
        manifest(tmp_path)


@pytest.mark.parametrize("content", (b"\xff", b'{"mode":"invalid"}'))
def test_invalid_encoding_and_schema_remain_rejected(tmp_path, content):
    (tmp_path / MARKER).write_bytes(content)
    with pytest.raises((UnicodeDecodeError, ValidationError)):
        manifest(tmp_path)
