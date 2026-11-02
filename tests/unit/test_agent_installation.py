"""Actual three-write manifest/Launcher agreement, no Root source execution or writes."""

import hashlib
import json
from pathlib import Path

import pytest

from soc_agent.agent_native import (
    ROOT_TARGETS,
    bind_installation_scope,
    installation_plan,
    installation_write_scope,
)


def rows():
    return [
        dict(target=p, current_sha256="a" * 64, new_sha256=("b" if i < 3 else "a") * 64)
        for i, p in enumerate(sorted(ROOT_TARGETS))
    ]


def test_exact_three_changes_are_not_four_and_unchanged_paths_stay_bound():
    manifest = rows()
    declared = tuple(r["target"] for r in manifest[:3])
    assert installation_write_scope(manifest, declared) == declared
    with pytest.raises(ValueError, match="WRITE_SCOPE_MISMATCH"):
        installation_write_scope(manifest, declared + (manifest[3]["target"],))
    # Same number is insufficient: a different target must also be rejected.
    with pytest.raises(ValueError, match="WRITE_SCOPE_MISMATCH"):
        installation_write_scope(manifest, declared[:2] + (manifest[3]["target"],))
    with pytest.raises(ValueError, match="WRITE_SCOPE_MISMATCH"):
        installation_write_scope(manifest + [manifest[0]], declared)


def test_mode_repair_is_a_write_and_requires_its_exact_target():
    manifest = rows()
    manifest[3]["repair_mode"] = True
    with pytest.raises(ValueError, match="WRITE_SCOPE_MISMATCH"):
        installation_write_scope(manifest, tuple(r["target"] for r in manifest[:3]))
    assert len(installation_write_scope(manifest, tuple(r["target"] for r in manifest[:4]))) == 4


def test_preview_checks_actual_manifest_and_pinned_declaration_without_exec(tmp_path, monkeypatch):
    review = tmp_path / "review"
    (review / "execution").mkdir(parents=True)
    manifest = rows()
    original = Path.read_bytes
    old = b"original root configuration"
    changed = b"reviewed configuration"
    for i, row in enumerate(manifest):
        path = review / f"source-{i}"
        path.write_bytes(changed if i < 3 else old)
        path.chmod(0o600)
        row.update(
            new_source=str(path),
            current_sha256=hashlib.sha256(old).hexdigest(),
            new_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        )
    declaration = tuple(r["target"] for r in manifest[:3])
    entry = review / "execution/root-trial.py"
    template = (
        "def install(manifest):\n"
        "    rows = manifest['replacements']\n"
        "    assert len(rows) == 8 and sum(r['current_sha256'] != r['new_sha256'] "
        "for r in rows) == 4, 'FIXED_INSTALLATION_WRITE_SCOPE'\n"
        "    raise RuntimeError('INSTALL_BODY_MUST_NOT_RUN_DURING_PREVIEW')\n"
        "raise RuntimeError('NEVER_EXECUTE_ROOT_ENTRY')\n"
    )
    entry.write_text(bind_installation_scope(template, manifest))
    path = review / "root-install-manifest-v3.json"
    path.write_text(json.dumps(dict(replacements=manifest)))
    request = dict(files={path.name: dict(path=str(path))})
    # Only the Root filesystem bytes are simulated. Parsing, source pin checks,
    # change computation and installed-vs-candidate comparisons run unchanged.
    monkeypatch.setattr(
        Path, "read_bytes", lambda p: old if str(p) in ROOT_TARGETS else original(p)
    )
    result = installation_plan(review, request)
    assert result["fixed_paths"] == 8 and result["unchanged_paths"] == 5
    assert result["write_targets"] == list(declaration)
    assert result["root_commands_executed"] is False
    entry.write_text(
        entry.read_text().replace(repr(declaration), repr(declaration + (manifest[3]["target"],)))
    )
    with pytest.raises(ValueError, match="WRITE_SCOPE_MISMATCH"):
        installation_plan(review, request)

    entry.write_text("# Previous copied hardcoded-four installer, no declaration\n")
    with pytest.raises(ValueError, match="WRITE_DECLARATION_REQUIRED"):
        installation_plan(review, request)


def test_prepared_installer_checks_three_actual_writes_before_any_io():
    manifest = rows()
    template = (
        "from __future__ import annotations\n"
        "def install(manifest):\n"
        "    rows = manifest['replacements']\n"
        "    assert len(rows) == 8 and sum(r['current_sha256'] != r['new_sha256'] "
        "for r in rows) == 4, 'FIXED_INSTALLATION_WRITE_SCOPE'\n"
        "    return 'VALIDATED_NO_IO'\n"
    )
    prepared = bind_installation_scope(template, manifest)
    scope = {}
    exec(compile(prepared, "isolated-installer-no-io", "exec"), scope)
    assert scope["install"](dict(replacements=manifest)) == "VALIDATED_NO_IO"
    changed = [dict(r) for r in manifest]
    changed[3]["new_sha256"] = "b" * 64
    with pytest.raises(AssertionError, match="FIXED_INSTALLATION_WRITE_SCOPE"):
        scope["install"](dict(replacements=changed))
    changed = [dict(r) for r in manifest]
    changed[0]["target"] = "/etc/UNAPPROVED"
    with pytest.raises(AssertionError, match="FIXED_INSTALLATION_WRITE_SCOPE"):
        scope["install"](dict(replacements=changed))


def test_original_installer_three_writes_eight_backups_and_five_untouched(tmp_path, monkeypatch):
    import ast
    import os
    import stat

    template = (Path(__file__).parents[1] / "fixtures/root_install_fragment.txt").read_text()
    manifest = rows()
    locations = {}
    unchanged = {}
    for index, row in enumerate(manifest):
        target = tmp_path / "root" / row["target"].lstrip("/")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(b"old")
        target.chmod(0o644)
        locations[row["target"]] = target
        source = tmp_path / f"candidate-{index}"
        source.write_bytes(b"new" if index < 3 else b"old")
        row.update(
            current_sha256=hashlib.sha256(b"old").hexdigest(),
            new_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
            new_source=str(source),
        )
        if index >= 3:
            unchanged[str(target)] = (target.stat().st_ino, target.stat().st_mtime_ns)
    fixed = bind_installation_scope(template, manifest)
    tree = ast.parse(fixed)
    # Only the exact filesystem fragment runs. Every Root path is mapped inside
    # tmp_path, and UID checks simulate the privilege boundary. No system command.
    original_stat, original_lstat = Path.stat, Path.lstat

    def owned(value):
        fields = list(value)
        fields[4] = 0
        fields[0] &= ~0o022  # Simulated trusted Root ancestors, including /tmp.
        return os.stat_result(fields)

    monkeypatch.setattr(Path, "stat", lambda p, **kw: owned(original_stat(p, **kw)))
    monkeypatch.setattr(Path, "lstat", lambda p: owned(original_lstat(p)))

    def local_path(value):
        return locations.get(str(value), Path(value))

    events = {}
    namespace = dict(
        Path=local_path,
        os=os,
        stat=stat,
        hashlib=hashlib,
        sha=lambda p: hashlib.sha256(p.read_bytes()).hexdigest(),
        evidence=lambda name, value: events.update({name: value}),
    )
    exec(compile(tree, "isolated-original-installer", "exec"), namespace)
    backup = tmp_path / "backups"
    namespace["install"](
        dict(replacements=manifest, backup_directory=str(backup), preserve_and_verify={})
    )
    assert len(list(backup.iterdir())) == 8
    summary = events["installed-files.json"]
    assert len(summary["replaced"]) == 3
    assert len(summary["verified_unchanged"]) == 5
    for index, row in enumerate(manifest):
        target = locations[row["target"]]
        assert target.read_bytes() == (b"new" if index < 3 else b"old")
        if index >= 3:
            assert (original_stat(target).st_ino, original_stat(target).st_mtime_ns) == unchanged[
                str(target)
            ]
    assert all(p.read_bytes() == b"old" for p in backup.iterdir())
