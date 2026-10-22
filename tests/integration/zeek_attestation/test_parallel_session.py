"""Mock Root/traffic entry, real capless file-only Zeek; never capture or DNS I/O."""

import io
import json
import os
import subprocess
import time
from types import SimpleNamespace

import pytest

from soc_agent.security_ai.collectors import offload_session as session


@pytest.mark.parametrize("authentication_failed", [False, True, "no_diagnostic", "supervised"])
def test_authenticated_session_waits_for_real_zeek_ready_before_start(
    tmp_path, monkeypatch, authentication_failed
):
    candidate = tmp_path / "candidate"
    supervised_mode = authentication_failed == "supervised"
    if supervised_mode:
        authentication_failed = False

    # TTY/START lifecycle uses an explicitly inert ordinary-user image. The real
    # standalone 0.5.16 installation gate is not this mocked Root boundary.
    def inert_image(output, *, analysis=False):
        import hashlib

        assert analysis
        release = session.installed_release()  # Read-only current installation.
        body = b"raise SystemExit('MOCK_ROOT_IMAGE_MUST_NOT_EXECUTE')\n"
        output.write_bytes(body)
        output.chmod(0o400)
        return session.UnifiedImage(
            path=output.absolute(),
            sha256=hashlib.sha256(body).hexdigest(),
            manifest=release.identity,
            previous_manifest=release.identity,
            version=release.version,
            action="CHECK",
        )

    monkeypatch.setattr(session, "prepare_image", inert_image)
    identity = session.prepare(candidate)
    scope = json.loads((candidate / "release.json").read_text())["capture_scope_digest"]
    real_popen, real_run = subprocess.Popen, subprocess.run
    order = []

    from soc_agent.security_ai.collectors.start_channel import (
        start_connect,
        start_peer,
        start_receive,
    )

    binding = None

    class RootOutput(io.StringIO):
        def readline(self, *args):
            text = super().readline(*args)
            if '"DNS_COPY_READY"' in text:
                start_receive(root.control, binding, time.monotonic() + 1)
                root.control.close()
                order.append("start")
            return text

    class FakeRoot:
        pid = os.getpid()

        def __init__(self):
            now = time.monotonic()
            if authentication_failed == "no_diagnostic":
                self.stdout = RootOutput("")
                return
            if authentication_failed:
                self.stdout = RootOutput(
                    json.dumps(
                        dict(
                            state="DNS_COPY_ROOT_ERROR",
                            stage="PASSWORD_POLICY",
                            api="_candidate_policy",
                            original_code="UNIFIED_PASSWORD_POLICY_REJECTED",
                            errno=None,
                            exit_code=1,
                        )
                    )
                    + "\n"
                )
                return
            self.control = start_connect(os.getuid(), os.getgid(), os.getpid(), binding, now + 1)
            self.stdout = RootOutput(
                "\n".join(
                    json.dumps(row)
                    for row in [
                        dict(
                            state="DNS_COPY_AUTHENTICATED",
                            root_pid=os.getpid(),
                            binding=binding,
                            scope_digest=scope,
                            session_started=now,
                            deadline=now + 10,
                        ),
                        dict(
                            state="DNS_COPY_READY",
                            scope_digest=scope,
                            capabilities={
                                key: 0 for key in ["CapEff", "CapPrm", "CapInh", "CapAmb"]
                            },
                        ),
                        dict(
                            state="CLOSED",
                            scope_digest=scope,
                            image_sha256=identity["image"],
                            manifest=json.loads((candidate / "release.json").read_text())[
                                "base_manifest"
                            ],
                            received=0,
                            accepted=0,
                            rejected=0,
                            final_chain="0" * 64,
                            socket_packets=0,
                            socket_drops=0,
                            capture_elapsed_seconds=0.01,
                        ),
                    ]
                )
                + "\n"
            )

        def wait(self, **kwargs):
            if hasattr(self, "control"):
                self.control.close()
            return 1 if authentication_failed else 0

    root = None

    def launch(argv, **kwargs):
        nonlocal root
        if argv == ["MOCK_ROOT_NO_EXECUTION"]:
            assert kwargs["stdin"] is None, "OS authentication must inherit the terminal"
            root = FakeRoot()
            return root
        return real_popen(argv, **kwargs)

    def run(argv, **kwargs):
        if argv == ["/usr/bin/ss", "-lnut", "sport = :53"]:
            # Only the modeled probe is used; no test DNS server or query runs.
            return subprocess.CompletedProcess(
                argv, 0, "tcp LISTEN 127.0.0.53:53\nudp UNCONN 127.0.0.53:53\n", ""
            )
        if "--approve" not in argv:
            return real_run(argv, **kwargs)
        order.append("mock_probe")
        receipt = dict(
            state="COMPLETED",
            records=[
                dict(source=["127.0.0.1", 45000], destination=["127.0.0.53", 53], transport=p)
                for p in ["UDP", "TCP"]
            ],
        )
        from pathlib import Path

        Path(argv[argv.index("--receipt") + 1]).write_text(json.dumps(receipt))
        return subprocess.CompletedProcess(argv, 0, "", "")

    def pinned(image, wire, approval, uid, gid):
        nonlocal binding
        binding = session.start_binding(wire, image.sha256, image.manifest, approval, scope)
        return ["MOCK_ROOT_NO_EXECUTION"]

    monkeypatch.setattr(session, "pinned_command", pinned)
    # Explicit test-only ordinary-user peer stands in for Root; never Native proof.
    monkeypatch.setattr(
        session,
        "start_peer",
        lambda channel, uid, gid, pid: start_peer(channel, os.getuid(), os.getgid(), pid),
    )
    monkeypatch.setattr(session.os, "isatty", lambda fd: True)
    monkeypatch.setattr(subprocess, "Popen", launch)
    monkeypatch.setattr(subprocess, "run", run)
    from pathlib import Path

    supervised = None
    audit_events = []
    if supervised_mode:
        body = json.loads((candidate / "release.json").read_text())
        image = session.UnifiedImage.model_validate(body["image"])
        wire = session.envelope(session.installed_release())
        approval = "f" * 64
        binding = session.start_binding(wire, image.sha256, image.manifest, approval, scope)

        def start_dns():
            nonlocal root
            root = FakeRoot()
            order.append("supervised_start_no_auth")
            return root

        supervised = SimpleNamespace(
            image=image,
            release=SimpleNamespace(identity=body["base_manifest"]),
            supervisor=SimpleNamespace(start_dns=start_dns),
            ended=False,
            envelope=wire,
            approval=approval,
            _event=lambda name, **details: audit_events.append((name, details)),
        )
        monkeypatch.setattr(session, "pinned_command", lambda *a: pytest.fail("second auth"))
    if authentication_failed:
        code = (
            "DNS_COPY_ENTRY_FAILED"
            if authentication_failed == "no_diagnostic"
            else "UNIFIED_PASSWORD_POLICY_REJECTED"
        )
        with pytest.raises(ValueError, match=code):
            session.execute(
                candidate,
                identity["manifest"],
                identity["image"],
                probe=Path("tests/native_dns_live_probe.py"),
            )
        assert order == []
        name = "entry-error.json" if authentication_failed == "no_diagnostic" else "root-error.json"
        error = json.loads((candidate / "live-attempt-1" / name).read_text())
        assert error["stage"] == (
            "OS_AUTH_OR_IMAGE_ENTRY"
            if authentication_failed == "no_diagnostic"
            else "PASSWORD_POLICY"
        )
        assert error["errno"] is None and error["exit_code"] == 1
        assert not (candidate / "live-attempt-1/zeek").exists()
        with session.start_listener(os.getuid(), binding):
            pass  # Session listener released after failed authentication.
        return
    result = session.execute(
        candidate,
        identity["manifest"],
        identity["image"],
        probe=Path("tests/native_dns_live_probe.py"),
        supervised=supervised,
    )
    assert order == (["supervised_start_no_auth"] if supervised_mode else []) + [
        "start",
        "mock_probe",
    ]
    if supervised_mode:
        from soc_agent.security_ai.collectors.store import CollectorStore

        recovered = CollectorStore(Path(result["diagnostics_store"]))
        recovered.verify()  # Recovery reads the chain; never authenticates or captures.
        assert supervised.zeek_snapshot == result
        assert audit_events[0][0] == "PHASE_D_DNS_COMPLETED"
    assert result["phase_times"]["zeek_ready"] <= result["phase_times"]["capture_ready"]
    assert result["zeek_exit"]["closed_observed"] and result["zeek_exit"]["cleanup_verified"]
    assert result["verdict"] == "DNS_NATIVE_ANALYSIS_COPY_E2E_INCOMPLETE"
    assert result["forwarded_probe_packets"] == 0
    timing = json.loads((candidate / "live-attempt-1/session-timing.json").read_text())
    assert timing["worker_exited"] and timing["whole_deadline_met"]


@pytest.mark.parametrize("version", [None, "0.6.2", "0.6.3"])
def test_real_standalone_image_keeps_exact_installed_version_gate(tmp_path, monkeypatch, version):
    from soc_agent.security_ai.ebpf_tc import checksum_image

    monkeypatch.setattr(
        checksum_image,
        "installed_release",
        lambda: None if version is None else SimpleNamespace(version=version),
    )
    monkeypatch.setattr(
        checksum_image,
        "payload_from_release",
        lambda *args: pytest.fail("Unapproved installation reached payload preparation"),
    )
    output = tmp_path / "never-created.py"
    with pytest.raises(ValueError, match="CHECKSUM_INSTALLED_0516_REQUIRED"):
        checksum_image.prepare(output, analysis=True)
    assert not output.exists()
