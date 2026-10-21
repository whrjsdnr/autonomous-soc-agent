"""Exercise the real startup to the approval boundary; never call sudo or load BPF."""

import shutil
import struct

import pytest

from soc_agent.security_ai.collectors.live_contract import bundle as zeek_bundle
from soc_agent.security_ai.ebpf_tc import supervisor_startup as startup
from soc_agent.security_ai.ebpf_tc.supervisor import SupervisedSession
from soc_agent.security_ai.ebpf_tc.trust import release_approval


@pytest.fixture(scope="module")
def candidate(tmp_path_factory):
    path = tmp_path_factory.mktemp("supervisor-startup")
    directory = path / "candidate"
    image = startup.prepare(directory)
    return directory, image


@pytest.mark.parametrize(
    "mismatch",
    [None, "legacy", "namespace", "manifest", "image", "legacy_run", "session", "zeek_scope"],
)
def test_startup_validates_real_tcx_plan_before_authentication(
    candidate, tmp_path, monkeypatch, mismatch
):
    source, image = candidate
    directory = tmp_path / "candidate"
    shutil.copytree(source, directory)
    calls = []
    validated_runs = []
    original_prepare_run = startup.prepare_run

    def prepare_run(handoff, image, zeek_plan):
        if mismatch == "zeek_scope":
            zeek_plan = zeek_plan.model_copy(update={"net_namespace": "net:[1]"})
        if mismatch in {"legacy_run", "session"}:
            original_run = startup.RunIdentity

            def wrong_run(**values):
                if mismatch == "legacy_run":
                    values["scope_digest"] = startup.digest(
                        handoff.application.plan.scope.model_dump(mode="json")
                    )
                else:
                    from uuid import uuid4

                    values["application_session"] = uuid4()
                return original_run(**values)

            monkeypatch.setattr(startup, "RunIdentity", wrong_run)
        run = original_prepare_run(handoff, image, zeek_plan)
        validated_runs.append(run)
        return run

    monkeypatch.setattr(startup, "prepare_run", prepare_run)

    def forbidden_auth(self):
        calls.append("AUTH")
        pytest.fail("No authentication is allowed in this test")

    def confirm(handoff):
        calls.append("APPROVAL")
        plan = handoff.plan
        scope = plan.broker.application.scope
        assert len(validated_runs) == 1
        run = validated_runs[0]
        assert run.scope_digest == startup.digest(scope.model_dump(mode="json"))
        assert run.scope_digest != startup.digest(
            handoff.application.plan.scope.model_dump(mode="json")
        )
        handoff.validate_run_identity(run)
        assert plan.mode == "B2D_TCX_BLOCKED"
        assert plan.program_sha256 == handoff.release.payloads["tc.bpf.o"].sha256
        assert plan.bundle_digest == handoff.release.bundle_digest
        assert handoff.release.identity == image.manifest
        assert scope.net_namespace == image.scope_namespace
        assert (scope.interface, scope.ifindex, scope.hook) == ("lo", 1, "INGRESS")
        assert (
            plan.broker.application.application_session
            == handoff.application.plan.application_session
        )
        assert handoff.envelope == release_approval(plan, handoff.release)
        assert (scope.max_duration_seconds, scope.queue_capacity) == (300, 32)
        assert struct.unpack_from("<5I", plan.wire(), 40) == (300, 4096, 32, 256, 20)
        assert handoff.image.zeek_bundle == startup.digest(zeek_bundle())
        return False

    monkeypatch.setattr(SupervisedSession, "authenticate_native", forbidden_auth)
    monkeypatch.setattr(startup, "confirm_scope", confirm)
    if mismatch == "legacy":
        original = startup.Preparation.os_auth_handoff

        def legacy(self, *args, **kwargs):
            release_approval(self.plan, startup.verify_package(args[0], args[1]))
            return original(self, *args, **kwargs)

        monkeypatch.setattr(startup.Preparation, "os_auth_handoff", legacy)
    if mismatch == "namespace":
        readlink = startup.os.readlink
        monkeypatch.setattr(
            startup.os,
            "readlink",
            lambda path, *a, **kw: (
                "net:[1]" if str(path) == "/proc/self/ns/net" else readlink(path, *a, **kw)
            ),
        )
    manifest = "a" * 64 if mismatch == "manifest" else image.manifest
    sha = "b" * 64 if mismatch == "image" else image.sha256
    error = {
        None: "SUPERVISOR_APPROVAL_DENIED",
        "legacy": "RELEASE_TCX_PLAN_REQUIRED",
        "namespace": "SUPERVISOR_NAMESPACE_CHANGED",
        "manifest": "SUPERVISOR_REVIEWED_IMAGE_REQUIRED",
        "image": "SUPERVISOR_REVIEWED_IMAGE_REQUIRED",
        "legacy_run": "HANDOFF_RUN_SCOPE",
        "session": "HANDOFF_RUN_SCOPE",
        "zeek_scope": "SUPERVISOR_STARTUP_SCOPE_MISMATCH",
    }[mismatch]
    with pytest.raises(ValueError, match=error):
        startup.execute(directory, manifest, sha)
    assert calls == (["APPROVAL"] if mismatch is None else [])


@pytest.mark.asyncio
async def test_control_heartbeat_does_not_depend_on_gui_or_dns_task():
    class Session:
        ended = False
        polls = 0

        def observe(self):
            self.polls += 1
            self.ended = self.polls == 3

    session = Session()
    await startup.watch_control(session)
    assert session.polls == 3


@pytest.mark.parametrize("failed_stage", [None, "native", "dns"])
def test_privileged_cleanup_precedes_dns_wait_and_partial_failure_is_independent(failed_stage):
    from types import SimpleNamespace

    calls = []

    def action(name):
        def run(*_):
            calls.append(name)
            if name == failed_stage:
                raise ValueError("SUPERVISOR_FIXTURE_STOP_FAILED")

        return run

    failures = startup.shutdown_collectors(
        SimpleNamespace(close=action("native")),
        SimpleNamespace(stop=action("dns")),
        SimpleNamespace(result=action("drain")),
    )
    assert calls == ["native", "dns", "drain"]
    assert len(failures) == bool(failed_stage)
    if failed_stage:
        assert failures[0]["original_code"] == "SUPERVISOR_FIXTURE_STOP_FAILED"
