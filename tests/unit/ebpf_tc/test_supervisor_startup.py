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


@pytest.mark.parametrize("mismatch", [None, "legacy", "namespace", "manifest", "image"])
def test_startup_validates_real_tcx_plan_before_authentication(
    candidate, tmp_path, monkeypatch, mismatch
):
    source, image = candidate
    directory = tmp_path / "candidate"
    shutil.copytree(source, directory)
    calls = []

    def forbidden_auth(self):
        calls.append("AUTH")
        pytest.fail("No authentication is allowed in this test")

    def confirm(handoff):
        calls.append("APPROVAL")
        plan = handoff.plan
        scope = plan.broker.application.scope
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
    }[mismatch]
    with pytest.raises(ValueError, match=error):
        startup.execute(directory, manifest, sha)
    assert calls == (["APPROVAL"] if mismatch is None else [])
