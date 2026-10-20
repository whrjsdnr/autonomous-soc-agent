"""Reuse existing app authority and Broker fixtures; do not create a second auth session."""

import json

import pytest
from tests.ebpf_tc_support import preparation

from soc_agent.security_ai.ebpf_native.authentication import FixtureAuthentication
from soc_agent.security_ai.ebpf_tc.auth_qualification import session_snapshot
from soc_agent.security_ai.ebpf_tc.installation import create_package


@pytest.mark.parametrize("reason", ["EXPIRED", "BROKER_EXITED"])
def test_existing_authority_once_restart_and_revocation(tmp_path, reason):
    p = preparation(tmp_path)
    try:
        p.prepare()
        p.approve(p.plan.approval)
        p.controller.authenticate(FixtureAuthentication())
        broker = p.controller.broker.identity
        for _ in range(2):
            p.controller.start()
            p.controller.stop()
        assert p.controller.broker.identity == broker
        assert session_snapshot(p.controller)["authority_in_memory"]
        with p.controller.application.store.database.transaction(write=False) as db:
            rows = [json.loads(r[0]) for r in db.execute("SELECT payload FROM monitor_audit")]
        assert sum(r["kind"] == "AUTHENTICATION_VERIFIED" for r in rows) == 1
        if reason == "EXPIRED":
            p.controller.application._grant_started -= 3601
        else:
            p.controller.broker.close()
        assert not session_snapshot(p.controller)["authority_in_memory"]
        assert p.controller.application.authentication == "REVOKED"
    finally:
        p.controller.close()
    recovered = p.controller.recover(p.controller.application.directory)
    assert not recovered["authentication_restored"] and not recovered["automatic_attach"]


def test_package_qualification_appends_audit_without_install_or_auth(tmp_path):
    p = preparation(tmp_path)
    try:
        p.prepare()
        release = create_package(p.artifacts, tmp_path / "package", "0.2.5")
        p.qualify_package(tmp_path / "package", release.identity)
        value = p.snapshot()["installation"]
        assert value["installed_release"] is None and value["native_release"] == "BLOCKED"
        assert value["installation_integrity"] == "PACKAGE_VERIFIED_ROOT_NOT_OBSERVED"
        assert value["dynamic_loader_trust"] == "BLOCKED_PREMAIN_NATIVE_NOT_OBSERVED"
        assert value["runtime_mapping_attestation"] == "PROCESS_WIDE_EXECUTABLE_SNAPSHOT_LIMITED"
        assert value["environment_contract"] == release.dynamic_trust.environment_contract
        assert value["nss_scope_policy"] == "ALL_CONFIGURED_NO_IMPLICIT_EXCLUSION"
        assert not p.controller.application._authenticated
        with p.controller.application.store.database.transaction(write=False) as db:
            rows = [json.loads(r[0]) for r in db.execute("SELECT payload FROM monitor_audit")]
        event = next(r for r in rows if r["kind"] == "INSTALLATION_PACKAGE_VERIFIED")
        assert event["details"]["release_manifest_digest"] == release.identity
        assert not event["details"]["native_execution"]
        with pytest.raises(ValueError, match="MISMATCH"):
            p.qualify_package(tmp_path / "package", "f" * 64)
    finally:
        p.controller.close()


def test_new_app_cannot_reuse_prior_approval_or_authentication(tmp_path):
    first = preparation(tmp_path / "first")
    second = preparation(tmp_path / "second")
    try:
        first.prepare()
        second.prepare()
        first.approve(first.plan.approval)
        first.controller.authenticate(FixtureAuthentication())
        with pytest.raises(ValueError, match="DIGEST_MISMATCH"):
            second.approve(first.plan.approval)
        assert not second.controller.application._authenticated
        with pytest.raises(ValueError):
            second.controller.start()
        requested = first.controller.application.scope.model_copy(update={"hook": "EGRESS"})
        with pytest.raises(ValueError, match="SCOPE"):
            first.controller.application.start(requested)
    finally:
        first.controller.close()
        second.controller.close()
