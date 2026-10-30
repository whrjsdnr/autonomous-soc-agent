"""Exercise the exact embedded coordinator with the Root child boundary mocked."""

from types import SimpleNamespace

import pytest

from soc_agent.continuous.dns_trial import source

CONFIG = dict(
    uid=1000,
    gid=1000,
    namespace="net:[4026532232]",
    namespace_device=4,
    namespace_inode=4026532232,
    boot_id="67d54395-bd0f-4e00-867b-58b7f20342fb",
)


def image():
    namespace = {"__name__": "UNSIGNED_NONPRIVILEGED_TEST"}
    body = source(CONFIG)
    exec(compile(body, "<reviewed-image>", "exec"), namespace)
    return namespace


def test_build_is_reproducible_and_program_entry_is_guarded():
    assert source(CONFIG) == source(CONFIG)
    with pytest.raises(SystemExit, match="EXACT_ROOT_R1_R2_AND_NATIVE_APPROVAL_REQUIRED"):
        exec(compile(source(CONFIG), "<guarded-image>", "exec"), {"__name__": "__main__"})


@pytest.mark.parametrize(
    "change",
    [dict(uid=0), dict(namespace="net:[4026531833]"), dict(namespace_inode=1), dict(port=5353)],
)
def test_unreviewed_scope_cannot_build(change):
    with pytest.raises(ValueError, match="FIXED_SCOPE"):
        source(CONFIG | change)


def test_start_without_root_does_not_enter_namespace_or_send():
    ns = image()
    with pytest.raises(ValueError, match="AUTHENTICATED_ROOT"):
        ns["BoundedDNSProbe"]().start()


def child(ns, monkeypatch, values, *, code=0):
    channel = object()
    result = SimpleNamespace(
        deadline=ns["time"].monotonic() + 66,
        channel=channel,
        receive=lambda: values.pop(0),
        finish=lambda: code,
        close=lambda: code,
    )
    monkeypatch.setitem(ns, "spawn_dns_child", lambda *_: result)
    monkeypatch.setattr(
        ns["select"], "select", lambda *_: ([channel], [], []) if values else ([], [], [])
    )
    probe = ns["BoundedDNSProbe"]()
    probe.start()
    return probe, result


def ready():
    return dict(state="LOCAL_DNS_READY", namespace=CONFIG["namespace"], cookie="fixture")


def completed():
    return dict(
        state="DNS_DIAGNOSTIC_COMPLETED",
        exchanges=[dict(transport=t) for t in ("UDP", "TCP", "UDP")],
        client_fds_closed=True,
    )


def test_nonblocking_poll_ready_completion_cleanup_and_replay(monkeypatch):
    ns = image()
    values = []
    probe, _ = child(ns, monkeypatch, values)
    probe.poll()  # No child message must never block the heartbeat watcher.
    assert not probe.ready
    values.extend([ready(), completed()])
    probe.poll()
    assert probe.ready and not probe.completed
    probe.poll()
    assert probe.completed and probe.close()["child_exit"] == 0
    with pytest.raises(ValueError, match="REPLAY"):
        probe.start()


@pytest.mark.parametrize(
    "fault",
    ["missing_ready", "wrong_namespace", "child_exit", "partial", "child_failure", "deadline"],
)
def test_failures_remain_explicit_and_child_cleanup_is_owned(monkeypatch, fault):
    ns = image()
    values = [ready(), completed()]
    if fault == "missing_ready":
        values.pop(0)
    elif fault == "wrong_namespace":
        values[0]["namespace"] = "net:[1]"
    elif fault == "partial":
        values[1]["exchanges"].pop()
    elif fault == "child_failure":
        values[0] = dict(state="DNS_CHILD_FAILED", error="UNSIGNED_BOUNDARY_FAILURE")
    probe, owned = child(ns, monkeypatch, values, code=2 if fault == "child_exit" else 0)
    if fault == "deadline":
        owned.deadline = 0
    with pytest.raises((ValueError, TimeoutError), match="CONTINUOUS_DNS_TRIAL"):
        probe.poll()
        probe.poll()
    assert probe.close()["started"] is True
    assert not probe.completed


def test_dnsmasq_candidate_uses_installed_server_without_upstream_or_host_config():
    from soc_agent.continuous.dns_trial import arguments, candidate

    result = candidate()
    assert result["server_implemented_by"] == "dnsmasq"
    assert result["binary"] == "/usr/sbin/dnsmasq"
    assert result["upstream_servers"] == [] and not result["host_configuration"]
    args = arguments()
    assert "--conf-file=/dev/null" in args and "--no-resolv" in args and "--no-hosts" in args
    assert "--listen-address=127.0.0.53" in args and "--port=53" in args
    assert not any(a.startswith(("--server=", "--enable-dbus", "--dhcp-range")) for a in args)
    assert "CapabilityBoundingSet=CAP_NET_BIND_SERVICE\n" in result["body"]
    assert "Restart=no\n" in result["body"] and "RuntimeMaxSec=90s\n" in result["body"]
    assert "--port=1053" in arguments(local_test=True)


@pytest.mark.parametrize("fault", ["id", "rcode", "address", "partial", "question"])
def test_oss_response_validation_denies_changed_evidence(fault):
    import struct

    from soc_agent.continuous.dns_trial import validate_response
    from soc_agent.security_ai.ebpf_tc.namespace_isolation import local_dns_response
    from soc_agent.security_ai.ebpf_tc.r2_diagnostic import QUESTION

    query = struct.pack("!6H", 0xC201, 0x100, 1, 0, 0, 0) + QUESTION
    response = bytearray(local_dns_response(query))
    if fault == "id":
        response[0] ^= 1
    elif fault == "rcode":
        response[3] |= 1
    elif fault == "address":
        response[-1] = 2
    elif fault == "partial":
        response.pop()
    else:
        response[14] ^= 1
    with pytest.raises(ValueError, match="CONTINUOUS_DNSMASQ_RESPONSE"):
        validate_response(query, bytes(response))


def test_native_client_cannot_send_from_host(monkeypatch):
    import os

    from soc_agent.continuous.dns_trial import dnsmasq_client

    monkeypatch.setattr(os, "readlink", lambda _: "net:[4026531833]")
    with pytest.raises(ValueError, match="CLIENT_IDENTITY"):
        dnsmasq_client(SimpleNamespace(namespace="net:[4026532232]"), ready=lambda _: None)
