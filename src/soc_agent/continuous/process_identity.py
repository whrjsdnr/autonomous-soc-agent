"""Observed identity of an ordinary service after exec; never execution authority."""


def authenticated_producer_ready(value, *, policy_sha256, namespace, now):
    """Compare READY with the caller's verified request, never a previous trial pin.

    This fixed predicate can be embedded in the reviewed Root coordinator, like
    observe_service_health. It neither grants authority nor refreshes timestamps.
    """
    if (
        not isinstance(policy_sha256, str)
        or len(policy_sha256) != 64
        or any(c not in "0123456789abcdef" for c in policy_sha256)
        or not isinstance(namespace, str)
        or not namespace.startswith("net:[")
        or not isinstance(value, dict)
    ):
        return False
    producer = value.get("producer", {})
    health = value.get("component_health", {})
    if not isinstance(producer, dict) or not isinstance(health, dict):
        return False
    stamps = (health.get("collector_message_unix"), value.get("heartbeat_unix"))
    return bool(
        value.get("source") == "NATIVE_SERVICE"
        and value.get("collector") == "RUNNING"
        and value.get("state") == "RUNNING"
        and producer.get("namespace") == namespace
        and producer.get("policy_sha256") == policy_sha256
        and type(producer.get("generation")) is int
        and 0 < producer["generation"] < 2**64
        and all(type(stamp) in (int, float) and 0 <= now - stamp < 5 for stamp in stamps)
    )


def read_service_journal(unit, since, *, run):
    """Bound diagnostic log collection independently of service/resource cleanup.

    A timeout preserves partial output and an unknown child exit code. The caller
    must save this record without treating it as successful journal collection.
    Only fixed trial units can be inspected; this never controls a service.
    """
    import subprocess

    if unit not in {
        "soc-continuous-collector.service",
        "soc-operations-runtime.service",
        "soc-continuous-tcp-trial.service",
        "soc-continuous-dns.service",
        "soc-continuous-dnsmasq.service",
    }:
        raise ValueError("TRIAL_JOURNAL_UNIT_SCOPE")
    args = [
        "/usr/bin/journalctl",
        "--no-pager",
        "--boot=0",
        "--lines=200",
        "-o",
        "short-iso",
        "-u",
        unit,
        "--since",
        since,
    ]
    try:
        result = run(args, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=15)
    except subprocess.TimeoutExpired as error:

        def decode(value):
            return (
                value.decode("utf-8", errors="replace") if isinstance(value, bytes) else value or ""
            )

        return dict(
            command=args,
            returncode=None,
            stdout=decode(error.stdout),
            stderr=decode(error.stderr),
            timed_out=True,
            error="JOURNAL_EVIDENCE_TIMEOUT",
            timeout_seconds=15,
            completeness="PARTIAL_OR_UNKNOWN",
        )
    return dict(
        command=args,
        returncode=result.returncode,
        stdout=result.stdout,
        stderr=result.stderr,
        timed_out=False,
        completeness="BOUNDED_TAIL" if result.returncode == 0 else "UNVERIFIED",
    )


def observe_service_health(properties, read_snapshot, clock):
    """Acquire fresh evidence AFTER blocking queries; keep the six-second bound.

    The caller may embed this fixed function in a reviewed Root coordinator. No
    service control or authority is provided. Observation timestamps are evidence,
    not a way to refresh/overwrite the source's authenticated heartbeat.
    """
    query_started = clock()
    collector = properties("soc-continuous-collector.service")
    application = properties("soc-operations-runtime.service")
    query_finished = clock()
    value = read_snapshot()
    acquired = clock()
    observation = dict(
        query_started=query_started,
        query_finished=query_finished,
        acquired_unix=acquired,
        query_seconds=query_finished - query_started,
        read_seconds=acquired - query_finished,
    )
    if value.get("stop_reason") == "OPERATOR_REQUEST":
        return value, observation
    if collector.get("ActiveState") != "active":
        raise ValueError("COLLECTOR_EARLY_EXIT")
    if application.get("ActiveState") != "active":
        raise ValueError("ORDINARY_RUNTIME_EARLY_EXIT")
    if value.get("last_error") or value.get("circuit_open"):
        raise ValueError("RUNTIME_FIRST_ERROR:" + str(value.get("last_error")))
    if value.get("collector") in ("FAILED", "STOPPED", "DEGRADED"):
        raise ValueError("COLLECTOR_STATE:" + str(value.get("collector")))
    heartbeat = value.get("heartbeat_unix")
    source = value.get("component_health", {}).get("collector_message_unix")
    for stamp, code in ((heartbeat, "RUNTIME_HEARTBEAT_STALE"), (source, "ROOT_HEARTBEAT_STALE")):
        if type(stamp) not in (int, float) or not 0 <= acquired - stamp < 6:
            raise ValueError(code)
    observation.update(runtime_age=acquired - heartbeat, source_age=acquired - source)
    return value, observation


def validate_ordinary_process(status: str) -> None:
    """Keep the UID/capability boundary strict and preserve a useful failure code."""
    required = ("Uid", "CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb", "NoNewPrivs")
    fields: dict[str, list[str]] = {}
    for line in status.splitlines():
        name, separator, body = line.partition(":")
        if separator and name in required:
            if name in fields:
                raise ValueError("ORDINARY_PROCESS_DUPLICATE_FIELD:" + name)
            fields[name] = body.split()
    if missing := set(required) - fields.keys():
        raise ValueError("ORDINARY_PROCESS_IDENTITY_INCOMPLETE:" + ",".join(sorted(missing)))
    if fields["Uid"] != ["1000"] * 4:
        raise ValueError("ORDINARY_PROCESS_UID_MISMATCH:" + ",".join(fields["Uid"]))
    for name in required[1:-1]:
        if len(fields[name]) != 1:
            raise ValueError("ORDINARY_PROCESS_CAPABILITY_UNVERIFIED:" + name)
        try:
            mask = int(fields[name][0], 16)
        except ValueError as error:
            raise ValueError("ORDINARY_PROCESS_CAPABILITY_UNVERIFIED:" + name) from error
        if mask:
            raise ValueError("ORDINARY_PROCESS_CAPABILITY_NONZERO:" + name)
    if fields["NoNewPrivs"] != ["1"]:
        raise ValueError("ORDINARY_PROCESS_NO_NEW_PRIVILEGES_UNVERIFIED")
