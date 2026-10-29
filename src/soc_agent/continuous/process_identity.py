"""Observed identity of an ordinary service after exec; never execution authority."""


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
