from datetime import timedelta
from uuid import UUID

import pytest
from tests.unit.operational_features.test_auth_source_store import (
    INCIDENT,
    TIME,
    admit,
    source,
    store,
)

from soc_agent.security_ai.operational.source_records import (
    DNSQuerySource,
    FlowEndpoint,
    NetworkFlowSource,
)
from soc_agent.security_ai.operational.source_store import OperationalSourceStore, SourceRejected


def flow():
    return NetworkFlowSource(
        header=source(10).header,
        transport="tcp",
        endpoint_a=FlowEndpoint(address="192.0.2.1", port=40000),
        endpoint_b=FlowEndpoint(address="198.51.100.1", port=443),
        started_at=TIME,
        ended_at=TIME,
    )


def dns():
    return DNSQuerySource(
        header=source(11).header,
        query_name="테스트.Example.",
        query_type=1,
        query_class=1,
        transaction_id=33,
    )


def test_flow_dns_admission_duplicate_restart_preserves_original(tmp_path):
    s = store(tmp_path)
    for item in (flow(), dns()):
        assert admit(s, item).status == "ACCEPTED"
        assert admit(s, item).duplicate
        assert s.load(item, expected_incident=INCIDENT) == item
    assert not s.windows(INCIDENT)
    s = OperationalSourceStore(
        s.database.path, allowed_lateness_seconds=60, max_future_skew_seconds=5
    )
    assert s.load(dns(), expected_incident=INCIDENT).query_name == "테스트.Example."
    assert s.load(flow(), expected_incident=INCIDENT).reported_packet_count is None
    assert not s.windows(INCIDENT)


@pytest.mark.parametrize(
    "update",
    [
        {"transport": "udp", "endpoint_b": {"address": "198.51.100.1", "port": None}},
        {"ended_at": TIME - timedelta(seconds=1)},
        {"reported_packet_count": -1},
        {"endpoint_a": {"address": "invalid", "port": 80}},
        {"endpoint_a": {"address": "::1", "port": 80}},
        {"top40": {}},
    ],
)
def test_bad_flow_rejected(update):
    with pytest.raises(ValueError):
        NetworkFlowSource.model_validate(flow().model_dump() | update)


@pytest.mark.parametrize("name", ["", "bad\n.example", "two names.test", "a" * 256])
def test_bad_dns_name_rejected(name):
    with pytest.raises(ValueError):
        DNSQuerySource.model_validate(dns().model_dump() | {"query_name": name})


def test_raw_source_digest_and_cross_incident_rejected(tmp_path):
    s = store(tmp_path)
    item = dns()
    admit(s, item)
    with pytest.raises(SourceRejected, match="ASSOCIATION"):
        s.load(item, expected_incident=UUID(int=99))
    with pytest.raises(SourceRejected, match="DIGEST"):
        s.ingest(
            flow(), expected_incident=INCIDENT, expected_source_digest="0" * 64, received_at=TIME
        )
    with s.database.transaction() as c:
        c.execute("UPDATE operational_sources SET digest=?", ("0" * 64,))
    with pytest.raises(SourceRejected, match="INTEGRITY"):
        s.load(item, expected_incident=INCIDENT)


def test_dns_future_event_cannot_close_auth_window(tmp_path):
    s = store(tmp_path)
    admit(s, source(1, 10))
    future = dns().model_copy(update={"header": source(11, 900).header})
    admit(s, future)
    assert admit(s, source(2, 20)).status == "ACCEPTED"


def test_invalid_endpoint_error_does_not_echo_sensitive_text():
    secret = "sensitive-raw-record-value"
    with pytest.raises(ValueError) as error:
        FlowEndpoint(address=secret, port=80)
    assert secret not in str(error.value)
