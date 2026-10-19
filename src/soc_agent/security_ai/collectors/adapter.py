"""Allowlisted fields only. DNS names, answers and payload are never retained."""

import hashlib
import json
import math
from decimal import Decimal, InvalidOperation

from soc_agent.security_ai.collectors.models import Event, Source
from soc_agent.security_ai.research.models import digest


def parse_line(line: bytes, kind: str, source: Source) -> Event:
    if len(line) > 16384 or kind not in {"network", "dns"}:
        raise ValueError("ZEEK_RECORD_BOUND_OR_KIND")
    try:

        def invalid(_):
            raise ValueError("ZEEK_NONFINITE_JSON")

        row = json.loads(line, parse_float=Decimal, parse_constant=invalid)
        if not isinstance(row, dict) or len(row) > 128:
            raise ValueError("ZEEK_OBJECT_REQUIRED")
        stamp = row["ts"]
        if isinstance(stamp, bool) or not isinstance(stamp, (int, Decimal)):
            raise ValueError("ZEEK_TIMESTAMP_INVALID")
        ns = Decimal(stamp) * 10**9
        if ns != ns.to_integral_value():
            raise ValueError("ZEEK_TIMESTAMP_PRECISION_UNSUPPORTED")
        values = dict(
            kind=kind,
            source=source,
            uid=row["uid"],
            event_ns=int(ns),
            record_digest=hashlib.sha256(line).hexdigest(),
            source_ip=row["id.orig_h"],
            destination_ip=row["id.resp_h"],
            source_port=row["id.orig_p"],
            destination_port=row["id.resp_p"],
            protocol=row["proto"],
        )
        if kind == "network":
            mapping = dict(
                duration="duration_seconds",
                orig_pkts="forward_packets",
                resp_pkts="backward_packets",
                orig_ip_bytes="forward_ip_bytes",
                resp_ip_bytes="backward_ip_bytes",
                missed_bytes="missed_bytes",
                conn_state="connection_state",
            )
            values.update(
                diagnostic="CONNECTION_SUMMARY",
                dns_visibility="ENCRYPTED_DNS_VISIBILITY_LIMIT"
                if 443 in (row["id.orig_p"], row["id.resp_p"])
                or 853 in (row["id.orig_p"], row["id.resp_p"])
                else "UNKNOWN",
            )
        else:
            values["dns_visibility"] = "PLAINTEXT_DNS_METADATA"
            mapping = dict(
                trans_id="transaction_id",
                qtype="query_type",
                rcode="response_code",
                rtt="response_latency_seconds",
                TC="truncated",
            )
            ttls = row.get("TTLs")
            if ttls is not None:
                if not isinstance(ttls, list) or len(ttls) > 64:
                    raise ValueError("ZEEK_TTL_BOUND")
                values["ttl_seconds"] = tuple(float(n) for n in ttls)
                if any(
                    isinstance(n, bool)
                    or not isinstance(n, (int, Decimal))
                    or not math.isfinite(float(n))
                    or n < 0
                    for n in ttls
                ):
                    raise ValueError("ZEEK_TTL_INVALID")
            values["diagnostic"] = (
                "MATCHED_TRANSACTION"
                if row.get("rtt") is not None
                else "RESPONSE_WITHOUT_TIMING"
                if row.get("rcode") is not None
                else "MISSING_RESPONSE_METADATA"
            )
        for key, name in mapping.items():
            if key in row:
                values[name] = float(row[key]) if isinstance(row[key], Decimal) else row[key]
        identity = dict(
            session=str(source.session_id), source=source.source_digest, kind=kind, uid=row["uid"]
        )
        if kind == "dns":
            identity.update(ts=int(ns), transaction=row.get("trans_id"))
        return Event(event_id=digest(identity), **values)
    except (KeyError, ValueError, TypeError, InvalidOperation, OverflowError) as error:
        # Pydantic/JSON errors may contain raw log content. Never expose that text.
        raise ValueError("ZEEK_RECORD_SCHEMA_REJECTED") from error
