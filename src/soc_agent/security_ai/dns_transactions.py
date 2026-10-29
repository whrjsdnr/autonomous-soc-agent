"""Stored DNS wire parsing/correlation using the existing bounded protocol parser.

This is deliberately not a DNS9 producer: the training extraction semantics are absent.
TCP records must contain one whole length-prefixed message; partial streams fail closed.
No Native payload-retention policy or live collector is changed.
"""

import hashlib
import struct
from typing import TYPE_CHECKING

from soc_agent.security_ai.operational.network_capture.parsing import PacketRejected, dns_message
from soc_agent.security_ai.research.dns import catalogue
from soc_agent.security_ai.research.models import digest

if TYPE_CHECKING:
    from soc_agent.security_ai.workflow_models import RawDNSJob


def transactions(job: "RawDNSJob") -> dict:
    pending, answered, ambiguous = {}, {}, set()
    events, previous = [], -1

    def event(status, record, **fields):
        row = dict(
            status=status,
            source_reference=record.source_reference,
            wire_sha256=hashlib.sha256(bytes.fromhex(record.wire_hex)).hexdigest(),
            timestamp_ns=record.timestamp_ns,
            source_capture_sha256=job.source_sha256,
            transport=record.transport,
            clock_epoch=job.clock_epoch,
            **fields,
        )
        row["event_identity"] = digest(row)
        events.append(row)
        return row

    for record in job.messages:
        if record.timestamp_ns < previous:
            raise ValueError("RAW_DNS_CLOCK_REVERSAL")
        previous = record.timestamp_ns
        wire = bytes.fromhex(record.wire_hex)
        if record.transport == "tcp":
            if len(wire) < 2 or struct.unpack_from("!H", wire)[0] != len(wire) - 2:
                event("INCOMPLETE_TCP_REASSEMBLY_REQUIRED", record)
                continue
            wire = wire[2:]
        try:
            question = dns_message(wire, retain_name=True)
        except PacketRejected as exc:
            event("INVALID_DNS_MESSAGE", record, reason=str(exc))
            continue
        client = (
            (str(record.destination_address), record.destination_port)
            if question.response
            else (str(record.source_address), record.source_port)
        )
        server = (
            (str(record.source_address), record.source_port)
            if question.response
            else (str(record.destination_address), record.destination_port)
        )
        # ASCII case folding is transaction correlation only, never a training transform.
        normalized = question.query_name.lower()
        key = digest(
            (
                job.source_sha256,
                job.clock_epoch,
                record.transport,
                client,
                server,
                question.transaction_id,
                question.query_type,
                question.query_class,
                normalized,
            )
        )
        fields = dict(
            transaction_identity=key,
            query_name=question.query_name,
            correlation_name_ascii_lower=normalized,
            name_normalization_scope="CORRELATION_ONLY_NOT_DNS9",
            query_name_digest=question.query_name_digest,
            transaction_id=question.transaction_id,
            query_type=question.query_type,
            query_class=question.query_class,
            response_code=question.response_code,
        )
        if key in ambiguous:
            event("AMBIGUOUS_TRANSACTION", record, **fields)
        elif question.response:
            prior = pending.pop(key, None)
            if prior:
                row = event(
                    "MATCHED_RESPONSE",
                    record,
                    query_reference=prior["source_reference"],
                    query_event_identity=prior["event_identity"],
                    query_timestamp_ns=prior["timestamp_ns"],
                    duration_ns=record.timestamp_ns - prior["timestamp_ns"],
                    **fields,
                )
                answered[key] = row
            else:
                event(
                    "DUPLICATE_RESPONSE" if key in answered else "UNMATCHED_RESPONSE",
                    record,
                    **fields,
                )
        elif key in pending or key in answered:
            pending.pop(key, None)
            ambiguous.add(key)
            event("AMBIGUOUS_QUERY_RETRANSMISSION_OR_ID_REUSE", record, **fields)
        else:
            pending[key] = event("QUERY", record, **fields)
    missing = [
        dict(
            status="MISSING_RESPONSE",
            query_event_identity=r["event_identity"],
            transaction_identity=k,
        )
        for k, r in pending.items()
    ]
    model = catalogue()["model"]
    from soc_agent.security_ai.dns9_contract import inspect_training

    result = dict(
        contract="soc-stored-dns-transactions:v1",
        source_sha256=job.source_sha256,
        source_origin=job.origin,
        source_assurance="DECLARED_UNATTESTED",
        clock_epoch=job.clock_epoch,
        messages=len(job.messages),
        events=events,
        missing_responses=missing,
        matched_transactions=sum(r["status"] == "MATCHED_RESPONSE" for r in events),
        dns9_feature_names=model["feature_names"],
        dns9_feature_contract_digest=model["feature_contract_digest"],
        dns9_model_sha256=model["artifacts"]["model_path"]["sha256"],
        dns9_training_contract=inspect_training(),
        eligibility="INVALID"
        if any(r["status"] == "INVALID_DNS_MESSAGE" for r in events)
        else "INCOMPLETE",
        reasons=[
            "DNS9_PRODUCER_PARITY_UNVERIFIED",
            "TRAINING_UNITS_AND_EXTRACTION_UNVERIFIED",
            "NO_GUESSED_DNS_FEATURES",
        ],
        model_inference_executed=False,
        tcp_support="ONE_COMPLETE_LENGTH_PREFIXED_MESSAGE_PER_RECORD",
        validation_level="QUESTION_METADATA_ONLY_NO_RR_VALIDATION",
    )
    result["receipt_digest"] = digest(result)
    return result
