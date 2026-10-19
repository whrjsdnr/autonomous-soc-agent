"""Durable packet parity proof bound to existing collector audit, never a capture attestation."""

import asyncio
import json
import re
from pathlib import Path
from uuid import uuid4

from soc_agent.security_ai.collectors.offline import file_digest
from soc_agent.security_ai.collectors.packet_input import SCOPE, Packet, verify_packets
from soc_agent.security_ai.collectors.packet_producer import aggregate
from soc_agent.security_ai.collectors.research import ZeekResearch
from soc_agent.security_ai.research.environment import read_local
from soc_agent.security_ai.research.models import digest, parse_receipt
from soc_agent.security_ai.research.service import write_new
from soc_agent.security_ai.research.zeek_input import ZeekRequest, validate_result


class ProducerService:
    def __init__(self, collector, *, paths=None):
        self.collector = collector
        self.proof = None
        self.restored = False
        self.new_inferences = 0
        self.pending = self.queue_peak = 0
        self.state = "NOT_PREPARED"
        self.last_error = None
        self.demo = ZeekResearch(collector.directory, self.authorize, paths=paths)

    def request(self, flow, profile):
        c = self.collector
        p = self.proof
        return ZeekRequest(
            research_mode=True,
            profile=profile,
            invocation_id=uuid4(),
            capture_session=c.store.source.session_id,
            flow_id=flow["flow_id"],
            provenance_digest=digest(p),
            pcap_sha256=c.store.source.source_digest,
            packet_log_sha256=p["packet_log_sha256"],
            script_sha256=p["script_sha256"],
            close_reason=flow["close_reason"],
            packets=tuple(Packet.model_validate(x) for x in flow["packets"]),
            feature_values=tuple(flow["values"]),
        )

    def verify(self):
        c = self.collector
        c.store.verify()
        p = json.loads(read_local(c.directory / "producer-proof.json", 4 * 1024**2))
        with c.store.runtime.database.transaction(write=False) as db:
            binding = [
                json.loads(r[0])["details"]["proof_digest"]
                for r in db.execute(
                    "SELECT payload FROM monitor_audit "
                    "WHERE json_extract(payload,'$.kind')='ZEEK_NETWORK14_PRODUCED'"
                )
            ]
        if (
            binding != [digest(p)]
            or p["session_id"] != str(c.store.source.session_id)
            or p["pcap_sha256"] != c.store.source.source_digest
            or p["scope"] != SCOPE
        ):
            raise ValueError("ZEEK_PRODUCER_PROOF_AUDIT_MISMATCH")
        if file_digest(c.directory / "logs/network14_packets.log") != p["packet_log_sha256"]:
            raise ValueError("ZEEK_PRODUCER_PACKET_LOG_CHANGED")
        self.proof = p
        return p

    def authorize(self, request):
        if self.restored:
            raise ValueError("ZEEK_RECOVERED_NO_NEW_INFERENCE")
        p = self.verify()
        c = self.collector
        if (
            file_digest(c.pcap) != p["pcap_sha256"]
            or file_digest(Path(__file__).with_name("network14.zeek")) != p["script_sha256"]
        ):
            raise ValueError("ZEEK_PRODUCER_SOURCE_OR_SCRIPT_CHANGED")
        flow = next(
            (f for f in p["flows"] if f["flow_id"] == request.flow_id and f["eligible"]), None
        )
        if flow is None:
            raise ValueError("ZEEK_FLOW_NOT_ELIGIBLE")
        expected = self.request(flow, request.profile)
        if expected.model_dump(exclude={"invocation_id"}) != request.model_dump(
            exclude={"invocation_id"}
        ):
            raise ValueError("ZEEK_REQUEST_SOURCE_BINDING_FAILED")

    async def produce(self, result):
        c = self.collector
        script = Path(__file__).with_name("network14.zeek")
        if not result.get("packet_mode") or result["packet_policy_sha256"] != file_digest(script):
            raise ValueError("ZEEK_PRODUCER_SCRIPT_IDENTITY")
        packets = await asyncio.to_thread(
            verify_packets,
            c.pcap,
            c.directory / "logs/network14_packets.log",
            c.sha256,
            result["log_sha256"]["network14_packets.log"],
        )
        proof = aggregate(packets, str(c.store.source.session_id))
        proof.update(
            session_id=str(c.store.source.session_id),
            pcap_sha256=c.sha256,
            packet_log_sha256=result["log_sha256"]["network14_packets.log"],
            script_sha256=result["packet_policy_sha256"],
            input_origin="ZEEK_OFFLINE_PCAP",
            native_capture=False,
        )
        write_new(c.directory / "producer-proof.json", proof)
        c.store.runtime.event(
            "ZEEK_NETWORK14_PRODUCED",
            dict(
                proof_digest=digest(proof), eligible=proof["eligible"], rejected=proof["rejected"]
            ),
        )
        self.proof = proof
        self.state = "PACKET_REFERENCE_VERIFIED"
        eligible = [f for f in proof["flows"] if f["eligible"]]
        if not eligible:
            self.state = "BLOCKED_NO_TIMEOUT_ELIGIBLE_FLOW"
            return
        if len(eligible) > 8:
            self.state = "BLOCKED_INFERENCE_QUEUE_BUDGET"
            self.last_error = "ZEEK_INFERENCE_CAPACITY_BLOCKED"
            return
        available = (
            int(Path("/proc/meminfo").read_text().split("MemAvailable:")[1].split()[0]) * 1024
        )
        if available < 2 * 1024**3:
            self.state = "BLOCKED_MODEL_HEADROOM"
            self.last_error = "ZEEK_MODEL_HEADROOM_REQUIRED"
            return
        state = await self.demo.start()
        if state["status"] != "READY":
            self.state = "BLOCKED_MODEL_ENVIRONMENT"
            self.last_error = "ZEEK_MODEL_ENVIRONMENT_BLOCKED"
            return
        # No capture remains running. At most eight references / sixteen invocations,
        # one worker at a time. Unknown attempts never retry, including recovery.
        self.state = "INFERENCE_RUNNING"
        self.pending = self.queue_peak = len(eligible) * 2
        for flow in eligible:
            for profile in ("quality", "edge"):
                available = (
                    int(Path("/proc/meminfo").read_text().split("MemAvailable:")[1].split()[0])
                    * 1024
                )
                pressure = float(
                    Path("/proc/pressure/memory").read_text().split("avg10=")[1].split()[0]
                )
                if available < 2 * 1024**3 or pressure >= 1:
                    self.state = "BLOCKED_MODEL_HEADROOM_NO_AUTO_RETRY"
                    self.last_error = "ZEEK_MODEL_HEADROOM_REQUIRED"
                    self.pending = 0
                    c.store.runtime.event(
                        "ZEEK_MODEL_HEADROOM_BLOCKED", dict(automatic_retry=False)
                    )
                    return
                self.pending -= 1
                request = self.request(flow, profile)
                key = digest(
                    dict(
                        session=str(request.capture_session), flow=request.flow_id, profile=profile
                    )
                )
                result = await self.demo.dispatch(request, key)
                c._budget()
                if (
                    result.get("record", {}).get("receipt")
                    and result["status"] != "CACHED_NO_NEW_INFERENCE"
                ):
                    self.new_inferences += 1
                if result["status"] != "COMPLETE":
                    self.state = "UNKNOWN_MODEL_OR_INVESTIGATION_NO_RETRY"
                    error = result.get("record", {}).get("error") or result.get("error")
                    self.last_error = (
                        error
                        if isinstance(error, str) and re.fullmatch(r"[A-Z0-9_]{1,128}", error)
                        else "ZEEK_MODEL_OR_INVESTIGATION_OUTCOME_UNKNOWN"
                    )
                    self.pending = 0
                    return
        self.state = "VERIFIED_RECEIPT_WINDOWS_RESEARCH_ONLY"
        c.store.runtime.event(
            "ZEEK_RESEARCH_FINALIZED",
            dict(
                inference_queue=dict(
                    depth=self.pending, capacity=16, peak=self.queue_peak, worker_concurrency=1
                ),
                new_inferences=self.new_inferences,
                operational_gate="BLOCKED",
                write_policy="WRITE_DENIED",
            ),
        )

    async def recover(self):
        self.restored = True
        self.verify()
        self.demo.snapshot()
        self.state = "RESTORED_NO_NEW_INFERENCE"

    def snapshot(self):
        if self.proof is not None:
            self.verify()
        records = self.demo.snapshot()
        if self.proof:
            for record in records["records"]:
                if record.get("receipt"):
                    receipt = parse_receipt(record["receipt"])
                    flow = next(
                        (
                            f
                            for f in self.proof["flows"]
                            if f["flow_id"] == receipt.flow_id and f["eligible"]
                        ),
                        None,
                    )
                    if flow is None:
                        raise ValueError("ZEEK_RESTORED_RECEIPT_FLOW_MISMATCH")
                    request = self.request(flow, receipt.profile).model_copy(
                        update={"invocation_id": receipt.invocation_id}
                    )
                    validate_result(request, receipt)
        return dict(
            state=self.state,
            scope=SCOPE,
            network14_parity="VERIFIED_FOR_RECEIPT_WINDOWS"
            if any(r.get("receipt") for r in records["records"])
            else "PENDING_ML_REFERENCE_OR_NO_ELIGIBLE_FLOW",
            dns9_parity="BLOCKED",
            eligible=self.proof["eligible"] if self.proof else None,
            rejected=self.proof["rejected"] if self.proof else None,
            packet_count=self.proof["packet_count"] if self.proof else None,
            peak_packet_references=self.proof["peak_packet_references"] if self.proof else None,
            inference_queue=dict(
                depth=self.pending, capacity=16, peak=self.queue_peak, worker_concurrency=1
            ),
            new_inferences=self.new_inferences,
            last_error=self.last_error,
            research=records,
        )
