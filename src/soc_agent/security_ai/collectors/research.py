"""Reuse isolated RF/LR worker, no-retry ledger and governed READ-only investigation."""

import asyncio

from soc_agent.security_ai.research.adapter import ResearchAdapter
from soc_agent.security_ai.research.models import digest
from soc_agent.security_ai.research.service import ResearchDemo
from soc_agent.security_ai.research.zeek_input import expected_source, validate_result


class ZeekResearch(ResearchDemo):
    attempt_limit = 256 * 1024
    capacity = 16

    def __init__(self, directory, authorize, *, paths=None):
        super().__init__(directory, paths=paths)
        self.adapter = ResearchAdapter(self.directory, paths=paths, live_metadata=True)
        self.adapter.authorize_zeek = authorize

    async def start(self):
        result = await super().start()
        return {"status": "READY"} if self.started else result

    async def dispatch(self, request, key):
        if key != digest(
            dict(
                session=str(request.capture_session), flow=request.flow_id, profile=request.profile
            )
        ):
            raise ValueError("ZEEK_IDEMPOTENCY_KEY_MISMATCH")
        await asyncio.to_thread(self.adapter.authorize_zeek, request)
        records, _ = self._records()
        cached = next((r for r in records if r["key"] == key), None)
        if (
            cached
            and cached.get("receipt")
            and cached["receipt"]["source_digest"] != expected_source(request)
        ):
            raise ValueError("ZEEK_CACHED_SOURCE_MISMATCH")
        return await super().dispatch(request, key)

    def validate_receipt(self, request, receipt):
        validate_result(request, receipt)

    def validate_completion(self, request, receipt):
        self.adapter.authorize_zeek(request)
        validate_result(request, receipt)

    def snapshot(self):
        records, unknown = self._records()
        return dict(
            records=records,
            unknown_attempts=unknown,
            model_metrics=self._model_metrics(records, unknown),
            worker_running=bool(self.adapter.process and self.adapter.process.returncode is None),
            active_model=self.active_model if hasattr(self, "active_model") else None,
        )
