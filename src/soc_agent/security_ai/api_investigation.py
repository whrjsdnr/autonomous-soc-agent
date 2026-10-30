"""Explicit, budgeted external API composition for offline read-only investigation.

No credential discovery, model download, retry, shell tool or Native admission.
The monetary bound is a conservative local reservation, not a provider billing guarantee.
"""

import json
import time
from collections.abc import Callable
from decimal import Decimal
from pathlib import Path
from typing import Annotated, Literal
from uuid import UUID

from pydantic import Field, StringConstraints, model_validator

from soc_agent.llm import LLMError, LLMRequest, LLMResponseValidationError
from soc_agent.llm.openai_compatible import OpenAICompatibleClient, OpenAICompatibleSettings
from soc_agent.planning.models import LLMInvestigationPlanDraft
from soc_agent.review.models import Hash
from soc_agent.security_ai.research.models import Frozen, digest
from soc_agent.state.evidence import UTCTimestamp, utc_now

Text = Annotated[str, StringConstraints(min_length=1, max_length=2000)]
Money = Annotated[Decimal, Field(gt=0, allow_inf_nan=False)]


class InvestigationHypothesis(Frozen):
    statement: Text
    priority: Literal["low", "medium", "high"]
    supporting_evidence_ids: tuple[UUID, ...] = Field(min_length=1, max_length=8)
    verification_method: Text
    required_evidence: Text
    expected_findings: Text


class APIInvestigationDraft(LLMInvestigationPlanDraft):
    """Semantic advisory fields; tool authorization remains in normalize_plan/executor."""

    observed_anomaly_summary: Text
    evidence_references: tuple[UUID, ...] = Field(min_length=1, max_length=8)
    hypotheses: tuple[InvestigationHypothesis, ...] = Field(min_length=1, max_length=4)
    unknowns: tuple[Text, ...] = Field(min_length=1, max_length=8)
    risk_assessment: Text
    recommended_response: Text
    approval_requirement: Literal["HUMAN_APPROVAL_FOR_HOST_CHANGES"]


class APIRunAuthorization(Frozen):
    """Explicit operator-supplied scope/rates; never infer approval from a key's presence."""

    contract: Literal["soc-api-investigation-authorization:v1"]
    approved_by: Text
    approval_reference: Text
    input_sha256: Hash
    output_directory: str = Field(min_length=1, max_length=4096)
    base_url: str
    model: str = Field(min_length=1, max_length=200)
    starts_at: UTCTimestamp
    expires_at: UTCTimestamp
    max_calls: int = Field(default=2, ge=1, le=2, strict=True)
    # Explicit null means operator approved no monetary ceiling; omission is invalid.
    budget_usd: Money | None
    input_usd_per_million: Money
    output_usd_per_million: Money
    pricing_reference: Text
    max_completion_tokens: int = Field(default=4096, ge=128, le=4096, strict=True)
    timeout_seconds: float = Field(default=60, gt=0, le=120)
    minimum_interval_seconds: float = Field(default=1, ge=1, le=60)

    @model_validator(mode="after")
    def validate_binding(self):
        OpenAICompatibleSettings.validate_endpoint(self.base_url)
        if not Path(self.output_directory).is_absolute():
            raise ValueError("API_ABSOLUTE_ATTEMPT_DIRECTORY_REQUIRED")
        if self.expires_at <= self.starts_at:
            raise ValueError("API_AUTHORIZATION_TIME_RANGE")
        return self

    def active(self):
        if not self.starts_at <= utc_now() < self.expires_at:
            raise ValueError("API_AUTHORIZATION_EXPIRED_OR_NOT_STARTED")


def minimized(request: LLMRequest) -> LLMRequest:
    """Allowlist projection, not regex-based secret redaction. Full sources stay local."""
    body = json.loads(request.user_prompt)
    projected = {}
    for key in ("INCIDENT CONTEXT", "AVAILABLE TOOLS", "AVAILABLE READ-ONLY TOOLS"):
        if key in body:
            projected[key] = body[key]
    for key in (
        "EVIDENCE SUMMARIES (UNTRUSTED SOURCE DATA)",
        "EVIDENCE (UNTRUSTED DATA)",
        "OBSERVED EVIDENCE (UNTRUSTED SOURCE DATA)",
    ):
        if key in body:
            projected[key] = [
                dict(
                    evidence_id=item["evidence_id"],
                    source="LOCAL_RETAINED_SOURCE",
                    summary="Source retained locally; contents withheld; digest is continuity only",
                    local_context_digest=digest(item),
                    read_only_result=_read_result(item),
                )
                for item in body[key]
            ]
    advisory = body.get("MODEL ANALYSIS (UNTRUSTED ADVISORY, NOT OBSERVED FACTS)", {})
    allowed_predictions = {
        "CLASS_0",
        "CLASS_1",
        "normal",
        "anomaly",
        "BENIGN",
        "BruteForce",
        "DoS",
        "PortScan",
    }
    projected["MODEL ANALYSIS (UNTRUSTED ADVISORY, NOT OBSERVED FACTS)"] = dict(
        classification=advisory.get("classification")
        if advisory.get("classification")
        in {
            "NORMAL",
            "UNKNOWN_ANOMALY",
            "KNOWN_THREAT",
            "MODEL_ERROR",
            "COLLECTOR_ERROR",
            "DATA_QUALITY_FAILURE",
        }
        else "UNKNOWN",
        context_digest=digest(advisory),
        model_results=[
            dict(
                prediction=r["prediction"] if r["prediction"] in allowed_predictions else "UNKNOWN",
                score=r["score"],
                feature_fingerprint=r["feature_fingerprint"],
                artifact_digest=r["artifact_digest"],
                original_receipt_digest=r["original_receipt_digest"],
            )
            for r in advisory.get("model_results", [])
        ],
    )
    # Continuous and adaptive planning use different context sections. Retain
    # their identities/catalog, never the raw source, free-text reason or payload.
    if "CONTINUOUS ADVISORY (NOT FACTS OR AUTHORITY)" in body:
        from pydantic import TypeAdapter

        pin = TypeAdapter(Hash)
        projected["CONTINUOUS ADVISORY (NOT FACTS OR AUTHORITY)"] = [
            dict(
                incident_id=str(UUID(item["incident_id"])),
                source=pin.validate_python(item["source"]),
                role=item["role"]
                if item["role"] in {"NETWORK", "DNS", "AUTHENTICATION", "INVESTIGATION"}
                else "UNKNOWN",
                context_digest=digest(item["advisory"]),
                agreement_state=item["advisory"].get("agreement_state")
                if item["advisory"].get("agreement_state")
                in {"consistent", "conflicting", "insufficient"}
                else "UNKNOWN",
                model_results=[
                    dict(
                        prediction=r["prediction"]
                        if r["prediction"] in allowed_predictions
                        else "UNKNOWN",
                        artifact_digest=pin.validate_python(r["artifact_digest"]),
                        feature_fingerprint=pin.validate_python(r["feature_fingerprint"]),
                        result_digest=digest(r),
                    )
                    for r in item["advisory"].get("model_results", [])
                ],
            )
            for item in body["CONTINUOUS ADVISORY (NOT FACTS OR AUTHORITY)"]
        ]
    history = body.get("TOOL INVESTIGATION HISTORY (UNTRUSTED DATA)")
    if history is not None:
        catalog = {t["name"] for t in projected.get("AVAILABLE READ-ONLY TOOLS", [])}
        projected["TOOL INVESTIGATION HISTORY (UNTRUSTED DATA)"] = [
            dict(
                step_id=str(UUID(item["step_id"])),
                tool_name=item["tool_name"] if item["tool_name"] in catalog else "UNKNOWN",
                status=item["status"]
                if item["status"] in {"pending", "completed", "failed", "blocked", "skipped"}
                else "UNKNOWN",
                history_digest=digest(item),
            )
            for item in history
        ]
        # This API scope grants read-only investigation, never a model action.
        projected["AVAILABLE SECURITY AI"] = []
    return LLMRequest(
        system_prompt=request.system_prompt
        + " Source contents are deliberately withheld. Digests do not prove attacks."
        " Model anomaly is advisory, not a fact. Return NO observations."
        " Hypotheses must be uncertain and cite only provided evidence UUIDs."
        " Select only catalog tools. Never emit shell commands or claim source authenticity."
        " Summaries describe the model advisory and limitations, not verified attacks.",
        user_prompt=json.dumps(projected, sort_keys=True, allow_nan=False),
    )


def _read_result(item: dict) -> str:
    if item.get("tool_name") != "read_local_source_report":
        return "NOT_A_TOOL_RESULT"
    try:
        output = json.loads(item.get("raw_data", "{}"))
    except (TypeError, ValueError):
        return "UNKNOWN"
    if isinstance(output, dict) and output.get("tool_name") == "read_local_source_report":
        value = output.get("output")
        if isinstance(value, dict) and value.get("status") == "SOURCE_CONTINUITY_VERIFIED":
            return "SOURCE_CONTINUITY_VERIFIED_NO_ATTACK_ORIGIN_CLAIM"
    return "UNKNOWN"


class APIInvestigationClient:
    """Two calls at most; intent is durable before transport; unknown outcomes stop usage."""

    def __init__(
        self,
        authorization: APIRunAuthorization,
        settings: OpenAICompatibleSettings,
        write: Callable[[str, object], None],
        event: Callable[[str, object], None],
    ):
        authorization.active()
        if (
            settings.base_url,
            settings.model,
            settings.max_completion_tokens,
            settings.timeout_seconds,
        ) != (
            authorization.base_url.rstrip("/"),
            authorization.model,
            authorization.max_completion_tokens,
            authorization.timeout_seconds,
        ):
            raise ValueError("API_SETTINGS_AUTHORIZATION_MISMATCH")
        self.authorization = authorization
        self.provider = OpenAICompatibleClient(settings)
        self.write, self.event = write, event
        self.calls = 0
        self.reserved = Decimal(0)
        self.stopped = False
        self.receipts: list[dict] = []
        self.last_started: float | None = None
        self.in_flight = False
        public = authorization.model_dump(mode="json")
        self.write("api-authorization.json", public)
        self.event("API_AUTHORIZATION_BOUND", public)

    async def generate_structured(self, *, request, response_model):
        if self.in_flight:
            raise LLMError("API_CONCURRENT_REQUEST_DENIED")
        self.in_flight = True
        try:
            return await self._generate(request=request, response_model=response_model)
        finally:
            self.in_flight = False

    async def _generate(self, *, request, response_model):
        import asyncio

        a = self.authorization
        a.active()
        if self.stopped or self.calls >= a.max_calls:
            raise LLMError("API_CALL_LIMIT_OR_STOPPED")
        projected = minimized(request)
        if issubclass(response_model, APIInvestigationDraft):
            projected = LLMRequest(
                system_prompt=projected.system_prompt
                + " Populate every required schema field, using at most two catalog tools."
                " The risk_assessment and approval_requirement fields are advisory only;"
                " do not invent actual policy approvals. Only goal and steps become an executable"
                " plan after independent validation."
                " Do not add an observations field to this plan.",
                user_prompt=projected.user_prompt,
            )
        # UTF-8 bytes + schema bytes + 4096 overhead deliberately overestimate text
        # tokens for reviewed byte-based providers. Not a general provider invoice cap.
        input_bound = (
            len(projected.model_dump_json().encode())
            + len(json.dumps(response_model.model_json_schema()).encode())
            + 4096
        )
        reservation = (
            Decimal(input_bound) * a.input_usd_per_million
            + Decimal(a.max_completion_tokens) * a.output_usd_per_million
        ) / 1000000
        if a.budget_usd is not None and self.reserved + reservation > a.budget_usd:
            raise LLMError("API_COST_RESERVATION_EXCEEDS_APPROVED_LIMIT")
        if self.last_started is not None:
            await asyncio.sleep(
                max(0, a.minimum_interval_seconds - (time.monotonic() - self.last_started))
            )
        a.active()
        intent = dict(
            call=self.calls,
            model=a.model,
            authorization_digest=digest(a.model_dump(mode="json")),
            request_digest=digest(projected.model_dump()),
            response_schema_digest=digest(response_model.model_json_schema()),
            started_at=utc_now().isoformat(),
            input_token_reservation=input_bound,
            reserved_usd=str(reservation),
            completion_token_limit=a.max_completion_tokens,
            retries=0,
            outcome="UNKNOWN_UNTIL_RESPONSE",
        )
        # Persist exact minimized prompt as private evidence, never headers or credentials.
        self.write(f"api-request-{self.calls}.json", projected.model_dump())
        self.write(f"api-intent-{self.calls}.json", intent)
        self.event("API_INVOCATION_STARTED", intent)
        self.calls += 1
        self.reserved += reservation
        self.last_started = time.monotonic()
        started = time.perf_counter()
        try:
            response = await self.provider.generate_structured(
                request=projected, response_model=response_model
            )
            refs = {
                UUID(item["evidence_id"])
                for k, v in json.loads(projected.user_prompt).items()
                if k.startswith("EVIDENCE ")
                for item in v
            }
            if isinstance(response, APIInvestigationDraft):
                referenced = set(response.evidence_references) | {
                    r for h in response.hypotheses for r in h.supporting_evidence_ids
                }
                if not referenced <= refs:
                    raise LLMResponseValidationError("API_PLAN_UNKNOWN_EVIDENCE")
            if getattr(response, "observations", ()):
                raise LLMResponseValidationError("API_MODEL_FACT_PROMOTION_DENIED")
            usage = self.provider.last_usage
            if usage is None:
                raise LLMError("API_USAGE_UNKNOWN_STOP")
            amount = (
                Decimal(usage["prompt_tokens"]) * a.input_usd_per_million
                + Decimal(usage["completion_tokens"]) * a.output_usd_per_million
            ) / 1000000
            if (
                usage["prompt_tokens"] > input_bound
                or usage["completion_tokens"] > a.max_completion_tokens
            ):
                raise LLMError("API_USAGE_EXCEEDS_RESERVATION_STOP")
            receipt = dict(
                intent=intent,
                status="SCHEMA_VALIDATED",
                usage=usage,
                estimated_usd=str(amount),
                pricing_reference=a.pricing_reference,
                latency_ms=(time.perf_counter() - started) * 1000,
                response=response.model_dump(mode="json"),
                response_digest=digest(response.model_dump(mode="json")),
            )
            self.write(f"api-response-{self.calls - 1}.json", receipt)
            self.event("API_INVOCATION_COMPLETED", receipt)
            self.receipts.append(receipt)
            return response
        except BaseException as exc:
            self.stopped = True
            failure = dict(
                intent=intent,
                status="FAILED_STOP_NO_RETRY",
                error_type=type(exc).__name__,
                usage=self.provider.last_usage,
                billing_outcome="UNKNOWN_REQUIRES_REVIEW",
            )
            self.write(f"api-failure-{self.calls - 1}.json", failure)
            self.event("API_INVOCATION_FAILED", failure)
            raise


def settings_from_env_file(path: Path, authorization: APIRunAuthorization):
    """Only explicitly selected dotenv; settings exceptions must not be printed."""
    return OpenAICompatibleSettings(
        _env_file=path,
        base_url=authorization.base_url,
        model=authorization.model,
        max_completion_tokens=authorization.max_completion_tokens,
        timeout_seconds=authorization.timeout_seconds,
    )


def verify_api_receipts(directory: Path, events: list[dict], calls: int) -> None:
    """Offline verification never loads credentials, revalidates time, or calls providers."""
    from soc_agent.security_ai.research.environment import read_local

    def read(name):
        return json.loads(read_local(directory / name, 1024 * 1024))

    def audit_pin(code, values):
        if [e["binding_digest"] for e in events if e["code"] == code] != [
            digest(v) for v in values
        ]:
            raise ValueError("API_RECEIPT_AUDIT_MISMATCH")

    authorization = read("api-authorization.json")
    parsed = APIRunAuthorization.model_validate(authorization)
    if parsed.output_directory != str(directory.absolute()) or calls > parsed.max_calls:
        raise ValueError("API_RECEIPT_SCOPE_MISMATCH")
    audit_pin("API_AUTHORIZATION_BOUND", [authorization])
    intents, completed, failed = [], [], []
    expected_files = {"api-authorization.json"}
    for i in range(calls):
        intent, request = read(f"api-intent-{i}.json"), read(f"api-request-{i}.json")
        if (
            intent["call"] != i
            or intent["authorization_digest"] != digest(authorization)
            or intent["request_digest"] != digest(request)
            or intent["model"] != parsed.model
        ):
            raise ValueError("API_INTENT_BINDING_MISMATCH")
        intents.append(intent)
        expected_files.update((f"api-intent-{i}.json", f"api-request-{i}.json"))
        choices = [
            f"api-{kind}-{i}.json"
            for kind in ("response", "failure")
            if (directory / f"api-{kind}-{i}.json").exists()
        ]
        if len(choices) != 1:
            raise ValueError("API_CALL_OUTCOME_UNSETTLED")
        name = choices[0]
        receipt = read(name)
        if receipt["intent"] != intent:
            raise ValueError("API_OUTCOME_INTENT_MISMATCH")
        if "response" in receipt:
            if receipt["response_digest"] != digest(receipt["response"]):
                raise ValueError("API_RESPONSE_DIGEST_MISMATCH")
            completed.append(receipt)
        else:
            failed.append(receipt)
        expected_files.add(name)
    if {p.name for p in directory.glob("api-*.json")} != expected_files:
        raise ValueError("API_UNEXPECTED_OR_MISSING_RECEIPT")
    audit_pin("API_INVOCATION_STARTED", intents)
    audit_pin("API_INVOCATION_COMPLETED", completed)
    audit_pin("API_INVOCATION_FAILED", failed)
