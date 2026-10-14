"""Explicitly injected Chat Completions adapter; no import-time configuration or I/O."""

import asyncio
import json
import threading
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from pydantic import BaseModel, Field, SecretStr, ValidationError, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from soc_agent.llm.client import validate_response
from soc_agent.llm.errors import LLMError, LLMResponseValidationError, LLMTimeoutError
from soc_agent.llm.models import LLMRequest


class OpenAICompatibleSettings(BaseSettings):
    """Environment-only configuration. Neither dotenv nor a provider is auto-discovered."""

    model_config = SettingsConfigDict(
        env_prefix="SOC_LLM_", frozen=True, extra="ignore", hide_input_in_errors=True
    )
    base_url: str = Field(repr=False)
    model: str = Field(min_length=1, repr=False)
    api_key: SecretStr = Field(repr=False)
    timeout_seconds: float = Field(default=60, gt=0, le=120)
    max_completion_tokens: int = Field(default=4096, ge=128, le=4096)

    @field_validator("base_url")
    @classmethod
    def validate_endpoint(cls, value: str) -> str:
        url = urlsplit(value)
        if (
            url.scheme != "https"
            or not url.hostname
            or url.username is not None
            or url.password is not None
            or url.query
            or url.fragment
        ):
            raise ValueError("Endpoint must be an HTTPS API base URL without credentials or query")
        return value.rstrip("/")

    @field_validator("api_key")
    @classmethod
    def nonempty_key(cls, value: SecretStr) -> SecretStr:
        if not value.get_secret_value().strip():
            raise ValueError("API credential is required")
        return value


class LLMProviderError(LLMError):
    """Provider rejected the request; response body is deliberately not disclosed."""


class LLMNetworkError(LLMError):
    """Transport failure without endpoint/header disclosure."""


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Never forward credentials to a provider-selected redirect target.
        return None


class OpenAICompatibleClient:
    """One bounded request, no retries; schema validation remains local and mandatory."""

    def __init__(self, settings: OpenAICompatibleSettings) -> None:
        self._settings = settings
        self._transport: threading.Thread | None = None
        self.last_usage: dict[str, int] | None = None

    async def generate_structured[T: BaseModel](
        self, *, request: LLMRequest, response_model: type[T]
    ) -> T:
        if self._transport is not None and self._transport.is_alive():
            raise LLMNetworkError("NETWORK: previous transport still active")
        self.last_usage = None
        body = {
            "model": self._settings.model,
            "messages": [
                {"role": "system", "content": request.system_prompt},
                {"role": "user", "content": request.user_prompt},
            ],
            "max_completion_tokens": self._settings.max_completion_tokens,
            "response_format": {
                "type": "json_schema",
                "json_schema": {
                    "name": response_model.__name__,
                    "strict": False,
                    "schema": response_model.model_json_schema(),
                },
            },
        }
        try:
            raw = await asyncio.wait_for(
                self._transport_request(json.dumps(body).encode()),
                timeout=self._settings.timeout_seconds,
            )
        except TimeoutError:
            raise LLMTimeoutError("LLM request exceeded its deadline") from None
        try:
            envelope = json.loads(raw)
        except (ValueError, TypeError):
            raise LLMResponseValidationError(
                "SCHEMA_VALIDATION: invalid response envelope JSON"
            ) from None
        usage = envelope.get("usage") if isinstance(envelope, dict) else None
        if isinstance(usage, dict) and all(
            type(usage.get(k)) is int and usage[k] >= 0
            for k in ("prompt_tokens", "completion_tokens")
        ):
            self.last_usage = {k: usage[k] for k in ("prompt_tokens", "completion_tokens")}
        try:
            choice = envelope["choices"][0]
            finish_reason = choice["finish_reason"]
            message = choice["message"]
            content = message["content"]
        except (KeyError, IndexError, TypeError):
            raise LLMResponseValidationError(
                "SCHEMA_VALIDATION: invalid response envelope"
            ) from None
        if finish_reason != "stop":
            reason = (
                "token limit reached" if finish_reason == "length" else "response not completed"
            )
            raise LLMResponseValidationError("SCHEMA_VALIDATION: " + reason)
        if message.get("refusal"):
            raise LLMResponseValidationError("SCHEMA_VALIDATION: provider refusal")
        if not isinstance(content, str):
            raise LLMResponseValidationError("SCHEMA_VALIDATION: missing structured content")
        try:
            payload = json.loads(content)
        except ValueError:
            raise LLMResponseValidationError("SCHEMA_VALIDATION: content is not JSON") from None
        try:
            return validate_response(payload, response_model)
        except LLMResponseValidationError as error:
            # Values, error messages, context and arbitrary extra-field names stay private.
            diagnostic = _schema_diagnostic(error, response_model)
            raise LLMResponseValidationError("SCHEMA_VALIDATION: " + diagnostic) from None

    async def _transport_request(self, body: bytes) -> bytes:
        # A stuck OS DNS resolver must not hold asyncio's default executor shutdown.
        # A timed-out client refuses a second transport until this daemon finishes.
        loop = asyncio.get_running_loop()
        future = loop.create_future()

        def deliver(value, error):
            if future.done():
                return
            if error is not None:
                future.set_exception(error)
            else:
                future.set_result(value)

        def worker():
            try:
                value, error = self._post(body), None
            except (LLMError, OSError) as failure:
                value, error = None, failure
            try:
                loop.call_soon_threadsafe(deliver, value, error)
            except RuntimeError:
                # A closed loop means the deadline/shutdown already abandoned this reply.
                return

        self._transport = threading.Thread(target=worker, daemon=True)
        self._transport.start()
        return await future

    def _post(self, body: bytes) -> bytes:
        request = Request(
            self._settings.base_url + "/chat/completions",
            data=body,
            headers={
                "Content-Type": "application/json",
                "Authorization": "Bearer " + self._settings.api_key.get_secret_value(),
            },
            method="POST",
        )
        try:
            with build_opener(_NoRedirect()).open(
                request, timeout=self._settings.timeout_seconds
            ) as response:
                data = response.read(1_048_577)
                if len(data) > 1_048_576:
                    raise LLMProviderError("PROVIDER: response exceeds size limit")
                return data
        except HTTPError:
            raise LLMProviderError("PROVIDER: request rejected") from None
        except TimeoutError:
            raise LLMTimeoutError("LLM request exceeded its deadline") from None
        except (URLError, OSError):
            raise LLMNetworkError("NETWORK: request could not complete") from None


def _schema_diagnostic(error: LLMResponseValidationError, model: type[BaseModel]) -> str:
    cause = error.__cause__
    if not isinstance(cause, ValidationError):
        return "invalid structured response"
    fields: set[str] = set()

    def collect(node: object) -> None:
        if isinstance(node, dict):
            properties = node.get("properties")
            if isinstance(properties, dict):
                fields.update(properties)
            for value in node.values():
                collect(value)
        elif isinstance(node, list):
            for value in node:
                collect(value)

    collect(model.model_json_schema())
    diagnostics = []
    for detail in cause.errors(include_input=False, include_context=False, include_url=False)[:5]:
        location = (
            ".".join(
                str(part) if isinstance(part, int) or part in fields else "[unknown-field]"
                for part in detail["loc"][:8]
            )
            or "[root]"
        )
        diagnostics.append(location + ": " + detail["type"])
    return "; ".join(diagnostics)
