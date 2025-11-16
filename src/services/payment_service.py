"""Payment validation service implementing secure coding controls."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from decimal import Decimal
from json import JSONDecodeError
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator


def _normalize_to_utc(dt: datetime) -> datetime:
    """Return a naive datetime normalized to UTC."""
    if dt.tzinfo is None:
        tz_aware = dt.replace(tzinfo=timezone.utc)
    else:
        tz_aware = dt.astimezone(timezone.utc)
    return tz_aware.replace(tzinfo=None)


def _serialize_errors(errors: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Convert validation errors into JSON serializable payloads without PII."""

    def convert(value: Any) -> Any:
        if isinstance(value, Decimal):
            return format(value, ".2f")
        if isinstance(value, list):
            return [convert(item) for item in value]
        if isinstance(value, dict):
            return {key: convert(val) for key, val in value.items()}
        return value

    sanitized_errors: list[dict[str, Any]] = []
    for error in errors:
        filtered = {key: convert(val) for key, val in error.items() if key != "input"}
        sanitized_errors.append(filtered)
    return sanitized_errors


class PaymentPayload(BaseModel):
    """Strict schema describing incoming payment payloads."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    amount: Decimal = Field(gt=Decimal("0"), max_digits=12, decimal_places=2)
    currency: str = Field(min_length=3, max_length=3, pattern=r"^[A-Z]{3}$")
    occurred_at: datetime
    description: str | None = Field(default=None, max_length=200)

    @field_validator("currency", mode="before")
    @classmethod
    def normalize_currency(cls, value: str) -> str:
        return value.upper()

    @field_validator("description")
    @classmethod
    def normalize_description(cls, value: str | None) -> str | None:
        if value == "":
            return None
        return value

    @field_validator("occurred_at")
    @classmethod
    def normalize_timestamp(cls, value: datetime) -> datetime:
        return _normalize_to_utc(value)


class PaymentRecord(BaseModel):
    """Stored payment entry returned to API clients."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        json_encoders={Decimal: lambda value: format(value, ".2f")},
    )

    id: str
    amount: Decimal
    currency: str
    occurred_at: datetime
    description: str | None = None


class PaymentValidationError(Exception):
    """Raised when payload parsing or validation fails."""

    def __init__(
        self,
        *,
        code: str,
        detail: str,
        status: int,
        errors: list[dict[str, Any]] | None = None,
    ):
        self.code = code
        self.detail = detail
        self.status = status
        self.errors = errors or []
        super().__init__(detail)


class PaymentService:
    """Service responsible for validating and storing payments."""

    def __init__(self):
        self._payments: list[PaymentRecord] = []

    def reset(self) -> None:
        """Clear stored state (useful for tests)."""
        self._payments.clear()

    def parse_payload(self, raw_body: bytes) -> PaymentPayload:
        """Parse raw request body using safe JSON settings."""
        try:
            text = raw_body.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise PaymentValidationError(
                code="invalid_encoding",
                detail="Request body must be UTF-8 encoded",
                status=400,
            ) from exc

        try:
            payload = json.loads(text, parse_float=str)
        except JSONDecodeError as exc:
            raise PaymentValidationError(
                code="invalid_json", detail="Malformed JSON payload", status=400
            ) from exc

        try:
            return PaymentPayload.model_validate(payload)
        except ValidationError as exc:
            raise PaymentValidationError(
                code="invalid_payment_payload",
                detail="Payment payload failed validation",
                status=422,
                errors=_serialize_errors(exc.errors()),
            ) from exc

    def record_payment(self, payload: PaymentPayload) -> PaymentRecord:
        """Persist validated payment information."""
        record = PaymentRecord(
            id=str(uuid4()),
            amount=payload.amount,
            currency=payload.currency,
            occurred_at=payload.occurred_at,
            description=payload.description,
        )
        self._payments.append(record)
        return record

    def list_payments(self) -> list[PaymentRecord]:
        """Return stored payments (used in status endpoints/tests)."""
        return list(self._payments)


# Global singleton used by the FastAPI layer.
payment_service = PaymentService()
