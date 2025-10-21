"""Helpers for generating RFC 7807 compliant error responses."""

from __future__ import annotations

from typing import Any, Mapping, MutableMapping
from uuid import uuid4

from fastapi.responses import JSONResponse

DEFAULT_TYPE = "about:blank"


def _ensure_headers(headers: Mapping[str, str] | None) -> MutableMapping[str, str]:
    """Return a mutable copy of headers or an empty dict."""
    return dict(headers or {})


def problem_response(
    *,
    status: int,
    title: str,
    detail: str,
    type_: str = DEFAULT_TYPE,
    instance: str | None = None,
    extras: Mapping[str, Any] | None = None,
    headers: Mapping[str, str] | None = None,
    correlation_id: str | None = None,
) -> JSONResponse:
    """
    Produce an RFC 7807 compliant JSON response.

    The function also mirrors the correlation id in the `X-Correlation-ID` header
    so that clients can trace the error end-to-end.
    """
    cid = correlation_id or str(uuid4())
    payload: dict[str, Any] = {
        "type": type_,
        "title": title,
        "status": status,
        "detail": detail,
        "correlation_id": cid,
    }
    if instance:
        payload["instance"] = instance
    if extras:
        payload.update(extras)

    response_headers = _ensure_headers(headers)
    # Preserve existing header if middleware already set it.
    response_headers.setdefault("X-Correlation-ID", cid)
    return JSONResponse(status_code=status, content=payload, headers=response_headers)
