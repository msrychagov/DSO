"""FastAPI application for the MVP."""

import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, File, HTTPException, Query, Request, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from src.domain.models import (
    Item,
    ItemCreate,
    ItemsResponse,
    ItemUpdate,
    PaginationParams,
    Token,
    User,
    UserCreate,
    UserLogin,
)
from src.security.problem_details import problem_response
from src.security.uploads import MAX_BYTES, UploadError, secure_store
from src.services.auth_service import auth_service
from src.services.item_service import item_service
from src.services.nfr_service import nfr_service
from src.services.payment_service import PaymentValidationError, payment_service
from src.services.security_service import security_service

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="MVP API", description="Minimum Viable Product API", version="1.0.0")

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:8080"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Security
security = HTTPBearer()

UPLOAD_STORAGE_PATH = os.getenv("UPLOAD_STORAGE_PATH", "./var/uploads")

EMAIL_RE = re.compile(r"(?P<local>[A-Za-z0-9._%+-]{1,64})@(?P<domain>[A-Za-z0-9.-]+\.[A-Za-z]{2,})")
PLAIN_DIGITS_RE = re.compile(r"\b\d{6,}\b")


def _ensure_correlation_id(request: Request) -> str:
    """Return existing correlation id or generate a new one."""
    correlation_id = getattr(request.state, "correlation_id", None)
    if not correlation_id:
        correlation_id = nfr_service.generate_correlation_id()
        request.state.correlation_id = correlation_id
    return correlation_id


def _problem_response(
    request: Request,
    *,
    status_code: int,
    title: str,
    detail: str,
    code: str,
    type_: str = "about:blank",
    headers: dict[str, str] | None = None,
    extras: dict[str, Any] | None = None,
):
    """Produce a RFC 7807 response with a stable correlation id."""
    payload = {"code": code}
    if extras:
        payload.update(_sanitize_extras(extras))
    sanitized_detail = _mask_pii(detail)
    return problem_response(
        status=status_code,
        title=title,
        detail=sanitized_detail,
        type_=type_,
        headers=headers,
        extras=payload,
        correlation_id=_ensure_correlation_id(request),
        instance=str(request.url.path),
    )


def _upload_storage_root() -> Path:
    return Path(UPLOAD_STORAGE_PATH)


def _format_utc_iso(value: datetime) -> str:
    return value.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")


def _mask_pii(value: str | None) -> str:
    if not value:
        return value or ""

    def _mask_email(match: re.Match[str]) -> str:
        local = match.group("local")
        domain = match.group("domain")
        masked_local = local[0] + "***" if len(local) > 1 else "***"
        return f"{masked_local}@{domain}"

    masked = EMAIL_RE.sub(_mask_email, value)
    masked = PLAIN_DIGITS_RE.sub("***", masked)
    return masked


def _sanitize_extras(data: Any) -> Any:
    if isinstance(data, dict):
        return {key: _sanitize_extras(value) for key, value in data.items()}
    if isinstance(data, list):
        return [_sanitize_extras(item) for item in data]
    if isinstance(data, str):
        return _mask_pii(data)
    return data


# Add NFR middleware for request tracking
@app.middleware("http")
async def nfr_middleware(request: Request, call_next):
    """NFR middleware for request tracking and security."""
    correlation_id = _ensure_correlation_id(request)
    nfr_service.log_request(correlation_id, str(request.url))

    response = await call_next(request)
    security_headers = nfr_service.get_security_headers()
    for header, value in security_headers.items():
        response.headers[header] = value

    return response


# Add security middleware for threat model controls
@app.middleware("http")
async def security_middleware(request: Request, call_next):
    """Security middleware implementing threat model controls."""
    try:
        security_service.process_request(request)
    except HTTPException as exc:
        headers = security_service.get_security_headers().copy()
        if exc.headers:
            headers.update(exc.headers)
        code = (
            "rate_limit_exceeded"
            if exc.status_code == status.HTTP_429_TOO_MANY_REQUESTS
            else "security_error"
        )
        detail = exc.detail if isinstance(exc.detail, str) else "Security policy violation"
        return _problem_response(
            request,
            status_code=exc.status_code,
            title="Security policy violation",
            detail=detail,
            code=code,
            headers=headers,
        )

    response = await call_next(request)

    security_headers = security_service.get_security_headers()
    for header, value in security_headers.items():
        response.headers[header] = value

    return response


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> User:
    """Get current authenticated user."""
    token = credentials.credentials
    user = auth_service.get_current_user(token)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token"
        )
    return user


def get_admin_user(user: User = Depends(get_current_user)) -> User:
    """Get current admin user."""
    if user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")
    return user


# Exception handlers
@app.exception_handler(ValueError)
async def value_error_exception_handler(request: Request, exc: ValueError):
    """Handle ValueError exceptions."""
    logger.warning("ValueError: %s", exc)
    return _problem_response(
        request,
        status_code=status.HTTP_400_BAD_REQUEST,
        title="Invalid input",
        detail=str(exc),
        code="validation_error",
    )


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Handle HTTPException exceptions."""
    detail = exc.detail if isinstance(exc.detail, str) else "HTTP error"
    status_code = exc.status_code
    title = "HTTP error"
    code = "http_error"

    if status_code == status.HTTP_401_UNAUTHORIZED:
        title = "Authentication required"
        code = "not_authenticated"
    elif status_code == status.HTTP_403_FORBIDDEN:
        title = "Access denied"
        code = "access_denied"
    elif status_code == status.HTTP_404_NOT_FOUND:
        title = "Resource not found"
        code = "not_found"
    elif status_code == status.HTTP_429_TOO_MANY_REQUESTS:
        title = "Too many requests"
        code = "rate_limit_exceeded"

    logger.warning("HTTPException (%s): %s", status_code, detail)
    return _problem_response(
        request,
        status_code=status_code,
        title=title,
        detail=detail,
        code=code,
        headers=exc.headers,
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Handle all other exceptions."""
    logger.error("Unhandled exception: %s", exc, exc_info=True)
    return _problem_response(
        request,
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        title="Internal server error",
        detail="Internal server error",
        code="internal_error",
    )


# Authentication endpoints
@app.post("/api/v1/auth/register", response_model=Token, status_code=status.HTTP_201_CREATED)
async def register(user_data: UserCreate):
    """Register a new user."""
    try:
        user, token = auth_service.register_user(user_data)
        logger.info(f"User registered: {user.username}")
        return auth_service.create_token_response(token)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@app.post("/api/v1/auth/login", response_model=Token)
async def login(login_data: UserLogin):
    """Login user."""
    try:
        user, token = auth_service.login_user(login_data)
        logger.info(f"User logged in: {user.username}")
        return auth_service.create_token_response(token)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))


@app.post("/api/v1/auth/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(current_user: User = Depends(get_current_user)):
    """Logout user."""
    auth_service.logout_user(current_user.id)  # Assuming logout invalidates token by user_id
    # For now, we'll just log the logout
    logger.info(f"User logged out: {current_user.username}")


# Items endpoints
@app.post("/api/v1/items", response_model=Item, status_code=status.HTTP_201_CREATED)
async def create_item(item_data: ItemCreate, current_user: User = Depends(get_current_user)):
    """Create a new item."""
    # Validate input using security service
    if not security_service.validate_item_input(item_data.name):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid item name")

    item = item_service.create_item(item_data, current_user.id)

    # Log security event
    security_service.log_item_event("created", item.id, current_user.id, name=item_data.name)

    logger.info(f"Item created: {item.id} by user {current_user.username}")
    return item


@app.get("/api/v1/items/{item_id}", response_model=Item)
async def get_item(item_id: int, current_user: User = Depends(get_current_user)):
    """Get item by ID."""
    # Validate item ID
    if not security_service.input_validator.validate_item_id(item_id):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid item ID")

    item = item_service.get_item(item_id, current_user)
    if not item:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Item not found")

    # Log access
    security_service.log_item_event("accessed", item_id, current_user.id)

    return item


@app.get("/api/v1/items", response_model=ItemsResponse)
async def get_items(
    limit: int = Query(10, ge=1, le=100),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(get_current_user),
):
    """Get items with pagination."""
    pagination = PaginationParams(limit=limit, offset=offset)
    items, total = item_service.get_user_items(current_user, pagination)

    return ItemsResponse(items=items, total=total, limit=limit, offset=offset)


@app.patch("/api/v1/items/{item_id}", response_model=Item)
async def update_item(
    item_id: int,
    update_data: ItemUpdate,
    current_user: User = Depends(get_current_user),
):
    """Update an item."""
    item = item_service.update_item(item_id, update_data, current_user)
    if not item:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Item not found or access denied",
        )
    logger.info(f"Item updated: {item.id} by user {current_user.username}")
    return item


@app.delete("/api/v1/items/{item_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_item(item_id: int, current_user: User = Depends(get_current_user)):
    """Delete an item."""
    success = item_service.delete_item(item_id, current_user)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Item not found or access denied",
        )
    logger.info(f"Item deleted: {item_id} by user {current_user.username}")


# Payments endpoint
@app.post("/api/v1/payments", status_code=status.HTTP_201_CREATED)
async def record_payment(request: Request, current_user: User = Depends(get_current_user)):
    """Validate and store payment events with strict schema enforcement."""
    raw_body = await request.body()
    try:
        payload = payment_service.parse_payload(raw_body)
    except PaymentValidationError as exc:
        extras = {"errors": exc.errors} if exc.errors else None
        return _problem_response(
            request,
            status_code=exc.status,
            title="Invalid payment payload",
            detail=exc.detail,
            code=exc.code,
            extras=extras,
        )

    record = payment_service.record_payment(payload)
    security_service.audit_logger.log_event(
        "payment_recorded",
        current_user.id,
        item_id=None,
        amount=format(record.amount, ".2f"),
        currency=record.currency,
    )
    logger.info("Payment recorded for user %s", current_user.username)
    return {
        "payment_id": record.id,
        "amount": format(record.amount, ".2f"),
        "currency": record.currency,
        "occurred_at": _format_utc_iso(record.occurred_at),
        "description": record.description,
    }


# Secure file uploads endpoint
@app.post("/api/v1/uploads", status_code=status.HTTP_201_CREATED)
async def upload_secure_file(
    request: Request,
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
):
    """Persist user uploads using strict file validation."""
    raw = await file.read(MAX_BYTES + 1)
    await file.close()
    try:
        stored = secure_store(_upload_storage_root(), raw)
    except UploadError as exc:
        return _problem_response(
            request,
            status_code=exc.status,
            title="Invalid upload",
            detail=exc.message,
            code=exc.code,
            extras={"media_type": file.content_type},
        )

    security_service.audit_logger.log_event(
        "file_uploaded",
        current_user.id,
        item_id=None,
        media_type=stored.media_type,
        resource_id=stored.resource_id,
    )
    logger.info("File uploaded by %s as %s", current_user.username, stored.media_type)
    return {
        "resource_id": stored.resource_id,
        "media_type": stored.media_type,
    }


# Health check
@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}


# NFR endpoints
@app.get("/api/v1/nfr/status")
async def nfr_status():
    """Get NFR compliance status."""
    return {
        "nfr_compliance": {
            "dependency_scan": nfr_service.check_dependency_vulnerabilities(),
            "data_encryption": nfr_service.check_data_encryption(),
            "audit_logs_count": len(nfr_service.get_audit_logs()),
        }
    }


@app.get("/api/v1/nfr/audit-logs")
async def get_audit_logs(limit: int = Query(100, ge=1, le=1000)):
    """Get audit logs for compliance."""
    return {"audit_logs": nfr_service.get_audit_logs(limit)}


# Security endpoints
@app.get("/api/v1/security/audit-logs")
async def get_security_audit_logs(limit: int = Query(100, ge=1, le=1000)):
    """Get security audit logs."""
    return {"audit_logs": security_service.get_audit_logs(limit)}


@app.get("/api/v1/security/status")
async def security_status():
    """Get security status."""
    return {
        "security_status": {
            "rate_limiting_enabled": security_service.rate_limiter.enabled,
            "rate_limit": security_service.rate_limiter.max_requests,
            "time_window": security_service.rate_limiter.time_window,
            "audit_logs_count": len(security_service.get_audit_logs()),
        }
    }
