import logging
import os
from pathlib import Path
from typing import Any, Mapping

from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.security import AuditLogger, InputValidator, security_middleware
from src.security import problem_response
from src.security.uploads import MAX_BYTES, UploadError, secure_store

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="SecDev Course App", version="0.1.0")

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://localhost:3000"],  # Only allow specific origins
    allow_credentials=True,
    allow_methods=["GET", "POST"],  # Restrict methods
    allow_headers=["*"],
)


@app.middleware("http")
async def security_middleware_handler(request: Request, call_next):
    """Security middleware implementing threat model controls"""
    if request.headers.get("range"):
        logger.warning("Blocked Range header from %s", request.client)
        security_headers = security_middleware.get_security_headers()
        return problem_response(
            status=416,
            title="Range requests disabled",
            detail="Range header is not supported",
            extras={"code": "range_header_blocked"},
            headers=security_headers,
            instance=str(request.url.path),
        )
    try:
        # Process request through security controls
        await security_middleware.process_request(request)
    except HTTPException as e:
        security_headers = security_middleware.get_security_headers()
        if e.headers:
            security_headers.update(e.headers)
        title = "Rate limit exceeded" if e.status_code == 429 else "Security policy violation"
        detail = e.detail if isinstance(e.detail, str) else title
        extras = {
            "code": "rate_limit_exceeded" if e.status_code == 429 else "security_error",
        }
        return problem_response(
            status=e.status_code,
            title=title,
            detail=detail,
            headers=security_headers,
            extras=extras,
            instance=str(request.url.path),
        )

    # Process request
    response = await call_next(request)

    # Add security headers to response
    security_headers = security_middleware.get_security_headers()
    for header, value in security_headers.items():
        response.headers[header] = value

    return response


# Модели данных
class ItemCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100, description="Item name")

    @field_validator("name")
    @classmethod
    def validate_name(cls, v):
        if not v or not v.strip():
            raise ValueError("Name cannot be empty or whitespace only")
        return v.strip()


class ItemResponse(BaseModel):
    id: int
    name: str


class ErrorResponse(BaseModel):
    error: dict


class ApiError(Exception):
    def __init__(
        self,
        *,
        code: str,
        title: str,
        detail: str,
        status: int = 400,
        type_: str = "about:blank",
        extras: dict[str, Any] | None = None,
    ):
        self.code = code
        self.title = title
        self.detail = detail
        self.status = status
        self.type_ = type_
        self.extras = extras or {}


@app.exception_handler(ApiError)
async def api_error_handler(request: Request, exc: ApiError):
    logger.warning(f"API Error: {exc.code} - {exc.detail} for {request.url}")
    extras = {"code": exc.code}
    extras.update(exc.extras)
    return problem_response(
        status=exc.status,
        title=exc.title,
        detail=exc.detail,
        type_=exc.type_,
        extras=extras,
        instance=str(request.url.path),
    )


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    # Normalize FastAPI HTTPException into our error envelope
    return _http_problem_response(
        request,
        status=exc.status_code,
        detail=exc.detail,
        headers=exc.headers,
    )


@app.exception_handler(StarletteHTTPException)
async def starlette_http_exception_handler(request: Request, exc: StarletteHTTPException):
    return _http_problem_response(
        request,
        status=exc.status_code,
        detail=exc.detail,
        headers=exc.headers,
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    logger.error(
        f"Unhandled exception: {type(exc).__name__}: {str(exc)} for {request.url}",
        exc_info=True,
    )
    return problem_response(
        status=500,
        title="Internal server error",
        detail="Internal server error",
        extras={"code": "internal_error"},
        instance=str(request.url.path),
    )


def _http_problem_response(
    request: Request,
    *,
    status: int,
    detail: Any,
    headers: Mapping[str, str] | None,
):
    """Normalize HTTP exceptions to RFC 7807."""
    normalized_detail = detail if isinstance(detail, str) else "HTTP error"
    title = "HTTP error"
    code = "http_error"
    if status == 404:
        title = "Resource not found"
        normalized_detail = "Requested resource was not found"
        code = "not_found"
    logger.warning(f"HTTP Error: {status} - {normalized_detail} for {request.url}")
    return problem_response(
        status=status,
        title=title,
        detail=normalized_detail,
        headers=headers,
        extras={"code": code},
        instance=str(request.url.path),
    )


@app.get("/health")
def health():
    return {"status": "ok"}


# Example minimal entity (for tests/demo)
_DB = {"items": []}


@app.post("/items")
def create_item(name: str, request: Request):
    """Create item with security controls"""
    # R2: Input validation to prevent tampering
    if not InputValidator.validate_item_name(name):
        logger.warning(f"Invalid item name attempted: {name}")
        raise ApiError(
            code="validation_error",
            title="Invalid item name",
            detail="Invalid item name. Contains forbidden characters or exceeds length limit.",
            status=422,
        )

    # R6: Audit logging for sensitive operations
    AuditLogger.log_security_event(
        "ITEM_CREATION",
        {
            "item_name": name,
            "client_ip": request.client.host if request.client else "unknown",
        },
        request,
    )

    item = {"id": len(_DB["items"]) + 1, "name": name}
    _DB["items"].append(item)
    logger.info(f"Item created successfully: {item}")
    return item


@app.get("/items/{item_id}")
def get_item(item_id: int, request: Request):
    """Get item with security controls"""
    # R2: Input validation to prevent tampering
    if not InputValidator.validate_item_id(item_id):
        logger.warning(f"Invalid item ID attempted: {item_id}")
        raise ApiError(
            code="validation_error",
            title="Invalid item identifier",
            detail="Invalid item ID. Must be a positive integer.",
            status=422,
        )

    # R6: Audit logging for data access
    AuditLogger.log_security_event(
        "ITEM_ACCESS",
        {
            "item_id": item_id,
            "client_ip": request.client.host if request.client else "unknown",
        },
        request,
    )

    for it in _DB["items"]:
        if it["id"] == item_id:
            logger.info(f"Item accessed successfully: {it}")
            return it

    logger.warning(f"Item not found: {item_id}")
    raise ApiError(
        code="not_found",
        title="Item not found",
        detail="item not found",
        status=404,
    )


@app.get("/items")
def list_items(request: Request):
    """List all items with security controls"""
    # R6: Audit logging for data listing
    AuditLogger.log_security_event(
        "ITEMS_LIST_ACCESS",
        {"client_ip": request.client.host if request.client else "unknown"},
        request,
    )

    logger.info(f"Items list accessed, count: {len(_DB['items'])}")
    return {"items": _DB["items"], "count": len(_DB["items"])}


UPLOAD_STORAGE_PATH = os.getenv("UPLOAD_STORAGE_PATH", "./var/uploads")


def _upload_storage_root() -> Path:
    return Path(UPLOAD_STORAGE_PATH)


@app.post("/uploads")
async def upload_file(request: Request, file: UploadFile = File(...)):
    """Upload endpoint protected by secure storage controls."""
    raw = await file.read(MAX_BYTES + 1)
    await file.close()
    try:
        stored = secure_store(_upload_storage_root(), raw)
    except UploadError as exc:
        logger.warning("Upload rejected: %s (%s)", exc.code, request.url)
        raise ApiError(
            code=exc.code,
            title="Invalid upload",
            detail=exc.message,
            status=exc.status,
            extras={"media_type": file.content_type},
        ) from exc

    AuditLogger.log_security_event(
        "FILE_UPLOAD",
        {
            "resource_id": stored.resource_id,
            "media_type": stored.media_type,
            "client_ip": request.client.host if request.client else "unknown",
        },
        request,
    )

    return {
        "resource_id": stored.resource_id,
        "media_type": stored.media_type,
    }
