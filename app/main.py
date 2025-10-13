import logging

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator

from app.security import AuditLogger, InputValidator, security_middleware

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
    try:
        # Process request through security controls
        await security_middleware.process_request(request)
    except HTTPException as e:
        return JSONResponse(
            status_code=e.status_code,
            content={"error": {"code": "SECURITY_ERROR", "message": e.detail}},
            headers=security_middleware.get_security_headers(),
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
    def __init__(self, code: str, message: str, status: int = 400):
        self.code = code
        self.message = message
        self.status = status


@app.exception_handler(ApiError)
async def api_error_handler(request: Request, exc: ApiError):
    logger.warning(f"API Error: {exc.code} - {exc.message} for {request.url}")
    return JSONResponse(
        status_code=exc.status,
        content={"error": {"code": exc.code, "message": exc.message}},
    )


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    # Normalize FastAPI HTTPException into our error envelope
    detail = exc.detail if isinstance(exc.detail, str) else "http_error"
    logger.warning(f"HTTP Error: {exc.status_code} - {detail} for {request.url}")
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": {"code": "http_error", "message": detail}},
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    logger.error(
        f"Unhandled exception: {type(exc).__name__}: {str(exc)} for {request.url}",
        exc_info=True,
    )
    return JSONResponse(
        status_code=500,
        content={"error": {"code": "internal_error", "message": "Internal server error"}},
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
            message="Invalid item name. Contains forbidden characters or exceeds length limit.",
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

    item_id = len(_DB["items"]) + 1
    new_item = {"id": item_id, "name": item.name}
    _DB["items"].append(new_item)


@app.get("/items/{item_id}")
def get_item(item_id: int, request: Request):
    """Get item with security controls"""
    # R2: Input validation to prevent tampering
    if not InputValidator.validate_item_id(item_id):
        logger.warning(f"Invalid item ID attempted: {item_id}")
        raise ApiError(
            code="validation_error",
            message="Invalid item ID. Must be a positive integer.",
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
    raise ApiError(code="not_found", message="item not found", status=404)


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
