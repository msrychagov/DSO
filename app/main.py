import logging

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="SecDev Course App", version="0.1.0")


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
        content={
            "error": {"code": "internal_error", "message": "Internal server error"}
        },
    )


@app.get("/health")
def health():
    return {"status": "ok"}


# Example minimal entity (for tests/demo)
_DB = {"items": []}


@app.post("/items", response_model=ItemResponse)
def create_item(item: ItemCreate):
    """Create a new item with improved validation and logging."""
    logger.info(f"Creating item with name: {item.name}")

    # Дополнительная бизнес-логика валидации
    if item.name.lower() in ["admin", "root", "system"]:
        raise ApiError(
            code="forbidden_name", message="This name is not allowed", status=422
        )

    item_id = len(_DB["items"]) + 1
    new_item = {"id": item_id, "name": item.name}
    _DB["items"].append(new_item)

    logger.info(f"Item created successfully with ID: {item_id}")
    return new_item


@app.get("/items/{item_id}", response_model=ItemResponse)
def get_item(item_id: int):
    """Get item by ID with improved error handling."""
    logger.info(f"Retrieving item with ID: {item_id}")

    if item_id <= 0:
        raise ApiError(
            code="invalid_id", message="Item ID must be positive", status=400
        )

    for item in _DB["items"]:
        if item["id"] == item_id:
            logger.info(f"Item found: {item}")
            return item

    logger.warning(f"Item not found with ID: {item_id}")
    raise ApiError(code="not_found", message="item not found", status=404)


@app.get("/items", response_model=list[ItemResponse])
def list_items():
    """List all items with optional filtering."""
    logger.info(f"Listing all items, count: {len(_DB['items'])}")
    return _DB["items"]
