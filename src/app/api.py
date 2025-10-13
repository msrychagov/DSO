"""
FastAPI application for the MVP.
"""

import logging
from datetime import datetime

from fastapi import Depends, FastAPI, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from src.domain.models import (
    ErrorResponse,
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
from src.services.auth_service import auth_service
from src.services.item_service import item_service
from src.services.nfr_service import nfr_service
from src.services.security_service import security_service

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="MVP API", description="Minimum Viable Product API", version="1.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:8080"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Add security middleware for threat model controls
@app.middleware("http")
async def security_middleware(request, call_next):
    """Security middleware implementing threat model controls."""
    try:
        # Process request through security controls
        security_service.process_request(request)
    except HTTPException as e:
        return JSONResponse(
            status_code=e.status_code,
            content={"error": {"code": "SECURITY_ERROR", "message": e.detail}},
            headers=security_service.get_security_headers(),
        )

    # Process request
    response = await call_next(request)

    # Add security headers to response
    security_headers = security_service.get_security_headers()
    for header, value in security_headers.items():
        response.headers[header] = value

    return response


# Add NFR middleware for request tracking
@app.middleware("http")
async def nfr_middleware(request, call_next):
    """NFR middleware for request tracking and security."""
    correlation_id = nfr_service.generate_correlation_id()
    request.state.correlation_id = correlation_id

    # Log request
    nfr_service.log_request(correlation_id, str(request.url))

    # Add security headers
    response = await call_next(request)
    security_headers = nfr_service.get_security_headers()
    for header, value in security_headers.items():
        response.headers[header] = value

    return response


# Security
security = HTTPBearer()


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
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required"
        )
    return user


# Exception handlers
@app.exception_handler(ValueError)
async def value_error_exception_handler(request, exc: ValueError):
    """Handle ValueError exceptions."""
    logger.warning(f"ValueError: {exc}")
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content=ErrorResponse(code="VALIDATION_ERROR", message=str(exc)).model_dump(),
    )


@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc: HTTPException):
    """Handle HTTPException exceptions."""
    logger.warning(f"HTTPException: {exc.detail}")
    return JSONResponse(
        status_code=exc.status_code,
        content=ErrorResponse(code="HTTP_ERROR", message=exc.detail).model_dump(),
    )


@app.exception_handler(Exception)
async def general_exception_handler(request, exc: Exception):
    """Handle all other exceptions."""
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=ErrorResponse(
            code="INTERNAL_ERROR", message="Internal server error"
        ).model_dump(),
    )


# Authentication endpoints
@app.post(
    "/api/v1/auth/register", response_model=Token, status_code=status.HTTP_201_CREATED
)
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
    auth_service.logout_user(
        current_user.id
    )  # Assuming logout invalidates token by user_id
    # For now, we'll just log the logout
    logger.info(f"User logged out: {current_user.username}")


# Items endpoints
@app.post("/api/v1/items", response_model=Item, status_code=status.HTTP_201_CREATED)
async def create_item(
    item_data: ItemCreate, current_user: User = Depends(get_current_user)
):
    """Create a new item."""
    # Validate input using security service
    if not security_service.validate_item_input(item_data.name):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid item name"
        )

    item = item_service.create_item(item_data, current_user.id)

    # Log security event
    security_service.log_item_event(
        "created", item.id, current_user.id, name=item_data.name
    )

    logger.info(f"Item created: {item.id} by user {current_user.username}")
    return item


@app.get("/api/v1/items/{item_id}", response_model=Item)
async def get_item(item_id: int, current_user: User = Depends(get_current_user)):
    """Get item by ID."""
    # Validate item ID
    if not security_service.input_validator.validate_item_id(item_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid item ID"
        )

    item = item_service.get_item(item_id, current_user)
    if not item:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Item not found"
        )

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
