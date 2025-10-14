"""
Domain models for the MVP application.
"""

import enum
from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


class UserRole(str, enum.Enum):
    """User roles."""

    USER = "user"
    ADMIN = "admin"


class User(BaseModel):
    """User domain model."""

    id: int
    username: str = Field(..., min_length=3, max_length=50)
    email: str = Field(..., pattern=r"^[^@]+@[^@]+\.[^@]+$")
    role: UserRole = UserRole.USER
    created_at: datetime
    is_active: bool = True

    @field_validator("username")
    @classmethod
    def validate_username(cls, v):
        if not v.isalnum():
            raise ValueError("Username must be alphanumeric")
        return v


class UserCreate(BaseModel):
    """User creation model."""

    username: str = Field(..., min_length=3, max_length=50)
    email: str = Field(..., pattern=r"^[^@]+@[^@]+\.[^@]+$")
    password: str = Field(..., min_length=6)


class UserLogin(BaseModel):
    """User login model."""

    username: str
    password: str


class Token(BaseModel):
    """Authentication token model."""

    access_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds


class Item(BaseModel):
    """Item domain model."""

    id: int
    name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = None
    owner_id: int
    created_at: datetime
    updated_at: datetime
    is_active: bool = True


class ItemCreate(BaseModel):
    """Item creation model."""

    name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = None


class ItemUpdate(BaseModel):
    """Item update model."""

    name: Optional[str] = Field(None, min_length=1, max_length=100)
    description: Optional[str] = None
    is_active: Optional[bool] = None


class PaginationParams(BaseModel):
    """Pagination parameters."""

    limit: int = Field(10, ge=1, le=100)
    offset: int = Field(0, ge=0)


class ItemsResponse(BaseModel):
    """Response model for listing items."""

    items: List[Item]
    total: int
    limit: int
    offset: int


class ErrorResponse(BaseModel):
    """Standardized error response model."""

    code: str
    message: str
    details: Optional[Dict[str, Any]] = None
