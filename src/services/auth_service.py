"""
Authentication service for the MVP application.
"""

import secrets
from datetime import datetime, timedelta
from typing import Optional

from src.adapters.database import db
from src.domain.models import Token, User, UserCreate, UserLogin


class AuthService:
    """Authentication service."""

    def __init__(self):
        self.active_tokens: dict[str, dict] = {}  # token -> {user_id, expires_at}
        self.token_expiry_hours = 24

    def register_user(self, user_data: UserCreate) -> tuple[User, str]:
        """Register a new user."""
        existing_user = db.get_user_by_username(user_data.username)
        if existing_user:
            raise ValueError("Username already exists")

        # Create user
        user = db.create_user(user_data)

        # Generate token
        token = self._generate_token(user.id)

        return user, token

    def login_user(self, login_data: UserLogin) -> tuple[User, str]:
        """Login user."""
        user = db.get_user_by_username(login_data.username)
        if not user or not user.is_active:
            raise ValueError("Invalid credentials")

        if not db.verify_password(user.id, login_data.password):
            raise ValueError("Invalid credentials")

        # Generate token
        token = self._generate_token(user.id)

        return user, token

    def logout_user(self, token: str) -> bool:
        """Logout user by invalidating token."""
        if token in self.active_tokens:
            del self.active_tokens[token]
            return True
        return False

    def get_current_user(self, token: str) -> Optional[User]:
        """Get current user from token."""
        token_data = self.active_tokens.get(token)
        if not token_data:
            return None

        # Check if token is expired
        if datetime.utcnow() > token_data["expires_at"]:
            del self.active_tokens[token]
            return None

        return db.get_user_by_id(token_data["user_id"])

    def is_admin(self, token: str) -> bool:
        """Check if user is admin."""
        user = self.get_current_user(token)
        return user and user.role == "admin"

    def _generate_token(self, user_id: int) -> str:
        """Generate authentication token."""
        token = secrets.token_urlsafe(32)
        expires_at = datetime.utcnow() + timedelta(hours=self.token_expiry_hours)

        self.active_tokens[token] = {"user_id": user_id, "expires_at": expires_at}

        return token

    def create_token_response(self, token: str) -> Token:
        """Create token response."""
        return Token(
            access_token=token,
            token_type="bearer",
            expires_in=self.token_expiry_hours * 3600,
        )


# Global auth service instance
auth_service = AuthService()
