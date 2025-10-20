"""
Database adapters for the MVP application.
In-memory storage for simplicity.
"""

import hashlib
from datetime import datetime
from typing import Dict, List, Optional

from src.domain.models import (
    Item,
    ItemCreate,
    ItemUpdate,
    PaginationParams,
    User,
    UserCreate,
)


class Database:
    """In-memory database for MVP."""

    def __init__(self):
        self.users: Dict[int, User] = {}
        self.items: Dict[int, Item] = {}
        self.user_passwords: Dict[int, str] = {}  # In production, use proper password hashing
        self.next_user_id = 1
        self.next_item_id = 1

    def create_user(self, user_data: UserCreate) -> User:
        """Create a new user."""
        user_id = self.next_user_id
        self.next_user_id += 1

        # Hash password (in production, use proper hashing like bcrypt)
        password_hash = hashlib.sha256(user_data.password.encode()).hexdigest()

        user = User(
            id=user_id,
            username=user_data.username,
            email=user_data.email,
            role="user",
            created_at=datetime.utcnow(),
            is_active=True,
        )

        self.users[user_id] = user
        self.user_passwords[user_id] = password_hash

        return user

    def get_user_by_username(self, username: str) -> Optional[User]:
        """Get user by username."""
        for user in self.users.values():
            if user.username == username and user.is_active:
                return user
        return None

    def get_user_by_id(self, user_id: int) -> Optional[User]:
        """Get user by ID."""
        return self.users.get(user_id)

    def verify_password(self, user_id: int, password: str) -> bool:
        """Verify user password."""
        stored_hash = self.user_passwords.get(user_id)
        if not stored_hash:
            return False

        password_hash = hashlib.sha256(password.encode()).hexdigest()
        return stored_hash == password_hash

    def create_item(self, item_data: ItemCreate, owner_id: int) -> Item:
        """Create a new item."""
        item_id = self.next_item_id
        self.next_item_id += 1
        now = datetime.utcnow()
        item = Item(
            id=item_id,
            name=item_data.name,
            description=item_data.description,
            owner_id=owner_id,
            created_at=now,
            updated_at=now,
            is_active=True,
        )
        self.items[item_id] = item
        return item

    def get_item_by_id(self, item_id: int) -> Optional[Item]:
        """Get item by ID."""
        return self.items.get(item_id)

    def get_items_by_owner(
        self, owner_id: int, pagination: PaginationParams
    ) -> tuple[List[Item], int]:
        """Get items by owner with pagination."""
        owner_items = [
            item for item in self.items.values() if item.owner_id == owner_id and item.is_active
        ]
        total = len(owner_items)
        start = pagination.offset
        end = pagination.offset + pagination.limit
        return owner_items[start:end], total

    def get_all_items(self, pagination: PaginationParams) -> tuple[List[Item], int]:
        """Get all active items with pagination."""
        active_items = [item for item in self.items.values() if item.is_active]
        total = len(active_items)
        start = pagination.offset
        end = pagination.offset + pagination.limit
        return active_items[start:end], total

    def update_item(self, item_id: int, update_data: ItemUpdate, owner_id: int) -> Optional[Item]:
        """Update an item."""
        item = self.items.get(item_id)
        if not item or item.owner_id != owner_id:
            return None

        if update_data.name is not None:
            item.name = update_data.name
        if update_data.description is not None:
            item.description = update_data.description
        if update_data.is_active is not None:
            item.is_active = update_data.is_active
        item.updated_at = datetime.utcnow()
        return item

    def delete_item(self, item_id: int, owner_id: int) -> bool:
        """Delete an item (soft delete)."""
        item = self.items.get(item_id)
        if not item or item.owner_id != owner_id:
            return False
        item.is_active = False
        item.updated_at = datetime.utcnow()
        return True


db = Database()
