"""
Item service for the MVP application.
"""

from typing import List, Optional, Tuple

from src.adapters.database import db
from src.domain.models import Item, ItemCreate, ItemUpdate, PaginationParams, User


class ItemService:
    """Item service for business logic."""

    def create_item(self, item_data: ItemCreate, owner_id: int) -> Item:
        """Create a new item."""
        return db.create_item(item_data, owner_id)

    def get_item(self, item_id: int, user: User) -> Optional[Item]:
        """Get item by ID with ownership check."""
        item = db.get_item_by_id(item_id)
        if not item or not item.is_active:
            return None

        # Check ownership or admin access
        if item.owner_id != user.id and user.role != "admin":
            return None

        return item

    def get_user_items(self, user: User, pagination: PaginationParams) -> Tuple[List[Item], int]:
        """Get items for a user with pagination."""
        if user.role == "admin":
            return db.get_all_items(pagination)
        else:
            return db.get_items_by_owner(user.id, pagination)

    def update_item(self, item_id: int, update_data: ItemUpdate, user: User) -> Optional[Item]:
        """Update an item with ownership check."""
        item = db.get_item_by_id(item_id)
        if not item or not item.is_active:
            return None

        # Check ownership or admin access
        if item.owner_id != user.id and user.role != "admin":
            return None

        return db.update_item(item_id, update_data, user.id)

    def delete_item(self, item_id: int, user: User) -> bool:
        """Delete an item with ownership check."""
        item = db.get_item_by_id(item_id)
        if not item or not item.is_active:
            return False

        # Check ownership or admin access
        if item.owner_id != user.id and user.role != "admin":
            return False

        return db.delete_item(item_id, user.id)


# Global item service instance
item_service = ItemService()
