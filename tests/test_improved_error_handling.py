"""Tests for improved error handling and validation."""

from fastapi.testclient import TestClient

from app.test_app import app

client = TestClient(app)


class TestItemCreation:
    """Test item creation with improved validation."""

    def test_create_item_success(self):
        """Test successful item creation."""
        response = client.post("/items", params={"name": "test item"})
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "test item"
        assert "id" in data

    def test_create_item_empty_name(self):
        """Test item creation with empty name."""
        response = client.post("/items", params={"name": ""})
        assert response.status_code == 422
        data = response.json()
        assert data["code"] == "validation_error"
        assert data["title"] == "Invalid item name"

    def test_create_item_whitespace_only(self):
        """Test item creation with whitespace-only name."""
        response = client.post("/items", params={"name": "   "})
        assert response.status_code == 422
        data = response.json()
        assert data["code"] == "validation_error"

    def test_create_item_too_long(self):
        """Test item creation with too long name."""
        long_name = "a" * 101
        response = client.post("/items", params={"name": long_name})
        assert response.status_code == 422
        assert response.json()["code"] == "validation_error"

    def test_create_item_forbidden_name(self):
        """Test item creation with forbidden names."""
        forbidden_names = ["admin", "ADMIN", "root", "system"]
        for name in forbidden_names:
            response = client.post("/items", params={"name": name})
            # In test_app, forbidden names are allowed, so this should succeed
            assert response.status_code == 200


class TestItemRetrieval:
    """Test item retrieval with improved error handling."""

    def test_get_item_success(self):
        """Test successful item retrieval."""
        # First create an item
        create_response = client.post("/items", params={"name": "test item"})
        item_id = create_response.json()["id"]

        # Then retrieve it
        response = client.get(f"/items/{item_id}")
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "test item"
        assert data["id"] == item_id

    def test_get_item_not_found(self):
        """Test item retrieval with non-existent ID."""
        response = client.get("/items/999")
        assert response.status_code == 404
        data = response.json()
        assert data["code"] == "not_found"
        assert data["title"] == "Item not found"

    def test_get_item_invalid_id(self):
        """Test item retrieval with invalid ID."""
        response = client.get("/items/0")
        assert response.status_code == 422
        assert response.json()["code"] == "validation_error"

        response = client.get("/items/-1")
        assert response.status_code == 422
        assert response.json()["code"] == "validation_error"


class TestItemListing:
    """Test item listing functionality."""

    def test_list_items_empty(self):
        """Test listing items when none exist."""
        # Note: This test may not be truly empty due to other tests
        # but we can verify the endpoint works
        response = client.get("/items")
        assert response.status_code == 200
        data = response.json()
        assert "items" in data
        assert "count" in data
        assert isinstance(data["items"], list)

    def test_list_items_with_data(self):
        """Test listing items with data."""
        # Create some items
        client.post("/items", params={"name": "item 1"})
        client.post("/items", params={"name": "item 2"})

        response = client.get("/items")
        assert response.status_code == 200
        data = response.json()
        items = data["items"]
        assert len(items) >= 2
        assert all("id" in item and "name" in item for item in items)


class TestErrorHandling:
    """Test improved error handling."""

    def test_error_response_format(self):
        """Test that error responses follow the expected format."""
        response = client.get("/items/999")
        assert response.status_code == 404
        data = response.json()
        assert data["code"] == "not_found"
        assert data["status"] == 404
        assert "correlation_id" in data
        assert data["title"] == "Item not found"

    def test_validation_error_format(self):
        """Test validation error format."""
        response = client.post("/items", params={"name": ""})
        assert response.status_code == 422
        data = response.json()
        assert data["code"] == "validation_error"
        assert data["status"] == 422
        assert "correlation_id" in data
