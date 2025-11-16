"""
Tests for MVP functionality.
"""

from fastapi.testclient import TestClient

from src.app.api import app

client = TestClient(app)


class TestAuthentication:
    """Test authentication endpoints."""

    def test_register_user_success(self):
        """Test successful user registration."""
        user_data = {
            "username": "testuser",
            "email": "test@example.com",
            "password": "password123",
        }
        response = client.post("/api/v1/auth/register", json=user_data)
        assert response.status_code == 201
        assert "access_token" in response.json()
        assert response.json()["token_type"] == "bearer"

    def test_register_user_duplicate_username(self):
        """Test registration with duplicate username."""
        user_data = {
            "username": "testuser",
            "email": "test@example.com",
            "password": "password123",
        }
        client.post("/api/v1/auth/register", json=user_data)  # First registration
        response = client.post("/api/v1/auth/register", json=user_data)  # Second registration
        assert response.status_code == 400
        body = response.json()
        assert body["code"] == "http_error"
        assert body["detail"] == "Username already exists"
        assert body["status"] == 400
        assert "correlation_id" in body

    def test_login_success(self):
        """Test successful user login."""
        user_data = {
            "username": "loginuser",
            "email": "login@example.com",
            "password": "password123",
        }
        client.post("/api/v1/auth/register", json=user_data)
        login_data = {"username": "loginuser", "password": "password123"}
        response = client.post("/api/v1/auth/login", json=login_data)
        assert response.status_code == 200
        assert "access_token" in response.json()

    def test_login_invalid_credentials(self):
        """Test login with invalid credentials."""
        login_data = {"username": "nonexistent", "password": "wrongpassword"}
        response = client.post("/api/v1/auth/login", json=login_data)
        assert response.status_code == 401
        body = response.json()
        assert body["code"] == "not_authenticated"
        assert "Invalid credentials" in body["detail"]
        assert body["status"] == 401
        assert "correlation_id" in body


class TestItems:
    """Test items endpoints."""

    def setup_method(self):
        """Setup test data."""
        # Register and login a user
        user_data = {
            "username": "itemuser",
            "email": "item@example.com",
            "password": "password123",
        }
        response = client.post("/api/v1/auth/register", json=user_data)
        self.token = response.json()["access_token"]
        self.headers = {"Authorization": f"Bearer {self.token}"}

    def test_create_item_success(self):
        """Test successful item creation."""
        item_data = {"name": "Test Item", "description": "Test Description"}
        response = client.post("/api/v1/items", json=item_data, headers=self.headers)
        assert response.status_code == 201
        assert response.json()["name"] == "Test Item"
        assert response.json()["owner_id"] == 1  # First registered user has ID 1

    def test_create_item_unauthorized(self):
        """Test item creation without authorization."""
        item_data = {"name": "Unauthorized Item", "description": "Should fail"}
        response = client.post("/api/v1/items", json=item_data)
        assert response.status_code in (401, 403)
        body = response.json()
        assert body["status"] == response.status_code
        assert body["code"] in {"access_denied", "not_authenticated"}
        assert "correlation_id" in body

    def test_get_item_success(self):
        """Test successful item retrieval."""
        item_data = {"name": "Get Item", "description": "Description for get"}
        create_response = client.post("/api/v1/items", json=item_data, headers=self.headers)
        item_id = create_response.json()["id"]

        response = client.get(f"/api/v1/items/{item_id}", headers=self.headers)
        assert response.status_code == 200
        assert response.json()["name"] == "Get Item"

    def test_get_item_not_found(self):
        """Test getting a non-existent item."""
        response = client.get("/api/v1/items/999", headers=self.headers)
        assert response.status_code == 404
        body = response.json()
        assert body["code"] == "not_found"
        assert body["detail"] == "Item not found"
        assert "correlation_id" in body

    def test_get_items_list(self):
        """Test getting a list of items with pagination."""
        item_data1 = {"name": "List Item 1", "description": "Desc 1"}
        item_data2 = {"name": "List Item 2", "description": "Desc 2"}
        client.post("/api/v1/items", json=item_data1, headers=self.headers)
        client.post("/api/v1/items", json=item_data2, headers=self.headers)

        response = client.get("/api/v1/items?limit=1&offset=0", headers=self.headers)
        assert response.status_code == 200
        data = response.json()
        assert len(data["items"]) == 1
        assert data["total"] == 2
        assert data["items"][0]["name"] == "List Item 1"

    def test_update_item_success(self):
        """Test successful item update."""
        item_data = {"name": "Original Name"}
        create_response = client.post("/api/v1/items", json=item_data, headers=self.headers)
        item_id = create_response.json()["id"]

        update_data = {"name": "Updated Name", "description": "New Description"}
        response = client.patch(f"/api/v1/items/{item_id}", json=update_data, headers=self.headers)
        assert response.status_code == 200
        assert response.json()["name"] == "Updated Name"
        assert response.json()["description"] == "New Description"

    def test_delete_item_success(self):
        """Test successful item deletion."""
        item_data = {"name": "Item to Delete"}
        create_response = client.post("/api/v1/items", json=item_data, headers=self.headers)
        item_id = create_response.json()["id"]

        response = client.delete(f"/api/v1/items/{item_id}", headers=self.headers)
        assert response.status_code == 204

        # Verify it's deleted
        get_response = client.get(f"/api/v1/items/{item_id}", headers=self.headers)
        assert get_response.status_code == 404

    def test_access_denied_other_user_item(self):
        """Test that users cannot access other users' items."""
        # Create another user
        user2_data = {
            "username": "user2",
            "email": "user2@example.com",
            "password": "password123",
        }
        user2_response = client.post("/api/v1/auth/register", json=user2_data)
        user2_token = user2_response.json()["access_token"]
        user2_headers = {"Authorization": f"Bearer {user2_token}"}

        # Create item with first user
        item_data = {"name": "User 1 Item", "description": "User 1 Description"}
        create_response = client.post("/api/v1/items", json=item_data, headers=self.headers)
        item_id = create_response.json()["id"]

        # Try to access with second user
        response = client.get(f"/api/v1/items/{item_id}", headers=user2_headers)
        assert response.status_code == 404


class TestHealthCheck:
    """Test health check endpoint."""

    def test_health_check(self):
        """Test health check endpoint."""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "timestamp" in data


class TestNFR:
    """Test NFR endpoints."""

    def test_nfr_status(self):
        """Test NFR status endpoint."""
        response = client.get("/api/v1/nfr/status")
        assert response.status_code == 200
        data = response.json()
        assert "nfr_compliance" in data
        assert "dependency_scan" in data["nfr_compliance"]
        assert "data_encryption" in data["nfr_compliance"]

    def test_nfr_audit_logs(self):
        """Test NFR audit logs endpoint."""
        response = client.get("/api/v1/nfr/audit-logs")
        assert response.status_code == 200
        data = response.json()
        assert "audit_logs" in data


class TestSecurity:
    """Test security endpoints."""

    def test_security_status(self):
        """Test security status endpoint."""
        response = client.get("/api/v1/security/status")
        assert response.status_code == 200
        data = response.json()
        assert "security_status" in data
        assert "rate_limiting_enabled" in data["security_status"]

    def test_security_audit_logs(self):
        """Test security audit logs endpoint."""
        response = client.get("/api/v1/security/audit-logs")
        assert response.status_code == 200
        data = response.json()
        assert "audit_logs" in data
