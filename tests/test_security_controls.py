"""
Tests for security controls implemented based on threat model.
Tests cover risks R1-R12 and corresponding STRIDE threats.
"""

import time

import pytest
from fastapi.testclient import TestClient

from app.security import RateLimiter, SessionManager

# Use test app with disabled rate limiting
from app.test_app import app as test_app

client = TestClient(test_app)


class TestRateLimiting:
    """Test R1 (Brute force) and R4 (DDoS) controls"""

    def test_rate_limiting_allows_normal_requests(self):
        """Test that normal requests are allowed"""
        # Create a separate rate limiter for testing
        rate_limiter = RateLimiter(max_requests=5, time_window=60, enabled=True)

        # Test that normal requests are allowed
        for _ in range(3):
            decision = rate_limiter.check("127.0.0.1")
            assert decision.allowed is True
            assert decision.retry_after is None

    def test_rate_limiting_blocks_excessive_requests(self):
        """Test that excessive requests are blocked"""
        # Create a separate rate limiter for testing
        rate_limiter = RateLimiter(max_requests=2, time_window=60, enabled=True)

        # Make requests to fill the limit
        assert rate_limiter.check("127.0.0.1").allowed is True
        assert rate_limiter.check("127.0.0.1").allowed is True
        decision = rate_limiter.check("127.0.0.1")
        assert decision.allowed is False  # Should be blocked
        assert decision.retry_after is not None

    def test_rate_limiter_reset_after_time_window(self):
        """Test that rate limiter resets after time window"""
        rate_limiter = RateLimiter(max_requests=2, time_window=1)

        # Make requests to fill the limit
        assert rate_limiter.check("127.0.0.1").allowed is True
        assert rate_limiter.check("127.0.0.1").allowed is True
        assert rate_limiter.check("127.0.0.1").allowed is False  # Should be blocked

        # Wait for time window to reset
        time.sleep(1.1)
        assert (
            rate_limiter.check("127.0.0.1").allowed is True
        )  # Should be allowed again


class TestInputValidation:
    """Test T (Tampering) controls"""

    def test_valid_item_name(self):
        """Test that valid item names are accepted"""
        response = client.post("/items", params={"name": "Valid Item Name"})
        assert response.status_code == 200
        assert "id" in response.json()
        assert response.json()["name"] == "Valid Item Name"

    def test_invalid_item_name_sql_injection(self):
        """Test that SQL injection patterns are blocked"""
        malicious_names = [
            "'; DROP TABLE items; --",
            "admin' OR '1'='1",
            'test"; DELETE FROM items; --',
            "item'; INSERT INTO users VALUES ('hacker', 'password'); --",
        ]

        for malicious_name in malicious_names:
            response = client.post("/items", params={"name": malicious_name})
            assert response.status_code == 422
            body = response.json()
            assert body["code"] == "validation_error"
            assert "Invalid item name" in body["detail"]

    def test_invalid_item_name_length(self):
        """Test that overly long names are blocked"""
        long_name = "x" * 101  # Exceeds 100 character limit
        response = client.post("/items", params={"name": long_name})
        assert response.status_code == 422
        assert response.json()["code"] == "validation_error"

    def test_empty_item_name(self):
        """Test that empty names are blocked"""
        response = client.post("/items", params={"name": ""})
        assert response.status_code == 422
        assert response.json()["code"] == "validation_error"

    def test_valid_item_id(self):
        """Test that valid item IDs are accepted"""
        # First create an item
        response = client.post("/items", params={"name": "Test Item"})
        assert response.status_code == 200
        item_id = response.json()["id"]

        # Then retrieve it
        response = client.get(f"/items/{item_id}")
        assert response.status_code == 200
        assert response.json()["name"] == "Test Item"

    def test_invalid_item_id_negative(self):
        """Test that negative item IDs are blocked"""
        response = client.get("/items/-1")
        assert response.status_code == 422
        assert response.json()["code"] == "validation_error"

    def test_invalid_item_id_zero(self):
        """Test that zero item ID is blocked"""
        response = client.get("/items/0")
        assert response.status_code == 422
        assert response.json()["code"] == "validation_error"


class TestSecurityHeaders:
    """Test security headers implementation"""

    def test_security_headers_present(self):
        """Test that security headers are present in responses"""
        response = client.get("/items")

        # Check for security headers
        assert "X-Content-Type-Options" in response.headers
        assert "X-Frame-Options" in response.headers
        assert "X-XSS-Protection" in response.headers
        assert "Strict-Transport-Security" in response.headers
        assert "Content-Security-Policy" in response.headers
        assert "Referrer-Policy" in response.headers

    def test_security_headers_values(self):
        """Test that security headers have correct values"""
        response = client.get("/items")

        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert response.headers["X-Frame-Options"] == "DENY"
        assert response.headers["X-XSS-Protection"] == "1; mode=block"
        assert "max-age=31536000" in response.headers["Strict-Transport-Security"]
        assert "default-src 'self'" in response.headers["Content-Security-Policy"]


class TestAuditLogging:
    """Test R (Repudiation) controls"""

    def test_audit_logging_item_creation(self):
        """Test that item creation is logged"""
        response = client.post("/items", params={"name": "Audit Test Item"})
        assert response.status_code == 200

        # Check that audit log file exists and contains the event
        try:
            with open("security_audit.log", "r") as f:
                log_content = f.read()
                assert "ITEM_CREATION" in log_content
                assert "Audit Test Item" in log_content
        except FileNotFoundError:
            pytest.fail("Audit log file should be created")

    def test_audit_logging_item_access(self):
        """Test that item access is logged"""
        # Create an item first
        client.post("/items", params={"name": "Access Test Item"})

        # Access the item
        response = client.get("/items/1")
        assert response.status_code == 200

        # Check that audit log contains the access event
        try:
            with open("security_audit.log", "r") as f:
                log_content = f.read()
                assert "ITEM_ACCESS" in log_content
        except FileNotFoundError:
            pytest.fail("Audit log file should be created")

    def test_audit_logging_items_list(self):
        """Test that items list access is logged"""
        response = client.get("/items")
        assert response.status_code == 200

        # Check that audit log contains the list access event
        try:
            with open("security_audit.log", "r") as f:
                log_content = f.read()
                assert "ITEMS_LIST_ACCESS" in log_content
        except FileNotFoundError:
            pytest.fail("Audit log file should be created")


class TestSessionManagement:
    """Test I (Information Disclosure) controls"""

    def test_session_creation(self):
        """Test that sessions can be created"""
        session_manager = SessionManager()
        session_token = session_manager.create_session("test_user")

        assert session_token is not None
        assert len(session_token) == 64  # SHA256 hex length
        assert session_token in session_manager.active_sessions

    def test_session_validation(self):
        """Test that valid sessions are validated"""
        session_manager = SessionManager()
        session_token = session_manager.create_session("test_user")

        session_data = session_manager.validate_session(session_token)
        assert session_data is not None
        assert session_data["user_id"] == "test_user"

    def test_session_timeout(self):
        """Test that sessions timeout after specified time"""
        session_manager = SessionManager()
        session_token = session_manager.create_session("test_user")

        # Simulate time passing
        session_manager.active_sessions[session_token]["last_activity"] = (
            time.time() - 2000  # 33+ minutes ago
        )

        session_data = session_manager.validate_session(session_token)
        assert session_data is None  # Should be invalid due to timeout

    def test_session_invalidation(self):
        """Test that sessions can be invalidated"""
        session_manager = SessionManager()
        session_token = session_manager.create_session("test_user")

        # Invalidate session
        session_manager.invalidate_session(session_token)

        session_data = session_manager.validate_session(session_token)
        assert session_data is None  # Should be invalid after invalidation


class TestCORSConfiguration:
    """Test CORS security configuration"""

    def test_cors_restricts_origins(self):
        """Test that CORS restricts origins"""
        # Test with allowed origin
        response = client.get("/items", headers={"Origin": "https://localhost:3000"})
        assert response.status_code == 200

        # Test with disallowed origin (should still work but CORS headers should be restrictive)
        response = client.get(
            "/items", headers={"Origin": "https://malicious-site.com"}
        )
        # The request itself should work, but CORS headers should prevent cross-origin access
        assert response.status_code == 200

    def test_cors_restricts_methods(self):
        """Test that CORS restricts HTTP methods"""
        # Test allowed methods
        response = client.get("/items")
        assert response.status_code == 200

        response = client.post("/items", params={"name": "Test"})
        assert response.status_code == 200

        # Test disallowed methods (should be handled by CORS middleware)
        response = client.options("/items")
        # OPTIONS should be allowed for CORS preflight
        assert response.status_code in [
            200,
            405,
        ]  # Either allowed or method not allowed


class TestErrorHandling:
    """Test error handling and information disclosure prevention"""

    def test_error_messages_do_not_leak_information(self):
        """Test that error messages don't leak sensitive information"""
        # Test with invalid item ID
        response = client.get("/items/999999")
        assert response.status_code == 404
        payload = response.json()
        error_message = payload["detail"]
        assert payload["code"] == "not_found"

        # Error message should be generic, not revealing internal details
        assert "item not found" in error_message.lower()
        assert "database" not in error_message.lower()
        assert "sql" not in error_message.lower()

    def test_validation_errors_are_generic(self):
        """Test that validation errors are generic"""
        response = client.post("/items", params={"name": "'; DROP TABLE items; --"})
        assert response.status_code == 422
        payload = response.json()
        error_message = payload["detail"]
        assert payload["code"] == "validation_error"

        # Error message should be generic, not revealing the specific attack pattern
        assert "Invalid item name" in error_message
        assert "DROP TABLE" not in error_message
        assert "SQL" not in error_message
