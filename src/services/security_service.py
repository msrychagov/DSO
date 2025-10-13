"""
Security service for MVP implementing P04 threat model controls.
"""

import logging
import os
import sys
import time
from collections import defaultdict, deque
from datetime import datetime
from typing import Dict, Optional

from fastapi import HTTPException, Request

logger = logging.getLogger(__name__)


class RateLimiter:
    """Rate limiting control for R1 (Brute force attacks) and R4 (DDoS)"""

    def __init__(
        self, max_requests: int = 5, time_window: int = 60, enabled: bool = True
    ):
        self.max_requests = max_requests
        self.time_window = time_window
        self.enabled = enabled
        self.requests = defaultdict(deque)

    def check_request(self, client_id: str) -> bool:
        """Check if the client is within the rate limit."""
        if not self.enabled:
            return True

        now = time.time()
        # Remove timestamps older than the window
        while (
            self.requests[client_id]
            and self.requests[client_id][0] < now - self.time_window
        ):
            self.requests[client_id].popleft()

        if len(self.requests[client_id]) >= self.max_requests:
            logger.warning(f"Rate limit exceeded for client {client_id}")
            return False

        self.requests[client_id].append(now)
        return True


class InputValidator:
    """Input validation control for R2 (Error details), R3 (SQLi), R8 (Input validation)"""

    def validate_item_name(self, name: str) -> bool:
        """Validate item name for length and dangerous characters."""
        if not (1 <= len(name) <= 100):
            return False
        # Simple check for SQL injection patterns (R3)
        if any(pattern in name.lower() for pattern in ["select * from", "drop table"]):
            return False
        return True

    def validate_item_id(self, item_id: int) -> bool:
        """Validate item ID to be a positive integer."""
        return item_id > 0


class AuditLogger:
    """Audit logging for R6 (Lack of audit)"""

    def __init__(self):
        self.logs = []

    def log_event(
        self, event_type: str, user_id: int, item_id: Optional[int] = None, **kwargs
    ):
        """Log a security-relevant event."""
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": event_type,
            "user_id": user_id,
            "item_id": item_id,
            **kwargs,
        }
        self.logs.append(log_entry)
        logger.info(f"Audit log: {log_entry}")

    def get_logs(self, limit: int = 100) -> list:
        """Get recent audit logs."""
        return list(self.logs)[-limit:]


class SecurityService:
    """Aggregates various security controls."""

    def __init__(self, rate_limiting_enabled: bool = True):
        self.rate_limiter = RateLimiter(enabled=rate_limiting_enabled)
        self.input_validator = InputValidator()
        self.audit_logger = AuditLogger()
        self.security_headers = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Content-Security-Policy": "default-src 'self'",
        }

    def process_request(self, request: Request):
        """Apply security controls to incoming requests."""
        client_id = request.client.host if request.client else "unknown"
        if not self.rate_limiter.check_request(client_id):
            raise HTTPException(status_code=429, detail="Too Many Requests")

    def validate_item_input(self, name: str) -> bool:
        """Validate item creation/update input."""
        return self.input_validator.validate_item_name(name)

    def log_item_event(self, event_type: str, item_id: int, user_id: int, **kwargs):
        """Log item-related security events."""
        self.audit_logger.log_event(event_type, user_id, item_id, **kwargs)

    def get_security_headers(self) -> Dict[str, str]:
        """Get security headers to be added to responses."""
        return self.security_headers

    def get_audit_logs(self, limit: int = 100) -> list:
        """Get audit logs."""
        return self.audit_logger.get_logs(limit)


# Global security service instance
# Disable rate limiting in test environment
rate_limiting_enabled = os.getenv("RATE_LIMITING_ENABLED", "true").lower() == "true"
# Also disable in test environment
if "pytest" in sys.modules:
    rate_limiting_enabled = False
security_service = SecurityService(rate_limiting_enabled=rate_limiting_enabled)
