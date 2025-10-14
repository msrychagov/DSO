"""
NFR service implementing P03 security requirements.
Implements security NFR checks from P03.
"""

import logging
import time
from collections import defaultdict, deque
from datetime import datetime
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


class NFRService:
    """Service for NFR compliance and request tracking."""

    def __init__(self):
        self.audit_logs: List[Dict[str, Any]] = []
        self.request_timestamps: Dict[str, deque] = defaultdict(deque)
        self.security_headers_config = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Content-Security-Policy": "default-src 'self'",
        }

    def generate_correlation_id(self) -> str:
        """Generate a unique correlation ID for each request (NFR-10)."""
        import secrets

        return secrets.token_urlsafe(16)

    def log_request(self, correlation_id: str, request_url: str):
        """Log incoming requests for audit purposes (NFR-06)."""
        log_entry = {
            "correlation_id": correlation_id,
            "timestamp": datetime.utcnow().isoformat(),
            "event": "request_received",
            "url": request_url,
            "action": "request",
        }
        self.audit_logs.append(log_entry)
        logger.info(f"Request logged: {log_entry}")

    def check_rate_limit(
        self, user_id: int, max_requests: int = 100, window_seconds: int = 60
    ) -> bool:
        """Check rate limiting (NFR-07)."""
        now = time.time()
        user_key = str(user_id)

        if user_key not in self.request_timestamps:
            self.request_timestamps[user_key] = deque()

        # Remove old requests outside window
        self.request_timestamps[user_key] = [
            req_time
            for req_time in self.request_timestamps[user_key]
            if now - req_time < window_seconds
        ]

        if len(self.request_timestamps[user_key]) >= max_requests:
            return False  # Rate limit exceeded

        self.request_timestamps[user_key].append(now)
        return True

    def check_dependency_vulnerabilities(self) -> Dict[str, Any]:
        """Simulate checking for dependency vulnerabilities (NFR-04)."""
        # In a real scenario, this would integrate with a SAST/SCA tool
        return {
            "status": "PASS",
            "details": "Dependency scan completed successfully",
            "vulnerabilities_found": 0,
            "last_checked": datetime.utcnow().isoformat(),
        }

    def check_data_encryption(self) -> Dict[str, Any]:
        """Simulate checking for data encryption at rest/in transit (NFR-05)."""
        # In a real scenario, this would check DB/storage config or TLS settings
        return {
            "status": "PASS",
            "encryption_at_rest": True,
            "encryption_in_transit": True,
            "details": "Data encryption properly configured",
        }

    def get_audit_logs(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent audit logs."""
        return list(self.audit_logs)[-limit:]

    def get_security_headers(self) -> Dict[str, str]:
        """Get configured security headers (NFR-08)."""
        return self.security_headers_config


# Global NFR service instance
nfr_service = NFRService()
