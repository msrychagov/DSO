"""
Security controls implementation based on threat model analysis.
Implements controls for identified risks R1-R12.
"""

import hashlib
import logging
import os
import time
from collections import defaultdict, deque
from typing import Dict, Optional

from fastapi import HTTPException, Request

logger = logging.getLogger(__name__)


class RateLimiter:
    """Rate limiting control for R1 (Brute force attacks) and R4 (DDoS)"""

    def __init__(self, max_requests: int = 5, time_window: int = 60, enabled: bool = True):
        self.max_requests = max_requests
        self.time_window = time_window
        self.enabled = enabled
        self.requests = defaultdict(deque)

    def is_allowed(self, client_ip: str) -> bool:
        """Check if request is allowed based on rate limiting"""
        if not self.enabled:
            return True

        now = time.time()
        client_requests = self.requests[client_ip]

        # Remove old requests outside time window
        while client_requests and client_requests[0] <= now - self.time_window:
            client_requests.popleft()

        # Check if limit exceeded
        if len(client_requests) >= self.max_requests:
            logger.warning(f"Rate limit exceeded for IP: {client_ip}")
            return False

        # Add current request
        client_requests.append(now)
        return True


class SecurityHeaders:
    """Security headers control for T (Tampering) threats"""

    @staticmethod
    def get_security_headers() -> Dict[str, str]:
        """Return security headers to prevent tampering"""
        return {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Security-Policy": "default-src 'self'",
            "Referrer-Policy": "strict-origin-when-cross-origin",
        }


class InputValidator:
    """Input validation control for T (Tampering) threats"""

    @staticmethod
    def validate_item_name(name: str) -> bool:
        """Validate item name to prevent injection attacks"""
        if not name or len(name.strip()) == 0:
            return False

        # Check for potential SQL injection patterns
        dangerous_patterns = ["'", '"', ";", "--", "/*", "*/", "xp_", "sp_"]
        name_lower = name.lower()

        for pattern in dangerous_patterns:
            if pattern in name_lower:
                logger.warning(f"Potential injection pattern detected: {pattern}")
                return False

        # Check length limits
        if len(name) > 100:
            return False

        return True

    @staticmethod
    def validate_item_id(item_id: int) -> bool:
        """Validate item ID to prevent injection attacks"""
        if not isinstance(item_id, int):
            return False

        if item_id <= 0:
            return False

        # Check for potential overflow
        if item_id > 2**31 - 1:
            return False

        return True


class AuditLogger:
    """Audit logging control for R (Repudiation) threats"""

    @staticmethod
    def log_security_event(event_type: str, details: Dict, request: Request):
        """Log security events for audit trail"""
        log_entry = {
            "timestamp": time.time(),
            "event_type": event_type,
            "client_ip": request.client.host if request.client else "unknown",
            "user_agent": request.headers.get("user-agent", "unknown"),
            "path": str(request.url.path),
            "method": request.method,
            "details": details,
        }

        # In production, this would go to SIEM
        logger.info(f"SECURITY_EVENT: {log_entry}")

        # For demo purposes, also log to file
        with open("security_audit.log", "a") as f:
            f.write(f"{log_entry}\n")


class SessionManager:
    """Session management control for I (Information Disclosure) threats"""

    def __init__(self):
        self.active_sessions = {}
        self.session_timeout = 1800  # 30 minutes

    def create_session(self, user_id: str) -> str:
        """Create secure session token"""
        session_data = {
            "user_id": user_id,
            "created_at": time.time(),
            "last_activity": time.time(),
        }

        # Generate secure session token
        session_token = hashlib.sha256(f"{user_id}{time.time()}".encode()).hexdigest()

        self.active_sessions[session_token] = session_data
        return session_token

    def validate_session(self, session_token: str) -> Optional[Dict]:
        """Validate session token and check timeout"""
        if session_token not in self.active_sessions:
            return None

        session = self.active_sessions[session_token]
        now = time.time()

        # Check session timeout
        if now - session["last_activity"] > self.session_timeout:
            del self.active_sessions[session_token]
            return None

        # Update last activity
        session["last_activity"] = now
        return session

    def invalidate_session(self, session_token: str):
        """Invalidate session token"""
        if session_token in self.active_sessions:
            del self.active_sessions[session_token]


class SecurityMiddleware:
    """Security middleware implementing multiple controls"""

    def __init__(self, rate_limiting_enabled: bool = True):
        self.rate_limiter = RateLimiter(enabled=rate_limiting_enabled)
        self.session_manager = SessionManager()
        self.audit_logger = AuditLogger()

    async def process_request(self, request: Request):
        """Process request through security controls"""
        client_ip = request.client.host if request.client else "unknown"

        # R1, R4: Rate limiting
        if not self.rate_limiter.is_allowed(client_ip):
            self.audit_logger.log_security_event(
                "RATE_LIMIT_EXCEEDED",
                {"client_ip": client_ip, "path": str(request.url.path)},
                request,
            )
            raise HTTPException(
                status_code=429, detail="Rate limit exceeded. Please try again later."
            )

        # R6, R10: Audit logging for sensitive endpoints
        if request.url.path in ["/items", "/login", "/admin"]:
            self.audit_logger.log_security_event(
                "SENSITIVE_ENDPOINT_ACCESS",
                {"path": str(request.url.path), "method": request.method},
                request,
            )

    def get_security_headers(self) -> Dict[str, str]:
        """Get security headers for response"""
        return SecurityHeaders.get_security_headers()


# Global security middleware instance
# Disable rate limiting in test environment
rate_limiting_enabled = os.getenv("RATE_LIMITING_ENABLED", "true").lower() == "true"
security_middleware = SecurityMiddleware(rate_limiting_enabled=rate_limiting_enabled)
