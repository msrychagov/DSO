import time
from contextlib import contextmanager

from fastapi.testclient import TestClient

from app.main import app
from app.security import RateLimiter, security_middleware


@contextmanager
def limited_rate_limiter(max_requests: int, window_seconds: int):
    previous = security_middleware.rate_limiter
    security_middleware.rate_limiter = RateLimiter(
        max_requests=max_requests,
        time_window=window_seconds,
        enabled=True,
    )
    try:
        yield
    finally:
        security_middleware.rate_limiter = previous


def test_rate_limit_returns_retry_after_header():
    with limited_rate_limiter(max_requests=2, window_seconds=2):
        with TestClient(app) as client:
            client.get("/items")
            client.get("/items")

            response = client.get("/items")
        assert response.status_code == 429
        payload = response.json()
        assert payload["code"] == "rate_limit_exceeded"
        assert payload["status"] == 429
        assert "correlation_id" in payload
        assert response.headers["Retry-After"].isdigit()
        assert response.headers["X-Correlation-ID"] == payload["correlation_id"]


def test_rate_limit_allows_after_window():
    with limited_rate_limiter(max_requests=1, window_seconds=1):
        with TestClient(app) as client:
            assert client.get("/items").status_code == 200
            blocked = client.get("/items")
        assert blocked.status_code == 429

        time.sleep(1.1)
        with TestClient(app) as client:
            response = client.get("/items")
        assert response.status_code == 200
