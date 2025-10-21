# tests/conftest.py
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]  # корень репозитория
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.security import security_middleware  # noqa: E402


@pytest.fixture(autouse=True)
def reset_rate_limiter():
    """Ensure rate limiter state does not leak across tests."""
    security_middleware.rate_limiter.requests.clear()
    yield
    security_middleware.rate_limiter.requests.clear()
