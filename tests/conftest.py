# tests/conftest.py
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]  # корень репозитория
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.security import security_middleware  # noqa: E402
from src.adapters.database import db  # noqa: E402
from src.services.payment_service import payment_service  # noqa: E402


@pytest.fixture(autouse=True)
def reset_rate_limiter():
    """Ensure rate limiter state does not leak across tests."""
    security_middleware.rate_limiter.requests.clear()
    yield
    security_middleware.rate_limiter.requests.clear()


@pytest.fixture(autouse=True)
def reset_payments():
    """Reset in-memory payments between tests."""
    payment_service.reset()
    yield
    payment_service.reset()


@pytest.fixture(autouse=True)
def reset_database():
    """Reset in-memory database for src app tests."""
    db.users.clear()
    db.items.clear()
    db.user_passwords.clear()
    db.next_user_id = 1
    db.next_item_id = 1
    yield
    db.users.clear()
    db.items.clear()
    db.user_passwords.clear()
    db.next_user_id = 1
    db.next_item_id = 1
