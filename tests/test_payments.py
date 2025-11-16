import json
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from src.app.api import app

client = TestClient(app)


@pytest.fixture()
def auth_headers():
    username = f"payuser{uuid4().hex[:8]}"
    user_data = {
        "username": username,
        "email": f"{username}@example.com",
        "password": "securepass1",
    }
    response = client.post("/api/v1/auth/register", json=user_data)
    token = response.json()["access_token"]
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


def test_payment_normalizes_decimal_and_timezone(auth_headers):
    payload = {
        "amount": "10.5",
        "currency": "usd",
        "occurred_at": "2024-01-01T10:00:00+03:00",
        "description": "  order #42 ",
    }
    response = client.post("/api/v1/payments", data=json.dumps(payload), headers=auth_headers)
    assert response.status_code == 201
    body = response.json()
    assert body["amount"] == "10.50"
    assert body["currency"] == "USD"
    assert body["occurred_at"] == "2024-01-01T07:00:00Z"
    assert body["description"] == "order #42"
    assert body["payment_id"]


def test_payment_rejects_invalid_currency(auth_headers):
    payload = {
        "amount": "15.00",
        "currency": "US",
        "occurred_at": "2024-01-01T00:00:00Z",
    }
    response = client.post("/api/v1/payments", data=json.dumps(payload), headers=auth_headers)
    assert response.status_code == 422
    body = response.json()
    assert body["code"] == "invalid_payment_payload"
    assert body["status"] == 422
    assert response.headers["X-Correlation-ID"] == body["correlation_id"]


def test_payment_rejects_invalid_json(auth_headers):
    response = client.post(
        "/api/v1/payments",
        data="{bad-json}",
        headers=auth_headers,
    )
    assert response.status_code == 400
    body = response.json()
    assert body["code"] == "invalid_json"
    assert body["status"] == 400
    assert "correlation_id" in body


def test_payment_rejects_negative_amount(auth_headers):
    payload = {
        "amount": "-1.00",
        "currency": "USD",
        "occurred_at": "2024-01-01T00:00:00Z",
    }
    response = client.post("/api/v1/payments", data=json.dumps(payload), headers=auth_headers)
    assert response.status_code == 422
    body = response.json()
    assert body["code"] == "invalid_payment_payload"
    assert "errors" in body
    assert any(err["loc"][-1] == "amount" for err in body["errors"])
