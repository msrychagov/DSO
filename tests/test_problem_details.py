from fastapi.testclient import TestClient

from app.main import app


def test_validation_error_returns_problem_details():
    with TestClient(app) as client:
        response = client.post("/items", params={"name": ""})
    assert response.status_code == 422

    payload = response.json()
    assert payload["code"] == "validation_error"
    assert payload["title"] == "Invalid item name"
    assert payload["status"] == 422
    assert payload["type"] == "about:blank"
    assert payload["detail"].startswith("Invalid item name")
    assert "correlation_id" in payload
    assert response.headers["X-Correlation-ID"] == payload["correlation_id"]


def test_http_exception_is_normalized_to_problem_details():
    with TestClient(app) as client:
        response = client.get("/definitely-missing")
    assert response.status_code == 404

    payload = response.json()
    assert payload["code"] == "not_found"
    assert payload["title"] == "Resource not found"
    assert payload["status"] == 404
    assert payload["type"] == "about:blank"
    assert payload["detail"] == "Requested resource was not found"
    assert response.headers["X-Correlation-ID"] == payload["correlation_id"]
