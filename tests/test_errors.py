from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_not_found_item():
    r = client.get("/items/999")
    assert r.status_code == 404
    body = r.json()
    assert body["code"] == "not_found"
    assert body["title"] == "Item not found"
    assert body["status"] == 404
    assert "correlation_id" in body


def test_validation_error():
    r = client.post("/items", params={"name": ""})
    assert r.status_code == 422
    body = r.json()
    assert body["code"] == "validation_error"
    assert body["title"] == "Invalid item name"
    assert body["status"] == 422
