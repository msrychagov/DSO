from fastapi.testclient import TestClient

from app.main import app


def test_range_header_is_blocked_with_problem_response():
    with TestClient(app) as client:
        response = client.get("/health", headers={"Range": "bytes=0-10"})

    assert response.status_code == 416
    payload = response.json()
    assert payload["code"] == "range_header_blocked"
    assert payload["title"] == "Range requests disabled"
    assert payload["status"] == 416
    assert payload["detail"] == "Range header is not supported"
    assert "X-Correlation-ID" in response.headers
