import shutil
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

import src.app.api as api_module
from src.app.api import app
from src.security.uploads import MAX_BYTES, PNG_MAGIC

client = TestClient(app)


@pytest.fixture()
def auth_headers():
    username = f"upload{uuid4().hex[:8]}"
    user_data = {
        "username": username,
        "email": f"{username}@example.com",
        "password": "securepass1",
    }
    response = client.post("/api/v1/auth/register", json=user_data)
    token = response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture()
def uploads_tmp_dir(monkeypatch, tmp_path):
    base_dir = tmp_path / f"uploads-{uuid4().hex}"
    base_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(api_module, "UPLOAD_STORAGE_PATH", str(base_dir))
    yield base_dir
    shutil.rmtree(base_dir, ignore_errors=True)


def test_secure_uploads_persist_file(auth_headers, uploads_tmp_dir):
    payload = PNG_MAGIC + b"\x00\x00\x00\x0dIEND\xaeB`\x82"
    with TestClient(app) as local_client:
        response = local_client.post(
            "/api/v1/uploads",
            headers=auth_headers,
            files={"file": ("test.png", payload, "image/png")},
        )
    assert response.status_code == 201
    body = response.json()
    saved_path = Path(uploads_tmp_dir) / body["resource_id"]
    assert saved_path.exists()
    assert saved_path.read_bytes() == payload
    assert body["media_type"] == "image/png"


def test_secure_uploads_reject_large_payload(auth_headers, uploads_tmp_dir):
    payload = PNG_MAGIC + b"\x00" * (MAX_BYTES + 1 - len(PNG_MAGIC))
    response = client.post(
        "/api/v1/uploads",
        headers=auth_headers,
        files={"file": ("big.png", payload, "image/png")},
    )
    assert response.status_code == 413
    body = response.json()
    assert body["code"] == "payload_too_large"
    assert body["status"] == 413


def test_secure_uploads_reject_bad_signature(auth_headers, uploads_tmp_dir):
    payload = b"malware!"
    response = client.post(
        "/api/v1/uploads",
        headers=auth_headers,
        files={"file": ("bad.txt", payload, "text/plain")},
    )
    assert response.status_code == 415
    body = response.json()
    assert body["code"] == "unsupported_media_type"
    assert "media_type" in body
