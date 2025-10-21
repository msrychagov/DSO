import shutil
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

import app.main as main_module
from app.main import app
from src.security.uploads import MAX_BYTES, PNG_MAGIC


@pytest.fixture()
def uploads_tmp_dir(monkeypatch):
    """Provide isolated upload directory inside the workspace."""
    previous = getattr(main_module, "UPLOAD_STORAGE_PATH", "./var/uploads")
    base_dir = Path("tmp/test-uploads")
    storage_dir = base_dir / f"case-{uuid4()}"
    storage_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(main_module, "UPLOAD_STORAGE_PATH", str(storage_dir))
    try:
        yield storage_dir
    finally:
        shutil.rmtree(storage_dir, ignore_errors=True)
        monkeypatch.setattr(main_module, "UPLOAD_STORAGE_PATH", previous)


def test_upload_png_success(uploads_tmp_dir):
    payload = PNG_MAGIC + b"\x00\x00\x00\x00IEND\xaeB`\x82"
    with TestClient(app) as client:
        response = client.post(
            "/uploads",
            files={"file": ("test.png", payload, "image/png")},
        )
    assert response.status_code == 200
    data = response.json()
    saved_path = Path(uploads_tmp_dir) / data["resource_id"]
    assert saved_path.exists()
    assert saved_path.read_bytes() == payload
    assert data["media_type"] == "image/png"


def test_rejects_oversized_payload(uploads_tmp_dir):
    payload = PNG_MAGIC + b"\x00" * (MAX_BYTES + 1 - len(PNG_MAGIC))
    with TestClient(app) as client:
        response = client.post(
            "/uploads",
            files={"file": ("too-big.png", payload, "image/png")},
        )
    assert response.status_code == 413
    body = response.json()
    assert body["code"] == "payload_too_large"
    assert body["status"] == 413


def test_rejects_bad_signature(uploads_tmp_dir):
    payload = b"not-an-image"
    with TestClient(app) as client:
        response = client.post(
            "/uploads",
            files={"file": ("text.txt", payload, "text/plain")},
        )
    assert response.status_code == 415
    body = response.json()
    assert body["code"] == "unsupported_media_type"
    assert body["status"] == 415
