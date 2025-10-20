"""Secure file storage helpers used by the upload endpoint."""

from __future__ import annotations

import os
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Final

PNG_MAGIC: Final = b"\x89PNG\r\n\x1a\n"
JPEG_SOI: Final = b"\xff\xd8"
JPEG_EOI: Final = b"\xff\xd9"
MAX_BYTES: Final = 5_000_000  # 5 MB hard limit

ALLOWED_TYPES: Final[dict[str, str]] = {
    "image/png": ".png",
    "image/jpeg": ".jpg",
}


@dataclass(frozen=True, slots=True)
class StoredFile:
    """Result descriptor returned by `secure_store`."""

    resource_id: str
    media_type: str
    path: Path


class UploadError(Exception):
    """Domain exception for upload validation errors."""

    def __init__(self, code: str, message: str, status: int):
        self.code = code
        self.message = message
        self.status = status
        super().__init__(message)


def sniff_media_type(data: bytes) -> str | None:
    """Return detected media type or None if data is not a supported image."""
    if data.startswith(PNG_MAGIC):
        return "image/png"
    if data.startswith(JPEG_SOI) and data.endswith(JPEG_EOI):
        return "image/jpeg"
    return None


def _resolve_storage_dir(base_dir: str | os.PathLike[str]) -> Path:
    base_path = Path(base_dir).expanduser().resolve()
    base_path.mkdir(parents=True, exist_ok=True)

    # Reject storage rooted in symlinks to avoid swapping directories at runtime.
    if base_path.is_symlink():
        raise UploadError("symlink_parent", "Upload directory must not be a symlink", status=500)
    return base_path


def secure_store(base_dir: str | os.PathLike[str], data: bytes) -> StoredFile:
    """
    Store validated image data on disk.

    The function enforces size/type constraints, generates UUID-based names
    and ensures the resulting path stays within the storage root.
    """
    if len(data) > MAX_BYTES:
        raise UploadError("payload_too_large", "Maximum upload size is 5 MB", status=413)

    media_type = sniff_media_type(data)
    if media_type not in ALLOWED_TYPES:
        raise UploadError(
            "unsupported_media_type", "Only PNG and JPEG images are allowed", status=415
        )

    storage_root = _resolve_storage_dir(base_dir)
    file_name = f"{uuid.uuid4()}{ALLOWED_TYPES[media_type]}"
    file_path = (storage_root / file_name).resolve()

    if not str(file_path).startswith(str(storage_root)):
        raise UploadError("path_traversal", "Invalid storage path detected", status=400)

    # Protect against symlinks anywhere in the ancestor chain.
    if any(parent.is_symlink() for parent in file_path.parents if parent != storage_root):
        raise UploadError("symlink_parent", "Upload directory contains symlinks", status=400)

    file_path.write_bytes(data)
    return StoredFile(resource_id=file_name, media_type=media_type, path=file_path)
