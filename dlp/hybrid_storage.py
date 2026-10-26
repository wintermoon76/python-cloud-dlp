
from pathlib import Path
import hashlib
import logging
import json

from dlp.storage import (
    STORAGE_ROOT,
    initialize_storage,
    route_file,
)
from dlp.cloud_storage import upload_file
from dlp.audit import record_event

logger = logging.getLogger(__name__)

ZONE_BY_ACTION = {
    "ALLOW": "approved",
    "FLAG": "quarantine",
    "QUARANTINE": "quarantine",
    "BLOCK": "blocked",
}


def save_file_hybrid(
    file_bytes: bytes,
    filename: str,
    action: str,
    findings: dict | None = None,
    risk: str = "UNKNOWN",
) -> dict:
    """Store a file in Azure, falling back to local storage if needed."""

    if not file_bytes:
        raise ValueError("Cannot store an empty file.")

    safe_name = Path(filename).name.strip()

    if not safe_name or safe_name in {".", ".."}:
        raise ValueError("Invalid filename.")

    if action not in ZONE_BY_ACTION:
        raise ValueError("Invalid DLP action.")

    zone = ZONE_BY_ACTION[action]
    file_hash = hashlib.sha256(file_bytes).hexdigest()
    findings_json = json.dumps(findings or {})

    # Try Azure first.
    try:
        cloud_url = upload_file(
            file_bytes=file_bytes,
            filename=safe_name,
            container_name=zone,
        )

        result = {
            "storage": "azure",
            "destination": zone,
            "file_hash": file_hash,
            "location": cloud_url,
            "fallback_used": False,
        }

    except Exception as exc:
        logger.warning(
            "Azure upload failed; using local storage. Reason: %s",
            type(exc).__name__,
        )

        # Local fallback.
        initialize_storage()

        incoming_dir = STORAGE_ROOT / "incoming"
        incoming_dir.mkdir(parents=True, exist_ok=True)

        local_name = f"{file_hash[:12]}_{safe_name}"
        incoming_path = incoming_dir / local_name

        if not incoming_path.exists():
            incoming_path.write_bytes(file_bytes)

        routed_path = route_file(incoming_path, zone)

        result = {
            "storage": "local",
            "destination": zone,
            "file_hash": file_hash,
            "location": str(routed_path),
            "fallback_used": True,
        }

    # Record the final storage outcome.
    record_event(
        filename=safe_name,
        file_hash=file_hash,
        findings=findings_json,
        risk=risk,
        action=action,
        destination=f"{result['storage']}:{result['destination']}",
        status="STORED_LOCAL_FALLBACK" if result["fallback_used"]
        else "STORED_AZURE",
    )

    return result
