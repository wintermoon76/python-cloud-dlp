
import hashlib
import json
from pathlib import Path

from dlp.detector import detect_sensitive_data
from dlp.policy import assess_risk, choose_action
from dlp.audit import record_event
from dlp.storage import initialize_storage, route_file


def scan_text(text: str, filename: str = "manual-input.txt") -> dict:
    findings = detect_sensitive_data(text)
    risk = assess_risk(findings)
    action = choose_action(risk)

    file_hash = hashlib.sha256(
        text.encode("utf-8")
    ).hexdigest()

    result = {
        "filename": filename,
        "file_hash": file_hash,
        "findings": findings,
        "risk": risk.value,
        "action": action.value,
    }

    record_event(
        filename=filename,
        file_hash=file_hash,
        findings=json.dumps(findings, sort_keys=True),
        risk=risk.value,
        action=action.value,
        destination="pending",
        status="SCANNED",
    )

    return result


def scan_and_route_file(
    content: bytes,
    filename: str,
) -> dict:
    """
    Scan an uploaded file's extracted text and route the original
    file into the appropriate local storage zone.
    """

    # Prevent directory traversal and unsafe filenames.
    safe_name = Path(filename).name.strip()

    if not safe_name or safe_name in {".", ".."}:
        raise ValueError("Invalid filename.")

    if not content:
        raise ValueError("The uploaded file is empty.")

    initialize_storage()

    # Extracted text is passed separately by the Streamlit app.
    # This function expects the caller to supply scan-ready text bytes.
    text = content.decode("utf-8")

    result = scan_text(text, filename=safe_name)

    zone_by_action = {
        "ALLOW": "approved",
        "FLAG": "quarantine",
        "QUARANTINE": "quarantine",
        "BLOCK": "blocked",
    }

    destination_zone = zone_by_action[result["action"]]

    from dlp.storage import STORAGE_ROOT

    incoming_dir = STORAGE_ROOT / "incoming"
    incoming_dir.mkdir(parents=True, exist_ok=True)

    incoming_path = incoming_dir / safe_name

    # Avoid overwriting existing files.
    if incoming_path.exists():
        stem = Path(safe_name).stem
        suffix = Path(safe_name).suffix
        incoming_path = incoming_dir / (
            f"{stem}_{result['file_hash'][:8]}{suffix}"
        )

    if incoming_path.exists():
        raise FileExistsError(
            "A file with this name and content is already in incoming storage."
        )

    incoming_path.write_bytes(content)

    try:
        routed_path = route_file(incoming_path, destination_zone)
    except Exception:
        # Keep the original file in incoming storage if routing fails.
        raise

    result["destination"] = destination_zone
    result["stored_path"] = str(routed_path)
    result["status"] = "ROUTED"

    # Record a second audit event with the final destination.
    record_event(
        filename=safe_name,
        file_hash=result["file_hash"],
        findings=json.dumps(result["findings"], sort_keys=True),
        risk=result["risk"],
        action=result["action"],
        destination=destination_zone,
        status="ROUTED",
    )

    return result
