
import sqlite3
from pathlib import Path
from datetime import datetime, timezone


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DB_PATH = PROJECT_ROOT / "data" / "runtime" / "audit.db"


def initialize_audit() -> None:
    """Create the audit database and table if needed."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    with sqlite3.connect(DB_PATH) as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                filename TEXT NOT NULL,
                file_hash TEXT,
                findings TEXT NOT NULL,
                risk TEXT NOT NULL,
                action TEXT NOT NULL,
                destination TEXT,
                status TEXT NOT NULL
            )
        """)


def record_event(
    filename: str,
    file_hash: str,
    findings: str,
    risk: str,
    action: str,
    destination: str,
    status: str,
) -> None:
    """Store a DLP event without storing the file's sensitive contents."""
    initialize_audit()

    timestamp = datetime.now(timezone.utc).isoformat()

    with sqlite3.connect(DB_PATH) as connection:
        connection.execute("""
            INSERT INTO audit_log (
                timestamp, filename, file_hash, findings,
                risk, action, destination, status
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            timestamp, filename, file_hash, findings,
            risk, action, destination, status
        ))
