
import sqlite3

import dlp.audit as audit


def test_record_event_stores_audit_metadata(tmp_path, monkeypatch):
    test_db = tmp_path / "audit.db"
    monkeypatch.setattr(audit, "DB_PATH", test_db)

    audit.record_event(
        filename="sample.txt",
        file_hash="abc123",
        findings='{"email": 1}',
        risk="MEDIUM",
        action="FLAG",
        destination="quarantine",
        status="FLAGGED",
    )

    with sqlite3.connect(test_db) as connection:
        row = connection.execute(
            """
            SELECT filename, file_hash, findings, risk, action,
                   destination, status
            FROM audit_log
            """
        ).fetchone()

    assert row == (
        "sample.txt",
        "abc123",
        '{"email": 1}',
        "MEDIUM",
        "FLAG",
        "quarantine",
        "FLAGGED",
    )
