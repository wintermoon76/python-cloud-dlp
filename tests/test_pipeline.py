
import dlp.pipeline as pipeline
import dlp.audit as audit


def test_clean_text_is_allowed(tmp_path, monkeypatch):
    monkeypatch.setattr(audit, "DB_PATH", tmp_path / "audit.db")

    result = pipeline.scan_text("The weather is pleasant today.")

    assert result["findings"] == {}
    assert result["risk"] == "LOW"
    assert result["action"] == "ALLOW"


def test_email_is_flagged(tmp_path, monkeypatch):
    monkeypatch.setattr(audit, "DB_PATH", tmp_path / "audit.db")

    result = pipeline.scan_text("Contact: riya@example.com")

    assert result["findings"] == {"email": 1}
    assert result["risk"] == "MEDIUM"
    assert result["action"] == "FLAG"


def test_password_is_blocked(tmp_path, monkeypatch):
    monkeypatch.setattr(audit, "DB_PATH", tmp_path / "audit.db")

    result = pipeline.scan_text("password=DemoSecret123")

    assert result["risk"] == "CRITICAL"
    assert result["action"] == "BLOCK"
