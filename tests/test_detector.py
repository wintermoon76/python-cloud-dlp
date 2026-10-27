
from dlp.detector import detect_sensitive_data


def test_detects_one_email():
    result = detect_sensitive_data("Contact: riya@example.com")

    assert result == {"email": 1}


def test_detects_two_emails():
    result = detect_sensitive_data(
        "riya@example.com and dev@example.org"
    )

    assert result == {"email": 2}


def test_returns_empty_dictionary_when_nothing_is_detected():
    result = detect_sensitive_data("The weather is pleasant today.")

    assert result == {}


def test_detects_indian_mobile_number():
    result = detect_sensitive_data("Call 9876543210")

    assert result == {"phone": 1}


def test_does_not_match_phone_inside_long_digit_sequence():
    result = detect_sensitive_data("1234567890123")

    assert result == {}


def test_detects_two_mobile_numbers():
    result = detect_sensitive_data("9876543210 and 8765432109")

    assert result == {"phone": 2}

from dlp.detector import detect_sensitive_data, passes_luhn


def test_detects_pan():
    findings = detect_sensitive_data("PAN: ABCDE1234F")
    assert findings["pan"] == 1


def test_detects_aadhaar_like_identifier():
    findings = detect_sensitive_data("ID: 1234 5678 9012")
    assert findings["aadhaar_like"] == 1


def test_detects_password_assignment():
    findings = detect_sensitive_data("password=SuperSecret123")
    assert findings["password"] == 1


def test_detects_api_key_assignment():
    findings = detect_sensitive_data("api_key=abcd1234efgh5678")
    assert findings["api_key_like"] == 1


def test_rejects_invalid_luhn_number():
    assert passes_luhn("4111111111111112") is False


def test_accepts_valid_luhn_number():
    assert passes_luhn("4111111111111111") is True


def test_detection_returns_counts_not_sensitive_values():
    findings = detect_sensitive_data("Contact alice@example.com")
    assert findings == {"email": 1}
    assert "alice@example.com" not in str(findings)
