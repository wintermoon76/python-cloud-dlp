
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
