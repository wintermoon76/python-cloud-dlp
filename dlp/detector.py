
import re


def passes_luhn(number: str) -> bool:
    """Check whether a digit string passes the Luhn checksum."""
    digits = [int(char) for char in number if char.isdigit()]

    if not 13 <= len(digits) <= 19:
        return False

    total = 0

    for index, digit in enumerate(reversed(digits)):
        if index % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit

    return total % 10 == 0



def find_payment_cards(text: str) -> list[str]:
    """Find Luhn-valid payment-card candidates without trailing separators."""
    candidates = re.findall(
        r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)",
        text,
    )

    valid_cards = []

    for candidate in candidates:
        normalized = re.sub(r"[ -]", "", candidate)

        if passes_luhn(normalized):
            valid_cards.append(candidate.rstrip(" -"))

    return valid_cards


PATTERNS = {
    "email": re.compile(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
    ),
    "phone": re.compile(
        r"(?<!\d)(?:\+91[\s-]?)?[6-9]\d{9}(?!\d)"
    ),
    "pan": re.compile(
        r"\b[A-Z]{5}[0-9]{4}[A-Z]\b",
        re.IGNORECASE,
    ),
    "aadhaar_like": re.compile(
        r"(?<!\d)(?:\d{4}[\s-]){2}\d{4}(?!\d)|(?<!\d)\d{12}(?!\d)"
    ),
    "password": re.compile(
        r"""(?i)\b(?:password|passwd|pwd)\s*[:=]\s*["']?[^,\s"']{4,}"""
    ),
    "api_key_like": re.compile(
        r"""(?i)\b(?:api[_-]?key|access[_-]?token|secret[_-]?key)\s*[:=]\s*["']?[A-Za-z0-9_\-./+=]{8,}"""
    ),
}


def detect_sensitive_data(text: str) -> dict[str, int]:
    """Return counts of detected sensitive-data categories, not raw values."""
    if not isinstance(text, str):
        raise TypeError("text must be a string")

    findings = {}

    for category, pattern in PATTERNS.items():
        matches = pattern.findall(text)
        if matches:
            findings[category] = len(matches)

    cards = find_payment_cards(text)
    if cards:
        findings["payment_card_like"] = len(cards)

    return findings
