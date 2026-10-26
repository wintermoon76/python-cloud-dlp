
from dlp.policy import (
    Action,
    RiskLevel,
    assess_risk,
    choose_action,
)


def test_no_findings_means_low_risk():
    assert assess_risk({}) == RiskLevel.LOW


def test_email_means_medium_risk():
    assert assess_risk({"email": 1}) == RiskLevel.MEDIUM


def test_sensitive_identifier_means_high_risk():
    assert assess_risk({"pan": 1}) == RiskLevel.HIGH


def test_password_means_critical_risk():
    assert assess_risk({"password": 1}) == RiskLevel.CRITICAL


def test_highest_risk_wins():
    assert assess_risk({
        "email": 1,
        "password": 1,
    }) == RiskLevel.CRITICAL


def test_critical_risk_is_blocked():
    assert choose_action(RiskLevel.CRITICAL) == Action.BLOCK
