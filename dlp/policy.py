
from enum import Enum
from typing import Optional

class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Action(str, Enum):
    ALLOW = "ALLOW"
    FLAG = "FLAG"
    QUARANTINE = "QUARANTINE"
    BLOCK = "BLOCK"


RISK_BY_CATEGORY = {
    "email": RiskLevel.MEDIUM,
    "phone": RiskLevel.MEDIUM,
    "pan": RiskLevel.HIGH,
    "aadhaar_like": RiskLevel.HIGH,
    "payment_card_like": RiskLevel.CRITICAL,
    "password": RiskLevel.CRITICAL,
    "api_key_like": RiskLevel.CRITICAL,
}


DEFAULT_POLICIES = {
    RiskLevel.LOW: Action.ALLOW,
    RiskLevel.MEDIUM: Action.FLAG,
    RiskLevel.HIGH: Action.QUARANTINE,
    RiskLevel.CRITICAL: Action.BLOCK,
}


def assess_risk(findings: dict[str, int]) -> RiskLevel:
    """Return the highest risk level among detected categories."""
    if not findings:
        return RiskLevel.LOW

    return max(
        (RISK_BY_CATEGORY.get(category, RiskLevel.HIGH)
         for category in findings),
        key=lambda risk: list(RiskLevel).index(risk),
    )
def choose_action(
    risk: RiskLevel,
    policies: Optional[dict[RiskLevel, Action]] = None,
) -> Action:
    """Choose the policy action for a given risk level."""
    active_policies = policies if policies is not None else DEFAULT_POLICIES
    return active_policies[risk]
