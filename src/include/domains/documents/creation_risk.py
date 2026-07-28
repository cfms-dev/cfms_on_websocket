from dataclasses import dataclass
from enum import StrEnum

from include.config.validation import DocumentCreationRiskPolicy


class CreationRiskLevel(StrEnum):
    NORMAL = "normal"
    ELEVATED = "elevated"
    HIGH = "high"


@dataclass(frozen=True, slots=True)
class CreationRiskSignals:
    new_account: bool
    pending_ratio: float
    ip_account_count: int
    denial_count: int


@dataclass(frozen=True, slots=True)
class CreationRiskAssessment:
    level: CreationRiskLevel
    reasons: tuple[str, ...]


def assess_creation_risk(
    signals: CreationRiskSignals, policy: DocumentCreationRiskPolicy
) -> CreationRiskAssessment:
    reasons = []
    if signals.new_account:
        reasons.append("new_account")
    if signals.pending_ratio >= policy.pending_elevated_ratio:
        reasons.append("pending_documents")
    if signals.ip_account_count >= policy.ip_accounts_elevated:
        reasons.append("ip_account_fanout")
    if signals.denial_count >= policy.denials_elevated:
        reasons.append("recent_denials")

    high_risk = (
        signals.pending_ratio >= policy.pending_high_ratio
        or signals.ip_account_count >= policy.ip_accounts_high
        or signals.denial_count >= policy.denials_high
        or len(reasons) >= 2
    )
    if high_risk:
        level = CreationRiskLevel.HIGH
    elif reasons:
        level = CreationRiskLevel.ELEVATED
    else:
        level = CreationRiskLevel.NORMAL
    return CreationRiskAssessment(level, tuple(reasons))
