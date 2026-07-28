from dataclasses import dataclass
from enum import StrEnum

from include.config.validation import DocumentDownloadRiskPolicy


class DownloadRiskLevel(StrEnum):
    NORMAL = "normal"
    ELEVATED = "elevated"
    HIGH = "high"


@dataclass(frozen=True, slots=True)
class DownloadRiskSignals:
    new_account: bool
    ip_account_count: int
    denial_count: int


@dataclass(frozen=True, slots=True)
class DownloadRiskAssessment:
    level: DownloadRiskLevel
    reasons: tuple[str, ...]


def assess_download_risk(
    signals: DownloadRiskSignals, policy: DocumentDownloadRiskPolicy
) -> DownloadRiskAssessment:
    reasons = []
    if signals.new_account:
        reasons.append("new_account")
    if signals.ip_account_count >= policy.ip_accounts_elevated:
        reasons.append("ip_account_fanout")
    if signals.denial_count >= policy.denials_elevated:
        reasons.append("recent_denials")

    high_risk = (
        signals.ip_account_count >= policy.ip_accounts_high
        or signals.denial_count >= policy.denials_high
        or len(reasons) >= 2
    )
    if high_risk:
        level = DownloadRiskLevel.HIGH
    elif reasons:
        level = DownloadRiskLevel.ELEVATED
    else:
        level = DownloadRiskLevel.NORMAL
    return DownloadRiskAssessment(level, tuple(reasons))
