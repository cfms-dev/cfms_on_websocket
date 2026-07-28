from include.config.validation import DocumentDownloadRiskPolicy
from include.domains.documents.download_risk import (
    DownloadRiskLevel,
    DownloadRiskSignals,
    assess_download_risk,
)


def _assess(**overrides):
    values = {
        "new_account": False,
        "ip_account_count": 1,
        "denial_count": 0,
        **overrides,
    }
    return assess_download_risk(
        DownloadRiskSignals(**values), DocumentDownloadRiskPolicy()
    )


def test_download_without_signals_is_normal_risk():
    assert _assess().level == DownloadRiskLevel.NORMAL


def test_one_download_signal_is_elevated_risk():
    assessment = _assess(new_account=True)

    assert assessment.level == DownloadRiskLevel.ELEVATED
    assert assessment.reasons == ("new_account",)


def test_two_download_signals_are_high_risk():
    assessment = _assess(new_account=True, denial_count=1)

    assert assessment.level == DownloadRiskLevel.HIGH


def test_download_high_thresholds_select_high_risk():
    assert _assess(ip_account_count=10).level == DownloadRiskLevel.HIGH
    assert _assess(denial_count=3).level == DownloadRiskLevel.HIGH
