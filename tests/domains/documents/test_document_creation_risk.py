from include.config.validation import DocumentCreationRiskPolicy
from include.domains.documents.creation_risk import (
    CreationRiskLevel,
    CreationRiskSignals,
    assess_creation_risk,
)


def _assess(**overrides):
    values = {
        "new_account": False,
        "pending_ratio": 0.0,
        "ip_account_count": 1,
        "denial_count": 0,
    }
    values.update(overrides)
    return assess_creation_risk(
        CreationRiskSignals(**values), DocumentCreationRiskPolicy()
    )


def test_no_signals_are_normal_risk():
    assert _assess().level == CreationRiskLevel.NORMAL


def test_one_elevated_signal_is_elevated_risk():
    assessment = _assess(new_account=True)

    assert assessment.level == CreationRiskLevel.ELEVATED
    assert assessment.reasons == ("new_account",)


def test_two_elevated_signals_become_high_risk():
    assessment = _assess(new_account=True, pending_ratio=0.5)

    assert assessment.level == CreationRiskLevel.HIGH
    assert assessment.reasons == ("new_account", "pending_documents")


def test_each_high_threshold_becomes_high_risk():
    for signals in (
        {"pending_ratio": 0.75},
        {"ip_account_count": 10},
        {"denial_count": 3},
    ):
        assert _assess(**signals).level == CreationRiskLevel.HIGH
