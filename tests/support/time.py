import datetime as dt
from functools import partialmethod

import pyotp
import pytest


@pytest.fixture
def totp_time(monkeypatch):
    instant = dt.datetime(2024, 1, 1, tzinfo=dt.UTC)
    monkeypatch.setattr(pyotp.TOTP, "now", partialmethod(pyotp.TOTP.at, instant))
    monkeypatch.setattr(
        pyotp.TOTP, "verify", partialmethod(pyotp.TOTP.verify, for_time=instant)
    )
    return instant
