from pathlib import Path
from types import SimpleNamespace

import pytest

pytestmark = pytest.mark.unit

PROJECT_ROOT = Path(__file__).resolve().parents[3]


def test_issue_login_token_only_renews_token():
    from include.database.models.identity import UserStatus
    from include.domains.identity.sessions import issue_login_token

    token = object()
    user = SimpleNamespace(
        status=UserStatus.ACTIVE,
        last_login=None,
        renew_token=lambda: token,
    )

    assert issue_login_token(user) is token
    assert user.last_login is None
