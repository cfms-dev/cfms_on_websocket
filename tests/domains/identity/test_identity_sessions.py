from pathlib import Path
from shutil import copyfile
from types import SimpleNamespace

PROJECT_ROOT = Path(__file__).resolve().parents[3]


def _prepare_config(monkeypatch, tmp_path):
    copyfile(PROJECT_ROOT / "src" / "config.toml.sample", tmp_path / "config.toml")
    monkeypatch.chdir(tmp_path)


def test_issue_login_token_only_renews_token(monkeypatch, tmp_path):
    _prepare_config(monkeypatch, tmp_path)
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
