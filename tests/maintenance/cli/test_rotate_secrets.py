import sqlite3

import pytest

from .support import _make_src_dir, _read_user_state, _run_maintain, _seed_users

pytestmark = pytest.mark.integration


@pytest.mark.parametrize(
    ("args", "input_text", "expected_code", "rotated"),
    [
        (["--yes"], None, 0, True),
        ([], "y\n", 0, True),
        ([], "n\n", 1, False),
    ],
)
def test_rotate_secrets_confirmation_and_persisted_state(
    tmp_path, args, input_text, expected_code, rotated
):
    src_dir = _make_src_dir(tmp_path)
    _seed_users(src_dir)
    (src_dir / "init").touch()
    with sqlite3.connect(src_dir / "app.db") as connection:
        connection.execute("UPDATE users SET secret_key = NULL WHERE username = 'bob'")
        original_secrets = dict(
            connection.execute("SELECT username, secret_key FROM users").fetchall()
        )
    original_state = _read_user_state(src_dir, "OldPass123!")
    original_config = (src_dir / "config.toml").read_bytes()

    result = _run_maintain(
        src_dir,
        ["user", "rotate-secrets", *args],
        check=False,
        input_text=input_text,
    )

    assert result.returncode == expected_code, result.stdout + result.stderr
    with sqlite3.connect(src_dir / "app.db") as connection:
        current_secrets = dict(
            connection.execute("SELECT username, secret_key FROM users").fetchall()
        )
    assert current_secrets.keys() == original_secrets.keys()
    if rotated:
        assert len(set(current_secrets.values())) == len(current_secrets)
        for name, secret in current_secrets.items():
            assert secret != original_secrets[name]
            assert len(bytes.fromhex(secret)) == 32
            assert secret not in result.stdout + result.stderr
    else:
        assert current_secrets == original_secrets
    assert _read_user_state(src_dir, "OldPass123!") == original_state
    assert (src_dir / "config.toml").read_bytes() == original_config
