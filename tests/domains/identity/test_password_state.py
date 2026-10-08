from pathlib import Path

import pytest
from argon2 import PasswordHasher
from sqlalchemy.orm import sessionmaker

pytestmark = pytest.mark.component

PROJECT_ROOT = Path(__file__).resolve().parents[3]


def test_set_password_participates_in_the_caller_transaction(
    sqlite_engine_factory,
) -> None:
    import include.database.models  # noqa: F401
    from include.database.models.identity import User
    from include.database.session import Base

    engine = sqlite_engine_factory(":memory:")
    Base.metadata.create_all(engine)
    local_session = sessionmaker(bind=engine)
    hasher = PasswordHasher()

    with local_session() as session:
        user = User(
            username="transaction-user",
            pass_hash=hasher.hash("OldPassword123!"),
            created_time=0,
            last_login=0,
        )
        session.add(user)
        session.commit()
        original_hash = user.pass_hash
        original_secret = user.secret_key

        user.set_password("NewPassword456!")

        assert user.pass_hash != original_hash
        assert user.secret_key != original_secret
        session.rollback()

    with local_session() as session:
        stored = session.get(User, "transaction-user")
        assert stored is not None
        assert stored.pass_hash == original_hash
        assert stored.secret_key == original_secret
        assert stored.verify_password("OldPassword123!") is True
        assert stored.verify_password("NewPassword456!") is False
