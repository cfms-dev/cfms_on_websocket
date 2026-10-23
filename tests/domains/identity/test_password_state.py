from pathlib import Path

import pytest
from argon2 import PasswordHasher
from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

pytestmark = pytest.mark.component

PROJECT_ROOT = Path(__file__).resolve().parents[3]


def test_set_password_participates_in_the_caller_transaction(
    sqlite_engine_factory,
) -> None:
    import include.database.models  # noqa: F401
    from include.database.models.auth import UserPasswordCredential
    from include.database.models.identity import User
    from include.database.session import Base
    from include.domains.identity.commands.credentials import set_password

    engine = sqlite_engine_factory(":memory:")
    Base.metadata.create_all(engine)
    local_session = sessionmaker(bind=engine)
    hasher = PasswordHasher()

    with local_session() as session:
        user = User(
            username="transaction-user",
            created_time=0,
            last_login=0,
        )
        credential = UserPasswordCredential(
            user=user, pass_hash=hasher.hash("OldPassword123!")
        )
        session.add(credential)
        session.commit()
        original_hash = credential.pass_hash
        original_secret = user.secret_key

        set_password(session, user, "NewPassword456!")

        assert credential.pass_hash != original_hash
        assert user.secret_key != original_secret
        session.rollback()

    with local_session() as session:
        stored = session.scalar(select(User).where(User.username == "transaction-user"))
        assert stored is not None
        credential = session.get(UserPasswordCredential, stored.id)
        assert credential.pass_hash == original_hash
        assert stored.secret_key == original_secret
        assert credential.verify("OldPassword123!") is True
        assert credential.verify("NewPassword456!") is False
