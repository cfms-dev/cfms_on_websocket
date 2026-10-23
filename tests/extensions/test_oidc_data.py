import pytest
from sqlalchemy import delete, inspect, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from include.database.models.auth import UserAuthPolicy
from include.database.models.identity import User
from include.database.session import Base
from include.extensions.data import (
    extension_metadata,
    load_extension_data,
    prepare_extension_tables,
)
from include.extensions.oidc_sso.credentials import bind_oidc_identity
from include.extensions.oidc_sso.models import OIDCBase, UserOidcCredential

pytestmark = pytest.mark.component


@pytest.fixture
def auth_sessions(sqlite_engine_factory):
    engine = sqlite_engine_factory()
    Base.metadata.create_all(engine)
    OIDCBase.metadata.create_all(engine)
    return sessionmaker(bind=engine)


def test_oidc_binding_is_unique_and_follows_account_lifetime(auth_sessions):
    with auth_sessions.begin() as session:
        owner, other = User(username="owner"), User(username="other")
        session.add_all([owner, other])
        session.flush()
        owner_id, other_id = owner.id, other.id
        binding = bind_oidc_identity(
            session, owner, "https://issuer.example", "subject"
        )
        binding_id = binding.id
        assert session.get(UserAuthPolicy, (owner_id, "login")) is None
    with pytest.raises(IntegrityError), auth_sessions.begin() as session:
        bind_oidc_identity(
            session, session.get(User, other_id), "https://issuer.example", "subject"
        )
    with auth_sessions.begin() as session:
        session.execute(delete(User).where(User.id == owner_id))
    with auth_sessions() as session:
        assert session.get(UserOidcCredential, binding_id) is None
        assert session.get(User, other_id) is not None


def test_oidc_schema_is_independent_and_adopts_existing_bindings(auth_sessions):
    assert inspect(UserOidcCredential).registry is not inspect(User).registry
    assert "user_oidc_credentials" not in Base.metadata.tables
    with auth_sessions.begin() as session:
        user = User(username="existing")
        session.add(user)
        session.flush()
        credential = bind_oidc_identity(
            session, user, "https://issuer.example", "subject"
        )
        credential_id = credential.id
    engine = auth_sessions.kw["bind"]
    table = UserOidcCredential.__table__
    with engine.connect() as connection:
        before = connection.execute(select(table)).all()
    declarations = load_extension_data(Base.metadata)
    with engine.begin() as connection:
        prepare_extension_tables(
            connection,
            extension_metadata(Base.metadata, declarations),
            set(declarations),
        )
    with engine.connect() as connection:
        assert connection.execute(select(table)).all() == before
        assert connection.execute(select(table.c.id)).scalar_one() == credential_id
