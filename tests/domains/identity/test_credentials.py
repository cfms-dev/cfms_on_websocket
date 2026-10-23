import uuid
from unittest.mock import Mock

import orjson
import pyotp
import pytest
from argon2 import PasswordHasher
from sqlalchemy import JSON, ForeignKey, LargeBinary, String, inspect, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    mapped_column,
    relationship,
    sessionmaker,
)

import include.database.models  # noqa: F401
from include.database.models.auth import (
    UserAuthPublicKey,
    UserPasswordCredential,
    UserTotpCredential,
)
from include.database.models.identity import User, UserGroup
from include.database.session import Base
from include.domains.identity import password_auth
from include.domains.identity.auth import auth_registry
from include.domains.identity.commands import users as user_commands
from include.domains.identity.commands.credentials import set_password, setup_totp

pytestmark = pytest.mark.component


@pytest.fixture
def credential_sessions(sqlite_engine_factory):
    engine = sqlite_engine_factory()
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)


@pytest.mark.parametrize("password", [None, "Password123!"])
@pytest.mark.filterwarnings("error::sqlalchemy.exc.SAWarning")
def test_create_user_persists_credentials_and_account_relations(
    credential_sessions, monkeypatch, password
):
    monkeypatch.setattr(user_commands, "Session", credential_sessions)
    with credential_sessions.begin() as session:
        session.add(UserGroup(group_name="operators"))

    user_commands.create_user(
        username="created",
        password=password,
        permissions=[{"permission": "set_passwd"}],
        groups=[{"group_name": "operators"}],
    )

    with credential_sessions() as session:
        user = session.scalar(select(User).where(User.username == "created"))
        assert [entry.permission for entry in user.rights] == ["set_passwd"]
        assert [entry.group_name for entry in user.groups] == ["operators"]
        credential = session.get(UserPasswordCredential, user.id)
        if password is None:
            assert credential is None
        else:
            assert credential.verify(password)
        assert session.get(UserTotpCredential, user.id) is None


def test_sparse_credentials_and_provider_queries_are_isolated(credential_sessions):
    with credential_sessions.begin() as session:
        empty, password, mfa, keys = [
            User(username=name) for name in ("empty", "password", "mfa", "keys")
        ]
        session.add_all([empty, password, mfa, keys])
        session.flush()
        set_password(session, password, "Password123!")
        set_password(session, mfa, "Password456!")
        session.add_all(
            [
                UserTotpCredential(
                    user=mfa, secret=pyotp.random_base32(), enabled=True
                ),
                UserTotpCredential(
                    user=password, secret=pyotp.random_base32(), enabled=False
                ),
                *[
                    UserAuthPublicKey(
                        user=keys, public_key_der=b"key", fingerprint=bytes([i]) * 32
                    )
                    for i in (1, 2)
                ],
            ]
        )
        session.flush()

        assert auth_registry.get_user_configured_methods(session, empty) == {
            "primary": [],
            "secondary": [],
        }
        assert auth_registry.get_user_configured_methods(session, password) == {
            "primary": ["password"],
            "secondary": [],
        }
        assert auth_registry.get_user_configured_methods(session, mfa) == {
            "primary": ["password"],
            "secondary": ["totp"],
        }
        assert auth_registry.get_user_configured_methods(session, keys) == {
            "primary": ["publickey"],
            "secondary": [],
        }
        assert session.get(UserPasswordCredential, empty.id) is None
        assert session.get(UserTotpCredential, keys.id) is None
        assert len(session.scalars(select(UserAuthPublicKey)).all()) == 2
        assert (
            auth_registry.get("password")
            .verify(session, password, {"password": "Password123!"}, {})
            .success
        )
        totp = session.get(UserTotpCredential, mfa.id)
        assert (
            auth_registry.get("totp")
            .verify(session, mfa, {"token": pyotp.TOTP(totp.secret).now()}, {})
            .success
        )
        assert (
            not auth_registry.get("password")
            .verify(session, password, {"password": "Password456!"}, {})
            .success
        )
        assert (
            not auth_registry.get("totp")
            .verify(session, password, {"token": "000000"}, {})
            .success
        )


@pytest.mark.parametrize("model", [UserPasswordCredential, UserTotpCredential])
def test_singleton_credentials_are_enforced_by_the_database(credential_sessions, model):
    with credential_sessions.begin() as session:
        user = User(username="single")
        session.add(user)
        session.flush()
        user_id = user.id
        data = (
            {"pass_hash": "hash"}
            if model is UserPasswordCredential
            else {"secret": "secret"}
        )
        session.add(model(user_id=user_id, **data))

    with credential_sessions() as session:
        session.add(model(user_id=user_id, **data))
        with pytest.raises(IntegrityError):
            session.commit()


def test_credential_deletion_and_user_deletion_have_distinct_lifetimes(
    credential_sessions,
):
    with credential_sessions.begin() as session:
        user = User(username="owner")
        session.add(user)
        session.flush()
        user_id = user.id
        set_password(session, user, "Password123!")
        session.add_all(
            [
                UserTotpCredential(user=user, secret="secret", enabled=True),
                UserAuthPublicKey(
                    user=user, public_key_der=b"key", fingerprint=b"f" * 32
                ),
            ]
        )

    with credential_sessions.begin() as session:
        session.delete(session.get(UserTotpCredential, user_id))

    with credential_sessions.begin() as session:
        assert session.get(UserTotpCredential, user_id) is None
        assert session.get(UserPasswordCredential, user_id) is not None
        assert session.scalar(select(UserAuthPublicKey)) is not None
        session.add(
            UserTotpCredential(user_id=user_id, secret="replacement", enabled=True)
        )
        session.flush()
        session.delete(session.get(User, user_id))

    with credential_sessions() as session:
        assert session.get(User, user_id) is None
        assert session.get(UserPasswordCredential, user_id) is None
        assert session.get(UserTotpCredential, user_id) is None
        assert session.scalar(select(UserAuthPublicKey)) is None


def test_totp_setup_and_backup_code_consumption_follow_the_caller_transaction(
    credential_sessions,
):
    with credential_sessions.begin() as session:
        user = User(username="totp")
        session.add(user)
        session.flush()
        user_id = user.id
        credential, codes = setup_totp(session, user)
        first_code, second_code = codes[:2]
        assert not credential.enabled
        assert credential.provisioning_uri == pyotp.TOTP(
            credential.secret
        ).provisioning_uri(name="totp", issuer_name="CFMS")
        assert first_code not in credential.backup_codes
        assert credential.verify(pyotp.TOTP(credential.secret).now())
        credential.enable()

    with credential_sessions() as session:
        credential = session.get(UserTotpCredential, user_id)
        assert credential.verify(first_code)
        assert len(orjson.loads(credential.backup_codes)) == 9
        session.rollback()

    with credential_sessions.begin() as session:
        credential = session.get(UserTotpCredential, user_id)
        assert len(orjson.loads(credential.backup_codes)) == 10
        assert credential.verify(first_code)

    with credential_sessions.begin() as session:
        credential = session.get(UserTotpCredential, user_id)
        assert not credential.verify(first_code)
        assert credential.verify(second_code)
        original_secret = credential.secret

    with credential_sessions() as session:
        credential, _ = setup_totp(session, session.get(User, user_id))
        assert credential.secret != original_secret
        assert not credential.enabled
        session.rollback()

    with credential_sessions() as session:
        credential = session.get(UserTotpCredential, user_id)
        assert credential.secret == original_secret
        assert credential.enabled
        assert len(orjson.loads(credential.backup_codes)) == 8


def test_creating_password_and_rotating_token_key_roll_back_together(
    credential_sessions,
):
    with credential_sessions.begin() as session:
        user = User(username="passwordless")
        session.add(user)
        session.flush()
        user_id, secret = user.id, user.secret_key

    with credential_sessions() as session:
        user = session.get(User, user_id)
        set_password(session, user, "Password123!", force_update_after_login=True)
        assert user.secret_key != secret
        credential = session.get(UserPasswordCredential, user_id)
        assert credential.verify("Password123!")
        assert credential.passwd_last_modified == 0
        session.rollback()

    with credential_sessions() as session:
        assert session.get(UserPasswordCredential, user_id) is None
        assert session.get(User, user_id).secret_key == secret


@pytest.mark.parametrize("modified", [0.0, 123.0])
def test_rehash_preserves_password_age_and_forced_update_marker(modified):
    credential = UserPasswordCredential(
        pass_hash=PasswordHasher(time_cost=1).hash("Password123!"),
        passwd_last_modified=modified,
    )
    original_hash = credential.pass_hash
    credential.rehash_if_needed("Password123!")
    assert credential.pass_hash != original_hash
    assert credential.verify("Password123!")
    assert not credential.check_needs_rehash()
    assert credential.passwd_last_modified == modified


def test_missing_password_credential_performs_dummy_verification(monkeypatch):
    hasher = Mock(wraps=PasswordHasher())
    monkeypatch.setattr(password_auth, "_password_hasher", hasher)
    assert not password_auth.verify_password_or_dummy(None, "Password123!")
    hasher.verify.assert_called_once_with(
        password_auth._dummy_password_hash, "Password123!"
    )


def test_unrelated_credential_model_can_own_multiple_tables_without_user_changes(
    credential_sessions,
):
    class ExtensionBase(DeclarativeBase):
        pass

    class DeviceCredential(ExtensionBase):
        __tablename__ = "test_device_credentials"

        id: Mapped[int] = mapped_column(primary_key=True)
        user_id: Mapped[uuid.UUID] = mapped_column(
            ForeignKey(User.id, ondelete="CASCADE")
        )
        public_material: Mapped[bytes] = mapped_column(LargeBinary)
        user: Mapped[User] = relationship(User)

    class DeviceOptions(ExtensionBase):
        __tablename__ = "test_device_options"

        credential_id: Mapped[int] = mapped_column(
            ForeignKey(DeviceCredential.id, ondelete="CASCADE"), primary_key=True
        )
        kind: Mapped[str] = mapped_column(String(32))
        parameters: Mapped[dict] = mapped_column(JSON)

    with credential_sessions() as session:
        ExtensionBase.metadata.create_all(session.get_bind())
    user_attributes = set(inspect(User).attrs.keys())
    try:
        with credential_sessions.begin() as session:
            device = DeviceCredential(
                user=User(username="device-user"), public_material=b"binary-key"
            )
            session.add(device)
            session.flush()
            device_id, user_id = device.id, device.user_id
            session.add(
                DeviceOptions(
                    credential_id=device_id,
                    kind="device",
                    parameters={"transports": ["usb", "nfc"], "counter": 7},
                )
            )

        with credential_sessions.begin() as session:
            device = session.get(DeviceCredential, device_id)
            assert device.user.username == "device-user"
            assert device.public_material == b"binary-key"
            assert session.get(DeviceOptions, device_id).parameters == {
                "transports": ["usb", "nfc"],
                "counter": 7,
            }
            session.delete(session.get(User, user_id))

        with credential_sessions() as session:
            assert session.get(DeviceCredential, device_id) is None
            assert session.get(DeviceOptions, device_id) is None
        assert set(inspect(User).attrs.keys()) == user_attributes
        assert (
            not {"password_credential", "totp_credential", "auth_public_keys"}
            & user_attributes
        )
    finally:
        ExtensionBase.registry.dispose()
