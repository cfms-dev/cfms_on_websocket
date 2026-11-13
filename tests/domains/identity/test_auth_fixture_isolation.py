from dataclasses import FrozenInstanceError

import orjson
import pytest
from argon2 import PasswordHasher
from sqlalchemy.orm import sessionmaker

from include.config.settings import global_config
from include.database.models.auth import (
    UserAuthPolicy,
    UserPasswordCredential,
    UserTotpCredential,
)
from include.database.models.identity import User
from include.database.session import Base
from include.domains.identity.auth.types import AuthPurpose
from include.domains.identity.commands.auth_policies import replace_auth_policy

pytestmark = pytest.mark.component


def test_prepared_credentials_keep_consumption_and_policy_changes_in_the_owning_database(
    auth_material_factory, sqlite_engine_factory, tmp_path
):
    material = auth_material_factory(
        "Password123!", global_config["security"]["pepper"]
    )
    databases = []
    for name in ("first", "second"):
        engine = sqlite_engine_factory(tmp_path / f"{name}.db")
        Base.metadata.create_all(engine)
        sessions = sessionmaker(bind=engine)
        with sessions.begin() as session:
            user = User(username="owner")
            credential = UserTotpCredential(
                user=user,
                secret=material.totp_secret,
                enabled=True,
                backup_codes=material.backup_hashes,
            )
            session.add_all(
                [
                    UserPasswordCredential(user=user, pass_hash=material.password_hash),
                    credential,
                ]
            )
            session.flush()
            replace_auth_policy(
                session,
                user,
                AuthPurpose.MFA,
                [[{"method": "totp", "credential_ids": [credential.credential_id]}]],
                expected_revision=0,
            )
            user_id = user.id
        databases.append((sessions, user_id))

    sessions, user_id = databases[0]
    with sessions.begin() as session:
        assert session.get(UserTotpCredential, user_id).verify(material.backup_codes[0])
        replace_auth_policy(
            session,
            session.get(User, user_id),
            AuthPurpose.MFA,
            [],
            expected_revision=1,
        )
    for index, (sessions, user_id) in enumerate(databases):
        with sessions() as session:
            credential = session.get(UserTotpCredential, user_id)
            assert len(orjson.loads(credential.backup_codes)) == (
                9 if index == 0 else 10
            )
            policy = session.get(UserAuthPolicy, (user_id, "mfa"))
            assert policy.revision == (2 if index == 0 else 1)
            assert bool(policy.chains) is (index == 1)
            assert credential.verify(material.backup_codes[0]) is (index == 1)
    assert len(orjson.loads(material.backup_hashes)) == 10


def test_prepared_material_retains_default_hash_parameters_and_separates_peppers(
    auth_material_factory,
):
    hasher = PasswordHasher()
    for pepper in ("first-pepper", "second-pepper"):
        material = auth_material_factory("Password123!", pepper)
        assert hasher.verify(material.password_hash, "Password123!")
        assert not hasher.check_needs_rehash(material.password_hash)
        hashes = orjson.loads(material.backup_hashes)
        assert len(hashes) == len(set(material.backup_codes)) == 10
        assert hasher.verify(hashes[0], material.backup_codes[0] + pepper)
        assert all(not hasher.check_needs_rehash(value) for value in hashes)
        with pytest.raises(FrozenInstanceError):
            material.totp_secret = "changed"
