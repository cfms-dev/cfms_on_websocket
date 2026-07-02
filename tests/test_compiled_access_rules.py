import time

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker


def _legacy_access_rules_allow(access_rules, user, access_type: str) -> bool:
    from include.domains.access.authorization.access_rules import (
        legacy_rule_data_matches_user,
    )

    relevant_access_types = {
        "read": ("read",),
        "write": ("read", "write"),
        "move": ("move",),
        "manage": ("read", "manage"),
    }[access_type]

    relevant_rules = [
        rule for rule in access_rules if rule.access_type in relevant_access_types
    ]
    if not relevant_rules:
        return True

    return all(
        legacy_rule_data_matches_user(rule.rule_data, user)
        for rule in relevant_rules
        if rule.rule_data
    )


@pytest.fixture()
def access_rule_session(protected_test_config, monkeypatch):
    monkeypatch.chdir(protected_test_config.src_dir)

    import include.database.models as models
    from include.database.session import Base

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine)
    with SessionLocal() as session:
        yield models, session


def test_compiled_access_rules_match_legacy_json_evaluator(access_rule_session):
    models, session = access_rule_session
    from include.domains.access.authorization.access_rules import set_access_rules
    from include.domains.access.authorization.compiled_rules import (
        compiled_rules_allow,
        find_compiled_access_rule_mismatches,
        rebuild_all_compiled_access_rules,
    )

    now = time.time()
    user = models.User(
        username="alice",
        pass_hash="hash",
        passwd_last_modified=now,
        nickname="Alice",
        avatar_id=None,
        last_login=None,
        created_time=now,
        status=0,
        secret_key="alice-secret",
        totp_secret=None,
        totp_enabled=False,
        totp_backup_codes=None,
        preference_dek_id=None,
    )
    user.rights.append(
        models.UserPermission(
            username="alice",
            permission="list_users",
            granted=True,
            start_time=0.0,
            end_time=None,
        )
    )
    group = models.UserGroup(group_name="staff", group_display_name="Staff")
    user.groups.append(
        models.UserMembership(
            username="alice",
            group_name="staff",
            start_time=0.0,
            end_time=None,
        )
    )
    document = models.Document(id="doc-1", title="Document", inherit=False)
    session.add_all([user, group, document])
    session.flush()

    set_access_rules(
        document,
        {
            "read": [
                {
                    "match": "any",
                    "match_groups": [
                        {
                            "match": "any",
                            "rights": {
                                "match": "any",
                                "require": ["debugging", "list_users"],
                            },
                            "groups": {
                                "match": "all",
                                "require": ["missing_group"],
                            },
                        }
                    ],
                }
            ],
            "write": [
                {
                    "match": "all",
                    "match_groups": [
                        {"groups": {"match": "all", "require": ["sysop"]}}
                    ],
                }
            ],
            "move": [
                {
                    "match": "all",
                    "match_groups": [
                        {"groups": {"match": "all", "require": ["staff"]}}
                    ],
                }
            ],
            "manage": [
                {
                    "match": "all",
                    "match_groups": [
                        {"rights": {"match": "all", "require": ["list_users"]}}
                    ],
                }
            ],
        },
        inherit_parent=False,
    )
    session.flush()
    rebuild_all_compiled_access_rules(session)

    assert find_compiled_access_rule_mismatches(session) == []

    target_type = "document"
    expected = {
        "read": True,
        "write": False,
        "move": True,
        "manage": True,
    }
    for access_type, allowed in expected.items():
        assert (
            _legacy_access_rules_allow(document.access_rules, user, access_type)
            is allowed
        )
        assert (
            compiled_rules_allow(
                session,
                target_type=target_type,
                target_id=document.id,
                user=user,
                access_type=access_type,
            )
            is allowed
        )
        assert (
            document.check_access_requirements(
                user, access_type, _no_recursive_check=True
            )
            is allowed
        )


def test_compiled_access_rule_mismatch_detector_reports_stale_rows(
    access_rule_session,
):
    models, session = access_rule_session
    from include.domains.access.authorization.access_rules import set_access_rules
    from include.domains.access.authorization.compiled_rules import (
        find_compiled_access_rule_mismatches,
        rebuild_all_compiled_access_rules,
    )

    folder = models.Folder(id="folder-1", name="Folder", inherit=False)
    session.add(folder)
    session.flush()
    set_access_rules(
        folder,
        {
            "read": [
                {
                    "match": "all",
                    "match_groups": [
                        {"groups": {"match": "all", "require": ["sysop"]}}
                    ],
                }
            ]
        },
        inherit_parent=False,
    )
    session.flush()
    rebuild_all_compiled_access_rules(session)

    assert find_compiled_access_rule_mismatches(session) == []

    session.query(models.CompiledAccessRule).delete()
    session.flush()

    assert find_compiled_access_rule_mismatches(session) == [("directory", folder.id)]
