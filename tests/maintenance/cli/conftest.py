import pytest

from .support import (
    _create_empty_database,
    _make_src_dir,
    _seed_audit_entries,
    _seed_permission_entries,
    _seed_users,
)


@pytest.fixture(scope="module")
def empty_database_template(tmp_path_factory):
    root = _make_src_dir(tmp_path_factory.mktemp("cli-empty-template"))
    _create_empty_database(root)
    return root


@pytest.fixture(scope="module")
def permission_database_template(tmp_path_factory):
    root = _make_src_dir(tmp_path_factory.mktemp("cli-permission-template"))
    _seed_permission_entries(root)
    return root


@pytest.fixture(scope="module")
def audit_database_templates(tmp_path_factory):
    templates = {}
    for batch_size in (1, 2):
        root = _make_src_dir(
            tmp_path_factory.mktemp(f"cli-audit-template-{batch_size}")
        )
        _seed_audit_entries(root, batch_size=batch_size)
        templates[batch_size] = root
    return templates


@pytest.fixture(scope="module")
def user_database_template(tmp_path_factory):
    root = _make_src_dir(tmp_path_factory.mktemp("cli-user-template"))
    _seed_users(root)
    return root
