import shutil

import pytest
from alembic.migration import MigrationContext

from maintenance.operations import deployment
from maintenance.operations.deployment import database, lifecycle, repository
from maintenance.operations.exceptions import MaintenanceOperationError

from .support import PROJECT_ROOT, _prepare_deployment, _write_release

pytestmark = pytest.mark.component


@pytest.mark.parametrize("selector", ["full", "prefix", "uppercase"])
@pytest.mark.parametrize("damage", ["file", "manifest"])
def test_lookup_ignores_unrelated_damaged_snapshot(tmp_path, selector, damage):
    root = tmp_path / "deployment"
    selected = _prepare_deployment(root)
    repository._snapshot_release(root, selected)
    unrelated = _write_release(tmp_path / "unrelated", "0.9.0", "unrelated")
    snapshot = repository._snapshot_release(root, unrelated)
    damaged = snapshot / (
        "src/alembic.ini" if damage == "file" else "release-manifest.json"
    )
    damaged.write_bytes(b"modified snapshot\n")
    cache = snapshot / "src" / "__pycache__" / "marker.pyc"
    cache.parent.mkdir()
    cache.write_bytes(b"preserve unrelated cache")
    release_id = {
        "full": selected.release_id,
        "prefix": selected.release_id[:12],
        "uppercase": selected.release_id.upper(),
    }[selector]

    result = repository._stored_release(root, release_id)

    assert result.release_id == selected.release_id
    assert damaged.read_bytes() == b"modified snapshot\n"
    assert cache.read_bytes() == b"preserve unrelated cache"
    assert snapshot.is_dir()


def test_lookup_missing_id_does_not_validate_unrelated_snapshot(tmp_path):
    root = tmp_path / "deployment"
    release = _prepare_deployment(root)
    snapshot = repository._snapshot_release(root, release)
    (snapshot / "src" / "alembic.ini").write_bytes(b"modified\n")

    with pytest.raises(MaintenanceOperationError, match="not found"):
        repository._stored_release(root, "f" * 64)

    assert snapshot.is_dir()


def test_lookup_detects_prefix_ambiguity_before_validating_candidates(tmp_path):
    root = tmp_path / "deployment"
    _prepare_deployment(root)
    paths = []
    for index in range(2):
        release = _write_release(tmp_path / f"candidate-{index}", "0.9.0", str(index))
        path = repository._snapshot_release(root, release).parent
        renamed = path.with_name("a" * 12 + str(index) * 52)
        path.rename(renamed)
        paths.append(renamed)

    with pytest.raises(MaintenanceOperationError, match="ambiguous"):
        repository._stored_release(root, "a" * 12)

    assert all(path.is_dir() for path in paths)


def test_lookup_preserves_version_root_entry_limit(tmp_path, monkeypatch):
    root = tmp_path / "deployment"
    release = _prepare_deployment(root)
    snapshot = repository._snapshot_release(root, release)
    (snapshot.parent.parent / "operator-note").write_text("note", encoding="utf-8")
    monkeypatch.setattr(repository, "MAX_STORED_RELEASES", 1)

    with pytest.raises(MaintenanceOperationError, match="more than 1"):
        repository._stored_release(root, release.release_id)


@pytest.mark.parametrize("link_target", ["versions", "selected"])
def test_lookup_rejects_linked_release_paths(tmp_path, link_target):
    root = tmp_path / "deployment"
    release = _prepare_deployment(root)
    snapshot = repository._snapshot_release(root, release)
    path = snapshot.parent.parent if link_target == "versions" else snapshot.parent
    external = tmp_path / "external"
    path.rename(external)
    path.symlink_to(external, target_is_directory=True)

    with pytest.raises(MaintenanceOperationError):
        repository._stored_release(root, release.release_id)

    assert external.is_dir()


@pytest.fixture
def recovery_deployment(tmp_path):
    root = tmp_path / "deployment"
    source = _write_release(root, "1.0.0", "source", with_migrations=True)
    shutil.copy2(
        PROJECT_ROOT / "src" / "config.toml.sample", root / "src" / "config.toml"
    )
    with database._suppress_bytecode_writes():
        source_head = database._alembic(source)[2]
    target = _write_release(
        tmp_path / "target",
        "1.1.0",
        "target",
        with_migrations=True,
        migration=("lookup_recovery_head", source_head),
    )
    source_snapshot = repository._snapshot_release(root, source)
    repository._snapshot_state(root, source)
    target_snapshot = repository._snapshot_release(root, target)
    repository._remove_active_release(root, source)
    repository._copy_release_to_active(root, target)
    repository._snapshot_state(root, target)
    return (
        root,
        repository._verified_stored_release(source_snapshot),
        repository._verified_stored_release(target_snapshot),
    )


@pytest.mark.parametrize(
    ("phase", "endpoint"),
    [
        ("activation", "source"),
        ("database-migration", "target"),
        ("database-recovery-required", "target"),
    ],
)
def test_resume_ignores_unrelated_damaged_snapshot(
    recovery_deployment,
    tmp_path,
    monkeypatch,
    phase,
    endpoint,
):
    root, source, target = recovery_deployment
    selected = source if endpoint == "source" else target
    engine = database._database_engine(root)
    try:
        with database._suppress_bytecode_writes(), engine.begin() as connection:
            _, scripts, head = database._alembic(selected)
            MigrationContext.configure(connection).stamp(scripts, head)
    finally:
        engine.dispose()
    unrelated = _write_release(tmp_path / "unrelated", "0.9.0", "unrelated")
    snapshot = repository._snapshot_release(root, unrelated)
    (snapshot / "src" / "alembic.ini").write_bytes(b"modified\n")
    before = {
        path.relative_to(snapshot): path.read_bytes()
        for path in snapshot.rglob("*")
        if path.is_file()
    }
    lifecycle._write_transaction(
        root,
        {
            "action": "upgrade",
            "phase": phase,
            "from_release": source.release_id,
            "to_release": target.release_id,
        },
    )
    monkeypatch.setattr(lifecycle, "_sync_environment", lambda *args: None)

    result = deployment.resume_deployment(root)

    assert result.active_release_id == selected.release_id
    assert repository._active_release(root).release_id == selected.release_id
    assert not lifecycle._transaction_path(root).exists()
    assert {
        path.relative_to(snapshot): path.read_bytes()
        for path in snapshot.rglob("*")
        if path.is_file()
    } == before
    engine = database._database_engine(root)
    try:
        with engine.connect() as connection:
            assert database._current_revision(connection) == head
    finally:
        engine.dispose()


@pytest.mark.parametrize("endpoint", ["source", "target"])
def test_resume_rejects_damaged_transaction_endpoint(recovery_deployment, endpoint):
    root, source, target = recovery_deployment
    selected = source if endpoint == "source" else target
    snapshot = repository._version_root(root, selected.release_id) / "release"
    (snapshot / "src" / "alembic.ini").write_bytes(b"modified\n")
    lifecycle._write_transaction(
        root,
        {
            "action": "upgrade",
            "phase": "activation",
            "from_release": source.release_id,
            "to_release": target.release_id,
        },
    )
    original_transaction = lifecycle._transaction_path(root).read_bytes()
    original_active = (root / "release-manifest.json").read_bytes()

    with pytest.raises(MaintenanceOperationError) as error:
        deployment.resume_deployment(root)

    assert str(snapshot.parent) in str(error.value)
    assert lifecycle._transaction_path(root).read_bytes() == original_transaction
    assert (root / "release-manifest.json").read_bytes() == original_active
    assert (snapshot / "src" / "alembic.ini").read_bytes() == b"modified\n"


def test_downgrade_ignores_unrelated_damaged_snapshot(
    recovery_deployment,
    tmp_path,
    monkeypatch,
):
    root, source, _target = recovery_deployment
    unrelated = _write_release(tmp_path / "unrelated", "0.9.0", "unrelated")
    snapshot = repository._snapshot_release(root, unrelated)
    (snapshot / "src" / "alembic.ini").write_bytes(b"modified\n")
    monkeypatch.setattr(lifecycle, "_preflight_downgrade_database", lambda *args: None)
    monkeypatch.setattr(lifecycle, "_downgrade_database", lambda *args: None)
    monkeypatch.setattr(lifecycle, "_sync_environment", lambda *args: None)

    result = deployment.downgrade_deployment(source.release_id[:12], root)

    assert result.active_release_id == source.release_id
    assert repository._active_release(root).release_id == source.release_id
    assert not lifecycle._transaction_path(root).exists()
    assert (snapshot / "src" / "alembic.ini").read_bytes() == b"modified\n"


@pytest.mark.parametrize("operation", ["status", "prune"])
def test_full_inventory_rejects_damaged_snapshot_without_deleting_versions(
    tmp_path, operation
):
    root = tmp_path / "deployment"
    active = _prepare_deployment(root)
    active_snapshot = repository._snapshot_release(root, active)
    unrelated = _write_release(tmp_path / "unrelated", "0.9.0", "unrelated")
    snapshot = repository._snapshot_release(root, unrelated)
    (snapshot / "src" / "alembic.ini").write_bytes(b"modified\n")

    if operation == "status":
        with pytest.raises(MaintenanceOperationError):
            deployment.inspect_deployment(root)
    else:
        with pytest.raises(MaintenanceOperationError):
            deployment.prune_deployment(
                root, expected_release_ids=(unrelated.release_id,)
            )

    assert active_snapshot.is_dir()
    assert snapshot.is_dir()
    assert (snapshot / "src" / "alembic.ini").read_bytes() == b"modified\n"
