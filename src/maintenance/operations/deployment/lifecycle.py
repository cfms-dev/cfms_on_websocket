import json
import platform
import shutil
from pathlib import Path
from typing import Any

from packaging.specifiers import SpecifierSet
from packaging.version import Version

from include.runtime_lock import RuntimeLockError, server_runtime_lock
from maintenance.operations.config import sync_config_template
from maintenance.operations.deployment.artifacts import _stage_release
from maintenance.operations.deployment.constants import _SHA256_PATTERN
from maintenance.operations.deployment.database import (
    _alembic,
    _current_revision,
    _database_engine,
    _downgrade_database,
    _preflight_downgrade_database,
    _preflight_upgrade_database,
    _suppress_bytecode_writes,
    _upgrade_database,
)
from maintenance.operations.deployment.environment import _sync_environment
from maintenance.operations.deployment.models import (
    DeploymentPruneResult,
    DeploymentResult,
    DeploymentSettings,
    DeploymentVersion,
    _Release,
)
from maintenance.operations.deployment.repository import (
    _active_release,
    _archive_active,
    _atomic_write,
    _copy_release_to_active,
    _copy_state_extensions,
    _discover,
    _hash_file,
    _load_settings,
    _maintenance_root,
    _project_root,
    _release_from_tree,
    _remove_active_release,
    _snapshot_release,
    _snapshot_state,
    _stored_release,
    _stored_releases,
    _verified_stored_release,
    _version_root,
    _write_settings,
)
from maintenance.operations.exceptions import MaintenanceOperationError


def _transaction_path(project_root: Path) -> Path:
    return _maintenance_root(project_root) / "transaction.json"


def _write_transaction(project_root: Path, data: dict[str, Any]) -> None:
    _atomic_write(
        _transaction_path(project_root),
        (json.dumps(data, indent=2, sort_keys=True) + "\n").encode(),
    )


def _load_transaction(project_root: Path) -> dict[str, Any]:
    path = _transaction_path(project_root)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise MaintenanceOperationError(f"Unable to read {path}: {exc}") from exc
    if data.get("action") not in {"upgrade", "downgrade"}:
        raise MaintenanceOperationError(f"Invalid deployment transaction: {path}")
    return data


def _restore_active(
    project_root: Path,
    source: _Release,
    failed_release: _Release | None = None,
) -> None:
    try:
        current = _active_release(project_root)
    except MaintenanceOperationError:
        current = None
    if current is not None and current.release_id == source.release_id:
        return
    if current is not None and current.release_id != source.release_id:
        _remove_active_release(project_root, current)
    elif current is None and failed_release is not None:
        for relative_path, expected_digest in failed_release.manifest["files"].items():
            path = project_root / Path(relative_path)
            if path.is_file() and _hash_file(path) == expected_digest:
                path.unlink()
        (project_root / "release-manifest.json").unlink(missing_ok=True)
        for path in sorted(project_root.rglob("*"), reverse=True):
            if path.is_dir() and path != _maintenance_root(project_root):
                try:
                    path.rmdir()
                except OSError:
                    pass
    if not (project_root / "release-manifest.json").exists():
        _copy_release_to_active(project_root, source)
    state = _version_root(project_root, source.release_id) / "state"
    _atomic_write(
        project_root / "src" / "config.toml",
        (state / "config.toml").read_bytes(),
    )
    _copy_state_extensions(project_root, source)


def _activate_upgrade(
    project_root: Path,
    source: _Release,
    target: _Release,
    settings: DeploymentSettings,
) -> None:
    _archive_active(project_root, source)
    _copy_release_to_active(project_root, target)
    _copy_state_extensions(project_root, source)
    sync_config_template(
        project_root / "src" / "config.toml.sample",
        write=True,
    )
    _snapshot_state(project_root, target)
    _sync_environment(project_root, settings)


def upgrade_deployment(
    package: str | Path,
    deployment_root: str | Path,
    *,
    expected_sha256: str | None = None,
    checksums_path: str | Path | None = None,
    extras: tuple[str, ...] | None = None,
    requirements_lock: str | Path | None = None,
) -> DeploymentResult:
    project_root = _project_root(deployment_root)
    transaction_path = _transaction_path(project_root)
    if transaction_path.exists():
        raise MaintenanceOperationError(
            f"Resume the unfinished deployment transaction first: {transaction_path}"
        )
    source = _active_release(project_root)
    try:
        lock = server_runtime_lock(project_root / "src").acquire()
    except RuntimeLockError as exc:
        raise MaintenanceOperationError(str(exc)) from exc
    stage = None
    database_started = False
    try:
        staged, package_digest, stage = _stage_release(
            package,
            project_root,
            expected_sha256=expected_sha256,
            checksums_path=checksums_path,
        )
        if staged.release_id == source.release_id:
            raise MaintenanceOperationError("The supplied release is already active")
        if Version(staged.version) < Version(source.version):
            raise MaintenanceOperationError(
                "Use deployment downgrade to activate an older stored release"
            )
        requires_python = SpecifierSet(staged.manifest["requires_python"])
        current_python = Version(platform.python_version())
        if current_python not in requires_python:
            raise MaintenanceOperationError(
                f"Target release requires Python {requires_python}; "
                f"the maintenance process uses {current_python}"
            )
        _preflight_upgrade_database(project_root, source, staged)

        settings = _load_settings(project_root)
        if extras is not None:
            settings = DeploymentSettings(1, tuple(sorted(set(extras))))
        maintenance_root = _maintenance_root(project_root)
        maintenance_root.mkdir(parents=True, exist_ok=True)
        if requirements_lock is not None:
            shutil.copy2(
                Path(requirements_lock).expanduser().resolve(),
                maintenance_root / "requirements.lock",
            )
        elif not (maintenance_root / "requirements.lock").exists():
            (maintenance_root / "requirements.lock").write_text("", encoding="utf-8")
        _write_settings(project_root, settings)

        snapshot = _snapshot_release(project_root, staged)
        target = _release_from_tree(snapshot, exact=True)
        source_snapshot = _snapshot_release(project_root, source)
        source = _verified_stored_release(source_snapshot)
        _snapshot_state(project_root, source)
        _write_transaction(
            project_root,
            {
                "action": "upgrade",
                "from_release": source.release_id,
                "phase": "activation",
                "to_release": target.release_id,
            },
        )
        try:
            _activate_upgrade(project_root, source, target, settings)
        except Exception:
            _restore_active(project_root, source, target)
            _sync_environment(project_root, settings)
            transaction_path.unlink(missing_ok=True)
            raise
        _write_transaction(
            project_root,
            {
                "action": "upgrade",
                "from_release": source.release_id,
                "phase": "database-migration",
                "to_release": target.release_id,
            },
        )
        database_started = True
        _upgrade_database(project_root, source, target)
        _release_from_tree(project_root, exact=False)
        _discover(project_root)
        transaction_path.unlink()
        shutil.rmtree(stage, ignore_errors=True)
        return DeploymentResult(
            "upgrade",
            project_root,
            target.version,
            target.release_id,
            package_sha256=package_digest,
        )
    except Exception:
        if database_started and transaction_path.exists():
            data = _load_transaction(project_root)
            data["phase"] = "database-recovery-required"
            _write_transaction(project_root, data)
        elif stage is not None:
            shutil.rmtree(stage, ignore_errors=True)
        raise
    finally:
        lock.release()


def downgrade_deployment(
    release_id: str,
    deployment_root: str | Path,
) -> DeploymentResult:
    project_root = _project_root(deployment_root)
    if _transaction_path(project_root).exists():
        raise MaintenanceOperationError("Resume the unfinished transaction first")
    source = _active_release(project_root)
    try:
        lock = server_runtime_lock(project_root / "src").acquire()
    except RuntimeLockError as exc:
        raise MaintenanceOperationError(str(exc)) from exc
    database_started = False
    try:
        target = _stored_release(project_root, release_id)
        if target.release_id == source.release_id:
            raise MaintenanceOperationError("The selected release is already active")
        target_state = _version_root(project_root, target.release_id) / "state"
        if not (target_state / "config.toml").is_file():
            raise MaintenanceOperationError(
                f"Stored release has no compatible configuration snapshot: {target.release_id}"
            )
        _preflight_downgrade_database(project_root, source, target)
        _snapshot_release(project_root, source)
        _snapshot_state(project_root, source)
        _write_transaction(
            project_root,
            {
                "action": "downgrade",
                "from_release": source.release_id,
                "phase": "database-migration",
                "to_release": target.release_id,
            },
        )
        database_started = True
        _downgrade_database(project_root, source, target)
        _write_transaction(
            project_root,
            {
                "action": "downgrade",
                "from_release": source.release_id,
                "phase": "activation",
                "to_release": target.release_id,
            },
        )
        _archive_active(project_root, source)
        _copy_release_to_active(project_root, target)
        _atomic_write(
            project_root / "src" / "config.toml",
            (target_state / "config.toml").read_bytes(),
        )
        _copy_state_extensions(project_root, target)
        _sync_environment(project_root, _load_settings(project_root))
        _release_from_tree(project_root, exact=False)
        _discover(project_root)
        _transaction_path(project_root).unlink()
        return DeploymentResult(
            "downgrade", project_root, target.version, target.release_id
        )
    except Exception:
        if database_started and _transaction_path(project_root).exists():
            data = _load_transaction(project_root)
            data["phase"] = "database-recovery-required"
            _write_transaction(project_root, data)
        raise
    finally:
        lock.release()


def resume_deployment(
    deployment_root: str | Path,
) -> DeploymentResult:
    project_root = _project_root(deployment_root)
    try:
        lock = server_runtime_lock(
            project_root / "src",
            allow_unfinished_deployment=True,
        ).acquire()
    except RuntimeLockError as exc:
        raise MaintenanceOperationError(str(exc)) from exc
    try:
        transaction = _load_transaction(project_root)
        source = _stored_release(project_root, transaction["from_release"])
        target = _stored_release(project_root, transaction["to_release"])
        phase = transaction["phase"]
        if phase in {"activation", "database-migration", "database-recovery-required"}:
            engine = _database_engine(project_root)
            try:
                with _suppress_bytecode_writes(), engine.connect() as connection:
                    revision = _current_revision(connection)
                    _, _, source_head = _alembic(source)
                    _, _, target_head = _alembic(target)
            finally:
                engine.dispose()
            if revision == source_head:
                _restore_active(project_root, source, target)
                active = source
            elif revision == target_head:
                _restore_active(project_root, target, source)
                active = target
            else:
                raise MaintenanceOperationError(
                    f"Database revision {revision or 'unversioned'} matches "
                    "neither transaction endpoint"
                )
        else:
            raise MaintenanceOperationError(
                f"Unsupported deployment transaction phase: {phase!r}"
            )
        _sync_environment(project_root, _load_settings(project_root))
        _transaction_path(project_root).unlink()
        return DeploymentResult(
            "resume", project_root, active.version, active.release_id
        )
    finally:
        lock.release()


def prune_deployment(
    deployment_root: str | Path,
    *,
    expected_release_ids: tuple[str, ...],
) -> DeploymentPruneResult:
    project_root = _project_root(deployment_root)
    normalized_ids = tuple(
        sorted(release_id.lower() for release_id in expected_release_ids)
    )
    if any(
        _SHA256_PATTERN(release_id) is None for release_id in expected_release_ids
    ) or len(normalized_ids) != len(set(normalized_ids)):
        raise MaintenanceOperationError(
            "Expected releases must be unique, full SHA-256 release IDs"
        )
    try:
        lock = server_runtime_lock(project_root / "src").acquire()
    except RuntimeLockError as exc:
        raise MaintenanceOperationError(str(exc)) from exc
    try:
        transaction_path = _transaction_path(project_root)
        if transaction_path.exists():
            raise MaintenanceOperationError(
                "Resume the unfinished deployment transaction first: "
                f"{transaction_path}"
            )
        active = _active_release(project_root)
        if active.release_id in normalized_ids:
            raise MaintenanceOperationError("The active release cannot be pruned")
        stored_releases = _stored_releases(project_root)
        candidates = tuple(
            (path, release)
            for path, release in stored_releases
            if release.release_id != active.release_id
        )
        actual_ids = tuple(sorted(release.release_id for _, release in candidates))
        if actual_ids != normalized_ids:
            raise MaintenanceOperationError(
                "Stored releases changed after the prune preview; inspect and retry"
            )

        removed = []
        for path, release in candidates:
            try:
                shutil.rmtree(path)
            except OSError as exc:
                raise MaintenanceOperationError(
                    f"Unable to remove stored release {release.release_id} after "
                    f"pruning {len(removed)} release(s): {exc}"
                ) from exc
            removed.append(
                DeploymentVersion(release.release_id, release.version, False)
            )
        return DeploymentPruneResult(
            project_root,
            active.version,
            active.release_id,
            tuple(removed),
        )
    finally:
        lock.release()


def inspect_deployment(deployment_root: str | Path) -> DeploymentResult:
    project_root = _project_root(deployment_root)
    active = _active_release(project_root)
    versions = []
    for _, release in _stored_releases(project_root):
        versions.append(
            DeploymentVersion(
                release.release_id,
                release.version,
                release.release_id == active.release_id,
            )
        )
    if not any(version.active for version in versions):
        versions.append(DeploymentVersion(active.release_id, active.version, True))
    return DeploymentResult(
        "status",
        project_root,
        active.version,
        active.release_id,
        tuple(versions),
    )
