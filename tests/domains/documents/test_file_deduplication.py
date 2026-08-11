import shutil
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace

import pytest
from loguru import logger as log
from sqlalchemy import Column, ForeignKey, MetaData, String, Table, create_engine, event
from sqlalchemy.orm import sessionmaker

_project_root = Path(__file__).resolve().parents[3]
_src_path = _project_root / "src"


class _FakeStorage:
    def __init__(self):
        self.objects: set[str] = set()
        self.fail_deletes = False

    def remove(self, path):
        if self.fail_deletes:
            return False
        existed = path in self.objects
        self.objects.discard(path)
        return existed

    def exists(self, path):
        return path in self.objects


@pytest.fixture
def deduplication_context(monkeypatch, tmp_path):
    src = str(_src_path)
    if src not in sys.path:
        sys.path.insert(0, src)

    config_dir = tmp_path / "config"
    config_dir.mkdir()
    shutil.copy(_src_path / "config.toml.sample", config_dir / "config.toml")
    (config_dir / "init").write_text("", encoding="utf-8")
    monkeypatch.chdir(config_dir)

    from include.database.models.files import (
        File,
        FileDeduplicationPhase,
        FileDeduplicationTask,
        FileTask,
        FileTaskStatus,
        TransferMode,
    )
    from include.database.models.identity import User
    from include.database.session import Base
    from include.domains.documents.queries.file_references import (
        _clear_file_references_cache,
    )
    from include.extensions.builtin import _file_deduplication as file_deduplication

    engine = create_engine(
        f"sqlite:///{tmp_path / 'deduplication.db'}",
        connect_args={"timeout": 10},
    )

    @event.listens_for(engine, "connect")
    def _enable_foreign_keys(dbapi_connection, _connection_record):
        dbapi_connection.execute("PRAGMA foreign_keys=ON")

    Base.metadata.create_all(
        engine,
        tables=[
            User.__table__,
            File.__table__,
            FileTask.__table__,
            FileDeduplicationTask.__table__,
        ],
    )
    owner_metadata = MetaData()
    Table("files", owner_metadata, autoload_with=engine)
    owners = Table(
        "test_file_owners",
        owner_metadata,
        Column("id", String(32), primary_key=True),
        Column("file_id", String(255), ForeignKey("files.id"), nullable=False),
    )
    owner_metadata.create_all(engine)

    testing_session = sessionmaker(bind=engine)
    storage = _FakeStorage()
    monkeypatch.setattr(file_deduplication, "Session", testing_session)
    monkeypatch.setattr(
        file_deduplication,
        "ProviderManager",
        lambda: SimpleNamespace(storage=storage),
    )
    _clear_file_references_cache()

    yield SimpleNamespace(
        module=file_deduplication,
        session=testing_session,
        storage=storage,
        owners=owners,
        File=File,
        Task=FileDeduplicationTask,
        Phase=FileDeduplicationPhase,
        FileTask=FileTask,
        FileTaskStatus=FileTaskStatus,
        TransferMode=TransferMode,
    )

    _clear_file_references_cache()
    engine.dispose()


def _add_duplicate_pair(context, *, live_download=False):
    digest = "a" * 64
    context.storage.objects.update({"canonical.bin", "source.bin"})
    with context.session() as session, session.begin():
        session.add_all(
            [
                context.File(
                    id="canonical",
                    path="canonical.bin",
                    sha256=digest,
                    size=7,
                    created_time=1.0,
                    active=True,
                ),
                context.File(
                    id="source",
                    path="source.bin",
                    sha256=digest,
                    size=7,
                    created_time=2.0,
                    active=True,
                ),
            ]
        )
        session.flush()
        session.execute(context.owners.insert(), {"id": "owner", "file_id": "source"})
        session.add(
            context.FileTask(
                id="completed-upload",
                file_id="source",
                status=context.FileTaskStatus.COMPLETED,
                mode=context.TransferMode.UPLOAD,
                start_time=1.0,
                end_time=2.0,
            )
        )
        if live_download:
            session.add_all(
                [
                    context.FileTask(
                        id="pending-download",
                        file_id="source",
                        status=context.FileTaskStatus.PENDING,
                        mode=context.TransferMode.DOWNLOAD,
                        start_time=1.0,
                        end_time=100.0,
                    ),
                    context.FileTask(
                        id="active-download",
                        file_id="source",
                        status=context.FileTaskStatus.IN_PROGRESS,
                        mode=context.TransferMode.DOWNLOAD,
                        start_time=1.0,
                        end_time=100.0,
                    ),
                ]
            )
        session.add(
            context.Task(
                file_id="source",
                phase=context.Phase.MERGE,
                available_at=0.0,
                attempts=0,
                created_time=1.0,
            )
        )


def test_worker_exits_quietly_after_successful_processing(
    deduplication_context, monkeypatch
):
    context = deduplication_context
    records = []
    worker = context.module.FileDeduplicationWorker()

    def stop_worker():
        worker._stop.set()
        worker._wake.set()
        return False

    monkeypatch.setattr(
        context.module,
        "process_one_file_deduplication_task",
        stop_worker,
    )
    sink_id = log.add(
        lambda message: records.append(message.record),
        filter=lambda record: (
            record["extra"].get("name") == "builtin.file_deduplication"
        ),
    )
    try:
        worker._run()
    finally:
        log.remove(sink_id)

    assert records == []


def test_non_duplicate_file_completes_quietly_without_storage_deletion(
    deduplication_context,
):
    context = deduplication_context
    messages = []
    sink_id = log.add(lambda message: messages.append(message.record["message"]))
    context.storage.objects.add("only.bin")
    with context.session() as session, session.begin():
        session.add(
            context.File(
                id="only",
                path="only.bin",
                sha256="a" * 64,
                size=4,
                created_time=1.0,
                active=True,
            )
        )
        session.add(
            context.Task(
                file_id="only",
                phase=context.Phase.MERGE,
                available_at=0.0,
                attempts=0,
                created_time=1.0,
            )
        )

    try:
        assert context.module.process_one_file_deduplication_task() is True
    finally:
        log.remove(sink_id)

    with context.session() as session:
        assert session.get(context.File, "only").active is True
        assert session.get(context.Task, "only") is None
    assert context.storage.objects == {"only.bin"}
    assert messages == []


def test_duplicate_references_and_storage_are_reclaimed(deduplication_context):
    context = deduplication_context
    _add_duplicate_pair(context)

    assert context.module.process_one_file_deduplication_task() is True

    with context.session() as session:
        assert session.get(context.File, "source") is None
        assert session.get(context.File, "canonical").active is True
        assert session.get(context.Task, "source") is None
        assert session.execute(context.owners.select()).one().file_id == "canonical"
    assert context.storage.objects == {"canonical.bin"}


def test_storage_delete_waits_for_active_download(deduplication_context):
    context = deduplication_context
    _add_duplicate_pair(context, live_download=True)

    assert context.module.process_one_file_deduplication_task() is True

    with context.session() as session, session.begin():
        source = session.get(context.File, "source")
        task = session.get(context.Task, "source")
        assert source.active is False
        assert task.phase == context.Phase.STORAGE_DELETE
        assert session.get(context.FileTask, "pending-download").file_id == "canonical"
        assert session.get(context.FileTask, "active-download").file_id == "source"
        assert "source.bin" in context.storage.objects
        session.get(
            context.FileTask, "active-download"
        ).status = context.FileTaskStatus.COMPLETED
        task.available_at = 0.0

    assert context.module.process_one_file_deduplication_task() is True
    with context.session() as session:
        assert session.get(context.File, "source") is None
        assert session.get(context.FileTask, "pending-download").file_id == "canonical"
    assert "source.bin" not in context.storage.objects


def test_storage_failure_is_retried_from_delete_phase(deduplication_context):
    context = deduplication_context
    _add_duplicate_pair(context)
    context.storage.fail_deletes = True

    assert context.module.process_one_file_deduplication_task() is True

    with context.session() as session, session.begin():
        source = session.get(context.File, "source")
        task = session.get(context.Task, "source")
        assert source.active is False
        assert task.phase == context.Phase.STORAGE_DELETE
        assert task.lease_owner is None
        assert "did not remove" in task.last_error
        task.available_at = 0.0

    context.storage.fail_deletes = False
    assert context.module.process_one_file_deduplication_task() is True
    with context.session() as session:
        assert session.get(context.File, "source") is None


def test_merge_failure_keeps_source_readable_and_reschedules(
    deduplication_context, monkeypatch
):
    context = deduplication_context
    _add_duplicate_pair(context)

    def fail_reference_discovery(_engine):
        raise RuntimeError("reference discovery failed")

    monkeypatch.setattr(
        context.module, "_get_file_references", fail_reference_discovery
    )
    assert context.module.process_one_file_deduplication_task() is True

    with context.session() as session:
        source = session.get(context.File, "source")
        task = session.get(context.Task, "source")
        assert source.active is True
        assert task.phase == context.Phase.MERGE
        assert task.lease_owner is None
        assert task.last_error == "reference discovery failed"
        assert session.execute(context.owners.select()).one().file_id == "source"
    assert "source.bin" in context.storage.objects


def test_missing_storage_object_is_idempotent_success(deduplication_context):
    context = deduplication_context
    _add_duplicate_pair(context)
    context.storage.objects.remove("source.bin")

    assert context.module.process_one_file_deduplication_task() is True

    with context.session() as session:
        assert session.get(context.File, "source") is None
        assert session.execute(context.owners.select()).one().file_id == "canonical"


def test_multiple_duplicate_tasks_converge_on_stable_canonical(
    deduplication_context,
):
    context = deduplication_context
    digest = "c" * 64
    context.storage.objects.update({"a.bin", "b.bin", "c.bin"})
    with context.session() as session, session.begin():
        for file_id in ("c", "a", "b"):
            session.add(
                context.File(
                    id=file_id,
                    path=f"{file_id}.bin",
                    sha256=digest,
                    size=10,
                    created_time=1.0,
                    active=True,
                )
            )
        session.flush()
        for file_id in ("c", "a", "b"):
            session.add(
                context.Task(
                    file_id=file_id,
                    phase=context.Phase.MERGE,
                    available_at=0.0,
                    attempts=0,
                    created_time=1.0,
                )
            )

    while context.module.process_one_file_deduplication_task():
        pass

    with context.session() as session:
        files = session.query(context.File).all()
        assert [(file.id, file.active) for file in files] == [("a", True)]
        assert session.query(context.Task).count() == 0
    assert context.storage.objects == {"a.bin"}


def test_expired_lease_can_be_reclaimed_once(deduplication_context):
    context = deduplication_context
    with context.session() as session, session.begin():
        session.add(
            context.File(
                id="leased",
                path="leased.bin",
                sha256="b" * 64,
                created_time=1.0,
                active=True,
            )
        )
        session.add(
            context.Task(
                file_id="leased",
                phase=context.Phase.MERGE,
                available_at=0.0,
                lease_owner="old-owner",
                lease_expires_at=1.0,
                attempts=0,
                created_time=1.0,
            )
        )

    def claim():
        return context.module._claim_next_task(now=time.time())

    with ThreadPoolExecutor(max_workers=2) as executor:
        claims = list(executor.map(lambda _index: claim(), range(2)))

    assert sum(claim is not None for claim in claims) == 1
