import hashlib
import os
import shutil
import sqlite3
import sys
import time
from dataclasses import FrozenInstanceError, dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import jsonschema
import orjson
import pytest
from sqlalchemy import Table, create_engine
from sqlalchemy.orm import sessionmaker
from websockets.exceptions import ConnectionClosed

_project_root = Path(__file__).resolve().parents[3]
_src_path = _project_root / "src"


def _get_revision_file_size(revision_id: str) -> int | None:
    with sqlite3.connect("src/app.db") as connection:
        row = connection.execute(
            """
            SELECT files.size
            FROM files
            JOIN document_revisions ON document_revisions.file_id = files.id
            WHERE document_revisions.id = ?
            """,
            (revision_id,),
        ).fetchone()

    return row[0] if row else None


def _set_revision_file_size(revision_id: str, size: int) -> None:
    with sqlite3.connect("src/app.db") as connection:
        connection.execute(
            """
            UPDATE files
            SET size = ?
            WHERE id = (
                SELECT file_id
                FROM document_revisions
                WHERE id = ?
            )
            """,
            (size, revision_id),
        )
        connection.commit()


def _get_file_task_status(task_id: str) -> int | None:
    with sqlite3.connect("src/app.db") as connection:
        row = connection.execute(
            "SELECT status FROM file_tasks WHERE id = ?", (task_id,)
        ).fetchone()

    return row[0] if row else None


class _FakeFrame:
    def __init__(self, data):
        self.data = data


@dataclass
class _SentPayload:
    data: object
    frame_type: object = None


class _FakeLogger:
    def bind(self, **_kwargs):
        return self

    def info(self, *_args, **_kwargs):
        pass

    def error(self, *_args, **_kwargs):
        pass

    def debug(self, *_args, **_kwargs):
        pass


class _FakeStorage:
    def __init__(self, root):
        self.root = root

    def _resolve(self, path):
        return self.root / path

    def fopen(self, path, mode="rb"):
        return open(self._resolve(path), mode)

    def getsize(self, path):
        return os.path.getsize(self._resolve(path))

    def makedirs(self, path, mode=0o777, exist_ok=False):
        os.makedirs(self._resolve(path), mode=mode, exist_ok=exist_ok)

    def remove(self, path):
        try:
            os.remove(self._resolve(path))
            return True
        except FileNotFoundError:
            return False

    def open_resumable_upload(
        self,
        path,
        *,
        file_size,
        chunk_size,
        session_id=None,
        checkpoint_size=None,
        checkpoint_data=None,
        checkpoint_callback=None,
    ):
        from include.providers.storage.local import LocalResumableUpload

        return LocalResumableUpload(
            str(self._resolve(path)),
            file_size,
            chunk_size,
        )


class _FakeProviderManager:
    def __init__(self, storage):
        self.storage = storage


class _TrackingSession:
    def __init__(self, tracker):
        self._tracker = tracker
        self._session = tracker.session_factory()

    def __enter__(self):
        session = self._session.__enter__()
        self._tracker.active += 1
        return session

    def __exit__(self, exc_type, exc_value, traceback):
        try:
            return self._session.__exit__(exc_type, exc_value, traceback)
        finally:
            self._tracker.active -= 1

    def __getattr__(self, name):
        return getattr(self._session, name)


class _TrackingSessionFactory:
    def __init__(self, session_factory):
        self.session_factory = session_factory
        self.active = 0

    def __call__(self):
        return _TrackingSession(self)


class _FakeDownloadStream:
    def __init__(self):
        self.sent_payloads = []
        self.responses = [_FakeFrame(b"ready"), _FakeFrame(b"complete")]

    def send(self, data, frame_type=None, **_kwargs):
        self.sent_payloads.append(_SentPayload(data, frame_type))

    def recv(self, timeout=None):
        return self.responses.pop(0)


class _AssertingDownloadStream(_FakeDownloadStream):
    def __init__(self, tracker):
        super().__init__()
        self.tracker = tracker

    def recv(self, timeout=None):
        assert self.tracker.active == 0
        return super().recv(timeout)


class _DisconnectBeforeCompletionStream(_FakeDownloadStream):
    def recv(self, timeout=None):
        if len(self.responses) == 1:
            raise ConnectionClosed(None, None)
        return super().recv(timeout)


class _FakeUploadStream:
    def __init__(self, frames):
        self.sent_payloads = []
        self.responses = [_FakeFrame(frame) for frame in frames]

    def send(self, data, frame_type=None, **_kwargs):
        self.sent_payloads.append(_SentPayload(data, frame_type))

    def recv(self, timeout=None):
        return self.responses.pop(0)


class _AssertingUploadStream(_FakeUploadStream):
    def __init__(self, frames, tracker):
        super().__init__(frames)
        self.tracker = tracker

    def recv(self, timeout=None):
        assert self.tracker.active == 0
        return super().recv(timeout)


class _DisconnectingUploadStream(_FakeUploadStream):
    def recv(self, timeout=None):
        if not self.responses:
            raise ConnectionError("upload connection closed")
        return super().recv(timeout)


class _FailingUploadNegotiationStream(_FakeUploadStream):
    def __init__(self):
        super().__init__([])
        self._failed = False

    def send(self, data, frame_type=None, **kwargs):
        if not self._failed:
            self._failed = True
            raise ConnectionError("upload connection closed")
        return super().send(data, frame_type, **kwargs)


def _new_transfer_handler(connection_handler_cls, stream):
    handler = connection_handler_cls.__new__(connection_handler_cls)
    handler.stream = stream
    handler.logger = _FakeLogger()
    handler.remote_address = "203.0.113.1"
    return handler


def _sent_json_messages(stream):
    return [
        orjson.loads(sent_payload.data)
        for sent_payload in stream.sent_payloads
        if isinstance(sent_payload.data, bytes | bytearray | memoryview)
    ]


@pytest.fixture
def file_task_context(monkeypatch, tmp_path):
    _src = str(_src_path)
    if _src not in sys.path:
        sys.path.insert(0, _src)

    config_dir = tmp_path / "config"
    config_dir.mkdir()
    shutil.copy(_src_path / "config.toml.sample", config_dir / "config.toml")
    (config_dir / "init").write_text("", encoding="utf-8")
    monkeypatch.chdir(config_dir)

    import include.transport.connection as connection_handler
    from include.config.constants import UPLOAD_TRANSFER_MIN_CHUNK_SIZE
    from include.database.models.files import File, FileDeduplicationTask, FileTask
    from include.database.models.identity import User
    from include.database.models.operations import RateLimitBucket, RiskIPAccount
    from include.database.session import Base
    from include.extensions.builtin._file_deduplication import (
        schedule_file_deduplication,
    )
    from include.transport.multiplexing import FrameType

    engine = create_engine(f"sqlite:///{tmp_path / 'file_tasks.db'}")
    Base.metadata.create_all(
        engine,
        tables=[
            cast(Table, User.__table__),
            cast(Table, File.__table__),
            cast(Table, FileTask.__table__),
            cast(Table, FileDeduplicationTask.__table__),
            cast(Table, RateLimitBucket.__table__),
            cast(Table, RiskIPAccount.__table__),
        ],
    )
    TestingSession = sessionmaker(bind=engine)

    monkeypatch.setattr(connection_handler, "Session", TestingSession)
    monkeypatch.setattr(
        connection_handler,
        "ProviderManager",
        lambda: _FakeProviderManager(_FakeStorage(tmp_path)),
    )
    monkeypatch.setattr(
        connection_handler,
        "pm",
        SimpleNamespace(
            hook=SimpleNamespace(
                ext_before_file_upload_finalize=lambda session, id, **_kwargs: (
                    schedule_file_deduplication(session, id)
                ),
                ext_on_file_upload_completed=lambda **_kwargs: None,
            )
        ),
    )

    return SimpleNamespace(
        session=TestingSession,
        connection=connection_handler,
        ConnectionHandler=connection_handler.ConnectionHandler,
        FrameType=FrameType,
        File=File,
        FileDeduplicationTask=FileDeduplicationTask,
        FileTask=FileTask,
        RateLimitBucket=RateLimitBucket,
        User=User,
        UPLOAD_TRANSFER_MIN_CHUNK_SIZE=UPLOAD_TRANSFER_MIN_CHUNK_SIZE,
    )


def _create_file_task(context, path, mode, status=0):
    session_factory = context.session
    with session_factory() as session:
        file = context.File(id=f"file-{mode}-{path}", path=path)
        task = context.FileTask(
            id=f"task-{mode}-{path}",
            file_id=file.id,
            mode=mode,
            status=status,
            start_time=time.time(),
            end_time=time.time() + 60,
        )
        session.add(file)
        session.add(task)
        session.commit()
        return task.id, file.id


def test_create_file_task_participates_in_caller_transaction(
    file_task_context,
) -> None:
    from include.domains.documents.handlers.documents import create_file_task

    with file_task_context.session() as session:
        file = file_task_context.File(id="atomic-file", path="uploads/atomic.bin")
        session.add(file)

        task_data = create_file_task(session, file, transfer_mode=1)

        assert session.get(file_task_context.FileTask, task_data["task_id"]) is not None
        session.rollback()

    with file_task_context.session() as session:
        assert session.get(file_task_context.File, "atomic-file") is None
        assert session.get(file_task_context.FileTask, task_data["task_id"]) is None


def test_create_file_task_is_persisted_by_caller_commit(file_task_context) -> None:
    from include.domains.documents.handlers.documents import create_file_task

    with file_task_context.session() as session:
        file = file_task_context.File(id="committed-file", path="uploads/committed.bin")
        session.add(file)
        task_data = create_file_task(session, file, transfer_mode=1)
        session.commit()

    with file_task_context.session() as session:
        task = session.get(file_task_context.FileTask, task_data["task_id"])
        assert task is not None
        assert task.file_id == "committed-file"


def test_download_task_records_issuer_without_binding_bearer(file_task_context) -> None:
    from include.domains.documents.handlers.documents import create_file_task

    with file_task_context.session.begin() as session:
        session.add(
            file_task_context.User(
                username="alice", pass_hash="unused", created_time=1.0
            )
        )
        file = file_task_context.File(id="download-file", path="download.bin")
        session.add(file)
        task_data = create_file_task(
            session,
            file,
            issued_by_username="alice",
        )

    with file_task_context.session() as session:
        task = session.get(file_task_context.FileTask, task_data["task_id"])
        assert task.issued_by_username == "alice"


def test_upload_task_lifecycle_uses_two_stage_deadline(
    file_task_context, monkeypatch
) -> None:
    from include.database.models.files import FileTaskStatus, TransferMode
    from include.domains.documents.commands import file_tasks

    task_id, _file_id = _create_file_task(
        file_task_context, "uploads/lifecycle.bin", mode=TransferMode.UPLOAD
    )
    monkeypatch.setattr(file_tasks.time, "time", lambda: 1000.0)

    with file_task_context.session.begin() as session:
        task = session.get(file_task_context.FileTask, task_id)
        task.start_time = 900.0
        task.end_time = 4500.0

    with file_task_context.session.begin() as session:
        claimed = file_tasks.claim_file_task(
            session, task_id, TransferMode.UPLOAD, now=1000.0
        )
        assert claimed is not None

    with file_task_context.session() as session:
        task = session.get(file_task_context.FileTask, task_id)
        hard_deadline = task.end_time
        assert task.status == FileTaskStatus.IN_PROGRESS
        assert task.start_time == 1000.0

    with file_task_context.session.begin() as session:
        assert (
            file_tasks.release_file_task(session, task_id, now=1001.0)
            == FileTaskStatus.PENDING
        )

    with file_task_context.session.begin() as session:
        claimed = file_tasks.claim_file_task(
            session, task_id, TransferMode.UPLOAD, now=1002.0
        )
        assert claimed is not None
        assert file_tasks.complete_file_task(session, task_id) is True
        assert file_tasks.complete_file_task(session, task_id) is False

    with file_task_context.session() as session:
        task = session.get(file_task_context.FileTask, task_id)
        assert task.start_time == 1000.0
        assert task.end_time == hard_deadline


def test_claim_returns_read_only_transfer_snapshot(file_task_context) -> None:
    from include.database.models.files import FileTaskStatus, TransferMode
    from include.domains.documents.commands.file_tasks import claim_file_task

    task_id, file_id = _create_file_task(
        file_task_context, "snapshot.bin", mode=TransferMode.DOWNLOAD
    )
    with file_task_context.session.begin() as session:
        file = session.get(file_task_context.File, file_id)
        file.size = 123
        task = session.get(file_task_context.FileTask, task_id)
        task.encryption_key = "sensitive-key"

    with file_task_context.session.begin() as session:
        claimed = claim_file_task(session, task_id, TransferMode.DOWNLOAD)

    assert claimed is not None
    assert claimed.task_id == task_id
    assert claimed.file_id == file_id
    assert claimed.file_path == "snapshot.bin"
    assert claimed.stored_file_size == 123
    assert claimed.issued_by_username is None
    assert claimed.encryption_key == "sensitive-key"
    assert "sensitive-key" not in repr(claimed)
    with pytest.raises(FrozenInstanceError):
        claimed.file_path = "changed.bin"

    with file_task_context.session() as session:
        task = session.get(file_task_context.FileTask, task_id)
        assert task.status == FileTaskStatus.IN_PROGRESS


def test_claim_rejects_invalid_or_competing_requests(file_task_context) -> None:
    from include.database.models.files import FileTaskStatus, TransferMode
    from include.domains.documents.commands.file_tasks import claim_file_task

    upload_task_id, _file_id = _create_file_task(
        file_task_context, "claim-once.bin", mode=TransferMode.UPLOAD
    )
    future_task_id, _file_id = _create_file_task(
        file_task_context, "future.bin", mode=TransferMode.UPLOAD
    )
    with file_task_context.session.begin() as session:
        upload_task = session.get(file_task_context.FileTask, upload_task_id)
        upload_task.start_time = 50.0
        upload_task.end_time = 500.0
        future_task = session.get(file_task_context.FileTask, future_task_id)
        future_task.start_time = 200.0
        future_task.end_time = 500.0

    with file_task_context.session.begin() as session:
        assert (
            claim_file_task(session, "missing-task", TransferMode.UPLOAD, now=100.0)
            is None
        )
        assert (
            claim_file_task(session, upload_task_id, TransferMode.DOWNLOAD, now=100.0)
            is None
        )
        assert (
            claim_file_task(session, future_task_id, TransferMode.UPLOAD, now=100.0)
            is None
        )
        assert (
            claim_file_task(session, upload_task_id, TransferMode.UPLOAD, now=100.0)
            is not None
        )
        assert (
            claim_file_task(session, upload_task_id, TransferMode.UPLOAD, now=100.0)
            is None
        )

    with file_task_context.session() as session:
        assert (
            session.get(file_task_context.FileTask, upload_task_id).status
            == FileTaskStatus.IN_PROGRESS
        )


def test_claim_marks_due_task_expired(file_task_context) -> None:
    from include.database.models.files import FileTaskStatus, TransferMode
    from include.domains.documents.commands.file_tasks import claim_file_task

    task_id, _file_id = _create_file_task(
        file_task_context, "uploads/expired.bin", mode=TransferMode.UPLOAD
    )
    with file_task_context.session.begin() as session:
        task = session.get(file_task_context.FileTask, task_id)
        task.end_time = 10.0

    with file_task_context.session.begin() as session:
        assert claim_file_task(session, task_id, TransferMode.UPLOAD, now=11.0) is None

    with file_task_context.session() as session:
        assert (
            session.get(file_task_context.FileTask, task_id).status
            == FileTaskStatus.EXPIRED
        )


def test_active_transfer_check_marks_due_task_expired(file_task_context) -> None:
    from include.database.models.files import FileTaskStatus, TransferMode

    task_id, _file_id = _create_file_task(
        file_task_context,
        "uploads/active-expired.bin",
        mode=TransferMode.UPLOAD,
        status=FileTaskStatus.IN_PROGRESS,
    )
    with file_task_context.session.begin() as session:
        session.get(file_task_context.FileTask, task_id).end_time = 1.0

    status = file_task_context.ConnectionHandler._get_file_task_status(task_id)

    assert status == FileTaskStatus.EXPIRED
    with file_task_context.session() as session:
        assert (
            session.get(file_task_context.FileTask, task_id).status
            == FileTaskStatus.EXPIRED
        )


def test_transfer_claim_race_reports_expired_status(file_task_context) -> None:
    from include.database.models.files import FileTaskStatus, TransferMode

    task_id, _file_id = _create_file_task(
        file_task_context, "expired-download.bin", mode=TransferMode.DOWNLOAD
    )
    with file_task_context.session.begin() as session:
        session.get(file_task_context.FileTask, task_id).end_time = 1.0

    stream = _FakeDownloadStream()
    handler = _new_transfer_handler(file_task_context.ConnectionHandler, stream)
    handler.send_file(task_id, offset=0, max_chunk_size=64 * 1024)

    response = _sent_json_messages(stream)[-1]
    assert response["code"] == 410
    assert response["data"] == {"task_status": "expired"}
    with file_task_context.session() as session:
        assert (
            session.get(file_task_context.FileTask, task_id).status
            == FileTaskStatus.EXPIRED
        )


def test_missing_transfer_task_reports_not_found(file_task_context) -> None:
    stream = _FakeDownloadStream()
    handler = _new_transfer_handler(file_task_context.ConnectionHandler, stream)

    handler.send_file("missing-task", offset=0, max_chunk_size=64 * 1024)

    response = _sent_json_messages(stream)[-1]
    assert response["code"] == 404
    assert response["data"] == {}


def test_download_limit_denial_releases_claimed_task(
    file_task_context, monkeypatch
) -> None:
    from include.config.validation import DocumentDownloadRiskPolicy
    from include.database.models.files import FileTaskStatus, TransferMode
    from include.domains.documents import download_limits

    policy = DocumentDownloadRiskPolicy(
        mode="enforce",
        task_capacity=1,
        task_refill_tokens=1,
    )
    monkeypatch.setattr(
        download_limits.DocumentDownloadRiskPolicy,
        "from_config",
        classmethod(lambda _cls: policy),
    )
    task_id, _file_id = _create_file_task(
        file_task_context,
        "rate-limited.bin",
        mode=TransferMode.DOWNLOAD,
    )
    now = time.time()
    with file_task_context.session.begin() as session:
        session.add(
            file_task_context.RateLimitBucket(
                namespace="download_transfer",
                scope="task",
                identity=task_id,
                tokens=0.0,
                last_refill_at=now,
                denial_count=0,
                last_attempt=now,
            )
        )

    stream = _FakeDownloadStream()
    handler = _new_transfer_handler(file_task_context.ConnectionHandler, stream)
    handler.send_file(task_id, offset=0, max_chunk_size=64 * 1024)

    response = _sent_json_messages(stream)[-1]
    assert response["code"] == 429
    assert response["data"]["scope"] == "task"
    assert "risk" not in response["data"]
    with file_task_context.session() as session:
        assert session.get(file_task_context.FileTask, task_id).status == (
            FileTaskStatus.PENDING
        )


def test_concurrent_upload_reports_conflict(file_task_context) -> None:
    from include.database.models.files import FileTaskStatus, TransferMode

    task_id, _file_id = _create_file_task(
        file_task_context,
        "uploads/in-progress.bin",
        mode=TransferMode.UPLOAD,
        status=FileTaskStatus.IN_PROGRESS,
    )
    stream = _FakeUploadStream([])
    handler = _new_transfer_handler(file_task_context.ConnectionHandler, stream)

    handler.receive_file(task_id, 1, hashlib.sha256(b"x").hexdigest(), 512, False)

    response = _sent_json_messages(stream)[-1]
    assert response["code"] == 409
    assert response["data"] == {"task_status": "in_progress"}


def test_concurrent_download_remains_bad_request(file_task_context) -> None:
    from include.database.models.files import FileTaskStatus, TransferMode

    task_id, _file_id = _create_file_task(
        file_task_context,
        "in-progress-download.bin",
        mode=TransferMode.DOWNLOAD,
        status=FileTaskStatus.IN_PROGRESS,
    )
    stream = _FakeDownloadStream()
    handler = _new_transfer_handler(file_task_context.ConnectionHandler, stream)

    handler.send_file(task_id, offset=0, max_chunk_size=64 * 1024)

    response = _sent_json_messages(stream)[-1]
    assert response["code"] == 400
    assert response["data"] == {}


def test_wrong_mode_and_future_task_report_bad_request(file_task_context) -> None:
    from include.database.models.files import TransferMode

    upload_task_id, _file_id = _create_file_task(
        file_task_context, "wrong-mode.bin", mode=TransferMode.UPLOAD
    )
    future_task_id, _file_id = _create_file_task(
        file_task_context, "future-download.bin", mode=TransferMode.DOWNLOAD
    )
    with file_task_context.session.begin() as session:
        future_task = session.get(file_task_context.FileTask, future_task_id)
        future_task.start_time = time.time() + 60
        future_task.end_time = future_task.start_time + 60

    for task_id in (upload_task_id, future_task_id):
        stream = _FakeDownloadStream()
        handler = _new_transfer_handler(file_task_context.ConnectionHandler, stream)

        handler.send_file(task_id, offset=0, max_chunk_size=64 * 1024)

        response = _sent_json_messages(stream)[-1]
        assert response["code"] == 400
        assert response["data"] == {}


def test_file_request_handlers_delegate_claiming(file_task_context) -> None:
    from include.domains.documents.handlers.documents import (
        RequestDownloadFileHandler,
        RequestUploadFileHandler,
    )

    calls = []
    handler = SimpleNamespace(
        data={
            "task_id": "task",
            "offset": 64,
            "file_size": 1,
            "sha256": "A" * 64,
            "max_chunk_size": 32 * 1024,
            "restart": True,
        },
        send_file=lambda task_id, offset, max_chunk_size: calls.append(
            ("download", task_id, offset, max_chunk_size)
        ),
        receive_file=lambda *args: calls.append(("upload", *args)),
    )

    RequestDownloadFileHandler().handle(handler)
    RequestUploadFileHandler().handle(handler)

    assert calls == [
        ("download", "task", 64, 32 * 1024),
        ("upload", "task", 1, "a" * 64, 32 * 1024, True),
    ]


def test_download_request_requires_bounded_chunk_size(file_task_context) -> None:
    from include.domains.documents.handlers.documents import RequestDownloadFileHandler

    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(
            {"task_id": "task"},
            RequestDownloadFileHandler.schema,
        )
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(
            {"task_id": "task", "max_chunk_size": 8 * 1024},
            RequestDownloadFileHandler.schema,
        )
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(
            {"task_id": "task", "max_chunk_size": 4 * 1024 * 1024},
            RequestDownloadFileHandler.schema,
        )


def test_upload_request_requires_v21_metadata(file_task_context) -> None:
    from include.domains.documents.handlers.documents import RequestUploadFileHandler

    valid = {
        "task_id": "task",
        "file_size": 1,
        "sha256": "a" * 64,
        "max_chunk_size": 512,
    }
    jsonschema.validate(valid, RequestUploadFileHandler.schema)
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(
            {"task_id": "task"},
            RequestUploadFileHandler.schema,
        )
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(
            {**valid, "sha256": "not-a-digest"},
            RequestUploadFileHandler.schema,
        )
