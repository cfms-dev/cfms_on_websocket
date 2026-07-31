import hashlib
import os
import re
import shutil
import sqlite3
import sys
import threading
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

from tests.test_client import CFMSTestClient, calculate_sha256
from tests.utils import assert_success

_project_root = Path(__file__).resolve().parent.parent
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
                ext_before_file_upload_commit=lambda session, id, **_kwargs: (
                    schedule_file_deduplication(session, id)
                ),
                ext_on_empty_file_uploaded=lambda **_kwargs: None,
                ext_on_file_uploaded=lambda **_kwargs: None,
                ext_post_file_upload_response=lambda **_kwargs: None,
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


@pytest.mark.parametrize(
    ("client_max_chunk_size", "configured_chunk_size", "expected_chunk_size"),
    [
        (32 * 1024, 2 * 1024 * 1024, 32 * 1024),
        (64 * 1024, 16 * 1024, 16 * 1024),
        (2 * 1024 * 1024, 4 * 1024 * 1024, 2 * 1024 * 1024),
    ],
)
def test_download_negotiates_and_persists_chunk_size(
    file_task_context,
    tmp_path,
    monkeypatch,
    client_max_chunk_size,
    configured_chunk_size,
    expected_chunk_size,
) -> None:
    from include.database.models.files import TransferMode

    relative_path = "negotiated-download.bin"
    (tmp_path / relative_path).write_bytes(b"x" * (70 * 1024))
    task_id, _file_id = _create_file_task(
        file_task_context,
        relative_path,
        mode=TransferMode.DOWNLOAD,
    )
    stream = _FakeDownloadStream()
    handler = _new_transfer_handler(file_task_context.ConnectionHandler, stream)
    monkeypatch.setattr(
        file_task_context.connection,
        "global_config",
        {"server": {"file_chunk_size": configured_chunk_size}},
    )

    handler.send_file(task_id, offset=0, max_chunk_size=client_max_chunk_size)

    metadata = _sent_json_messages(stream)[0]["data"]
    assert metadata["chunk_size"] == expected_chunk_size
    assert (
        metadata["total_chunks"]
        == (70 * 1024 + expected_chunk_size - 1) // expected_chunk_size
    )
    with file_task_context.session() as session:
        assert (
            session.get(file_task_context.FileTask, task_id).chunk_size
            == expected_chunk_size
        )


@pytest.mark.parametrize("offset", [0, 64 * 1024])
def test_resume_reuses_persisted_chunk_size(
    file_task_context, tmp_path, monkeypatch, offset
) -> None:
    from include.database.models.files import TransferMode

    relative_path = "resumed-download.bin"
    (tmp_path / relative_path).write_bytes(b"y" * (128 * 1024))
    task_id, _file_id = _create_file_task(
        file_task_context,
        relative_path,
        mode=TransferMode.DOWNLOAD,
    )
    with file_task_context.session.begin() as session:
        session.get(file_task_context.FileTask, task_id).chunk_size = 64 * 1024
    stream = _FakeDownloadStream()
    handler = _new_transfer_handler(file_task_context.ConnectionHandler, stream)
    monkeypatch.setattr(
        file_task_context.connection,
        "global_config",
        {"server": {"file_chunk_size": 32 * 1024}},
    )

    handler.send_file(task_id, offset=offset, max_chunk_size=128 * 1024)

    assert _sent_json_messages(stream)[0]["data"]["chunk_size"] == 64 * 1024


def test_resume_rejects_smaller_client_limit_and_releases_task(
    file_task_context, tmp_path
) -> None:
    from include.database.models.files import FileTaskStatus, TransferMode

    relative_path = "resume-conflict.bin"
    (tmp_path / relative_path).write_bytes(b"z" * (128 * 1024))
    task_id, _file_id = _create_file_task(
        file_task_context,
        relative_path,
        mode=TransferMode.DOWNLOAD,
    )
    with file_task_context.session.begin() as session:
        session.get(file_task_context.FileTask, task_id).chunk_size = 64 * 1024
    stream = _FakeDownloadStream()
    handler = _new_transfer_handler(file_task_context.ConnectionHandler, stream)

    handler.send_file(task_id, offset=64 * 1024, max_chunk_size=32 * 1024)

    response = _sent_json_messages(stream)[-1]
    assert response["code"] == 409
    assert response["data"] == {"chunk_size": 64 * 1024}
    with file_task_context.session() as session:
        assert (
            session.get(file_task_context.FileTask, task_id).status
            == FileTaskStatus.PENDING
        )


def test_resume_rejects_offset_not_aligned_to_persisted_chunk_size(
    file_task_context, tmp_path
) -> None:
    from include.database.models.files import FileTaskStatus, TransferMode

    relative_path = "misaligned-resume.bin"
    (tmp_path / relative_path).write_bytes(b"m" * (128 * 1024))
    task_id, _file_id = _create_file_task(
        file_task_context,
        relative_path,
        mode=TransferMode.DOWNLOAD,
    )
    with file_task_context.session.begin() as session:
        session.get(file_task_context.FileTask, task_id).chunk_size = 64 * 1024
    stream = _FakeDownloadStream()
    handler = _new_transfer_handler(file_task_context.ConnectionHandler, stream)

    handler.send_file(task_id, offset=32 * 1024, max_chunk_size=64 * 1024)

    response = _sent_json_messages(stream)[-1]
    assert response["code"] == 400
    assert response["data"] == {"chunk_size": 64 * 1024}
    with file_task_context.session() as session:
        assert (
            session.get(file_task_context.FileTask, task_id).status
            == FileTaskStatus.PENDING
        )


def test_resume_after_all_chunks_replays_only_missing_key(
    file_task_context, tmp_path
) -> None:
    from include.database.models.files import FileTaskStatus, TransferMode

    relative_path = "key-resume.bin"
    file_size = 96 * 1024
    (tmp_path / relative_path).write_bytes(b"k" * file_size)
    task_id, _file_id = _create_file_task(
        file_task_context,
        relative_path,
        mode=TransferMode.DOWNLOAD,
    )

    interrupted_stream = _DisconnectBeforeCompletionStream()
    handler = _new_transfer_handler(
        file_task_context.ConnectionHandler,
        interrupted_stream,
    )
    handler.send_file(task_id, offset=0, max_chunk_size=64 * 1024)

    first_actions = [
        message.get("action") for message in _sent_json_messages(interrupted_stream)
    ]
    assert first_actions.count("file_chunk") == 2
    assert "aes_key" in first_actions
    with file_task_context.session() as session:
        task = session.get(file_task_context.FileTask, task_id)
        assert task.status == FileTaskStatus.PENDING
        assert task.encryption_key is not None
        assert task.chunk_size == 64 * 1024

    resumed_stream = _FakeDownloadStream()
    resumed_handler = _new_transfer_handler(
        file_task_context.ConnectionHandler,
        resumed_stream,
    )
    resumed_handler.send_file(
        task_id,
        offset=file_size,
        max_chunk_size=64 * 1024,
    )

    resumed_actions = [
        message.get("action") for message in _sent_json_messages(resumed_stream)
    ]
    assert "file_chunk" not in resumed_actions
    assert resumed_actions == ["transfer_file", "aes_key", "transfer_complete"]
    with file_task_context.session() as session:
        assert (
            session.get(file_task_context.FileTask, task_id).status
            == FileTaskStatus.COMPLETED
        )


@pytest.mark.parametrize(
    ("client_max_chunk_size", "configured_chunk_size", "expected_chunk_size"),
    [
        (1024, 2 * 1024 * 1024, 1024),
        (64 * 1024, 2048, 2048),
        (4 * 1024 * 1024, 4 * 1024 * 1024, 64 * 1024),
    ],
)
def test_upload_negotiates_shared_chunk_size(
    file_task_context,
    monkeypatch,
    client_max_chunk_size,
    configured_chunk_size,
    expected_chunk_size,
) -> None:
    from include.database.models.files import FileTaskStatus, TransferMode

    relative_path = "uploads/negotiated-upload.bin"
    task_id, _file_id = _create_file_task(
        file_task_context,
        relative_path,
        mode=TransferMode.UPLOAD,
    )
    payload = b"u"
    sha256 = hashlib.sha256(payload).hexdigest()
    stream = _FakeUploadStream([payload])
    handler = _new_transfer_handler(file_task_context.ConnectionHandler, stream)
    monkeypatch.setattr(
        file_task_context.connection,
        "global_config",
        {"server": {"file_chunk_size": configured_chunk_size}},
    )

    handler.receive_file(
        task_id,
        len(payload),
        sha256,
        client_max_chunk_size,
        False,
    )

    ready = _sent_json_messages(stream)[0]
    assert ready["data"] == {
        "file_size": len(payload),
        "chunk_size": expected_chunk_size,
        "offset": 0,
        "supports_resume": True,
    }
    with file_task_context.session() as session:
        task = session.get(file_task_context.FileTask, task_id)
        assert task.status == FileTaskStatus.COMPLETED
        assert task.chunk_size == expected_chunk_size


def test_local_upload_resumes_from_complete_chunk(file_task_context) -> None:
    from include.database.models.files import FileTaskStatus, TransferMode

    chunk_size = file_task_context.UPLOAD_TRANSFER_MIN_CHUNK_SIZE
    payload = b"r" * chunk_size + b"tail"
    sha256 = hashlib.sha256(payload).hexdigest()
    relative_path = "uploads/resumable-local.bin"
    task_id, file_id = _create_file_task(
        file_task_context, relative_path, mode=TransferMode.UPLOAD
    )

    first_stream = _DisconnectingUploadStream([payload[:chunk_size]])
    first_handler = _new_transfer_handler(
        file_task_context.ConnectionHandler, first_stream
    )
    first_handler.receive_file(task_id, len(payload), sha256, chunk_size, False)

    with file_task_context.session() as session:
        task = session.get(file_task_context.FileTask, task_id)
        assert task.status == FileTaskStatus.PENDING
        assert task.chunk_size == chunk_size
        assert task.upload_file_size == len(payload)
        assert task.upload_sha256 == sha256

    resumed_stream = _FakeUploadStream([payload[chunk_size:]])
    resumed_handler = _new_transfer_handler(
        file_task_context.ConnectionHandler, resumed_stream
    )
    resumed_handler.receive_file(task_id, len(payload), sha256, chunk_size, False)

    ready = _sent_json_messages(resumed_stream)[0]
    assert ready["data"]["offset"] == chunk_size
    with file_task_context.session() as session:
        task = session.get(file_task_context.FileTask, task_id)
        file = session.get(file_task_context.File, file_id)
        assert task.status == FileTaskStatus.COMPLETED
        assert file.active is True
    assert (
        file_task_context.connection.ProviderManager().storage.root / relative_path
    ).read_bytes() == payload


def test_upload_metadata_conflict_requires_explicit_restart(
    file_task_context,
) -> None:
    from include.database.models.files import FileTaskStatus, TransferMode

    chunk_size = file_task_context.UPLOAD_TRANSFER_MIN_CHUNK_SIZE
    original = b"a" * (chunk_size * 2)
    replacement = b"b" * chunk_size
    original_sha256 = hashlib.sha256(original).hexdigest()
    replacement_sha256 = hashlib.sha256(replacement).hexdigest()
    relative_path = "uploads/restarted-local.bin"
    task_id, _file_id = _create_file_task(
        file_task_context, relative_path, mode=TransferMode.UPLOAD
    )

    first_handler = _new_transfer_handler(
        file_task_context.ConnectionHandler,
        _DisconnectingUploadStream([original[:chunk_size]]),
    )
    first_handler.receive_file(
        task_id, len(original), original_sha256, chunk_size, False
    )

    conflict_stream = _FakeUploadStream([])
    conflict_handler = _new_transfer_handler(
        file_task_context.ConnectionHandler, conflict_stream
    )
    conflict_handler.receive_file(
        task_id,
        len(replacement),
        replacement_sha256,
        chunk_size,
        False,
    )
    response = _sent_json_messages(conflict_stream)[-1]
    assert response["code"] == 409
    assert response["data"] == {
        "file_size": len(original),
        "sha256": original_sha256,
        "chunk_size": chunk_size,
    }

    restart_stream = _FakeUploadStream([replacement])
    restart_handler = _new_transfer_handler(
        file_task_context.ConnectionHandler, restart_stream
    )
    restart_handler.receive_file(
        task_id,
        len(replacement),
        replacement_sha256,
        chunk_size,
        True,
    )
    assert _sent_json_messages(restart_stream)[0]["data"]["offset"] == 0
    with file_task_context.session() as session:
        task = session.get(file_task_context.FileTask, task_id)
        assert task.status == FileTaskStatus.COMPLETED
        assert task.chunk_size == chunk_size


def test_upload_without_digest_discards_disconnected_progress(
    file_task_context,
) -> None:
    from include.database.models.files import FileTaskStatus, TransferMode

    chunk_size = file_task_context.UPLOAD_TRANSFER_MIN_CHUNK_SIZE
    relative_path = "uploads/non-resumable-local.bin"
    task_id, _file_id = _create_file_task(
        file_task_context, relative_path, mode=TransferMode.UPLOAD
    )
    handler = _new_transfer_handler(
        file_task_context.ConnectionHandler,
        _DisconnectingUploadStream([b"x" * chunk_size]),
    )

    handler.receive_file(task_id, chunk_size * 2, None, chunk_size, False)

    with file_task_context.session() as session:
        task = session.get(file_task_context.FileTask, task_id)
        assert task.status == FileTaskStatus.PENDING
        assert task.chunk_size == chunk_size
        assert task.upload_file_size is None
        assert task.upload_sha256 is None
    assert not (
        file_task_context.connection.ProviderManager().storage.root / relative_path
    ).exists()


def test_upload_closes_resources_when_negotiation_send_fails(
    file_task_context, tmp_path, monkeypatch
) -> None:
    from include.database.models.files import FileTaskStatus, TransferMode

    class TrackingStorage(_FakeStorage):
        upload = None

        def open_resumable_upload(self, *args, **kwargs):
            self.upload = super().open_resumable_upload(*args, **kwargs)
            return self.upload

    relative_path = "uploads/disconnected-negotiation.bin"
    task_id, _file_id = _create_file_task(
        file_task_context, relative_path, mode=TransferMode.UPLOAD
    )
    storage = TrackingStorage(tmp_path)
    monkeypatch.setattr(
        file_task_context.connection,
        "ProviderManager",
        lambda: _FakeProviderManager(storage),
    )
    handler = _new_transfer_handler(
        file_task_context.ConnectionHandler, _FailingUploadNegotiationStream()
    )
    payload = b"a" * file_task_context.UPLOAD_TRANSFER_MIN_CHUNK_SIZE

    handler.receive_file(
        task_id,
        len(payload),
        hashlib.sha256(payload).hexdigest(),
        len(payload),
        False,
    )

    assert storage.upload is not None
    assert storage.upload._closed is True
    with file_task_context.session() as session:
        task = session.get(file_task_context.FileTask, task_id)
        assert task.status == FileTaskStatus.PENDING
        assert task.upload_sha256 == hashlib.sha256(payload).hexdigest()


def test_upload_persists_provider_checkpoint_on_disconnect(
    file_task_context, tmp_path, monkeypatch
) -> None:
    from include.database.models.files import FileTaskStatus, TransferMode
    from include.providers.storage.local import LocalResumableUpload

    class CheckpointingUpload(LocalResumableUpload):
        def __init__(self, path, file_size, chunk_size, checkpoint_callback):
            super().__init__(path, file_size, chunk_size)
            self._checkpoint_callback = checkpoint_callback

        def write(self, data):
            written = super().write(data)
            self.checkpoint_data = "authoritative-checkpoint"
            self._checkpoint_callback(self.checkpoint_data)
            return written

    class CheckpointingStorage(_FakeStorage):
        def open_resumable_upload(
            self,
            path,
            *,
            file_size,
            chunk_size,
            checkpoint_callback,
            **_kwargs,
        ):
            return CheckpointingUpload(
                str(self._resolve(path)),
                file_size,
                chunk_size,
                checkpoint_callback,
            )

    chunk_size = file_task_context.UPLOAD_TRANSFER_MIN_CHUNK_SIZE
    payload = b"a" * (chunk_size * 2)
    relative_path = "uploads/checkpointed-disconnect.bin"
    task_id, _file_id = _create_file_task(
        file_task_context, relative_path, mode=TransferMode.UPLOAD
    )
    storage = CheckpointingStorage(tmp_path)
    monkeypatch.setattr(
        file_task_context.connection,
        "ProviderManager",
        lambda: _FakeProviderManager(storage),
    )
    handler = _new_transfer_handler(
        file_task_context.ConnectionHandler,
        _DisconnectingUploadStream([payload[:chunk_size]]),
    )

    handler.receive_file(
        task_id,
        len(payload),
        hashlib.sha256(payload).hexdigest(),
        chunk_size,
        False,
    )

    with file_task_context.session() as session:
        task = session.get(file_task_context.FileTask, task_id)
        assert task.status == FileTaskStatus.PENDING
        assert task.upload_checkpoint_data == "authoritative-checkpoint"


def test_upload_rejects_client_limit_below_persisted_chunk_size(
    file_task_context,
) -> None:
    from include.database.models.files import FileTaskStatus, TransferMode

    relative_path = "uploads/chunk-size-conflict.bin"
    task_id, _file_id = _create_file_task(
        file_task_context, relative_path, mode=TransferMode.UPLOAD
    )
    with file_task_context.session.begin() as session:
        task = session.get(file_task_context.FileTask, task_id)
        task.chunk_size = 1024

    stream = _FakeUploadStream([])
    handler = _new_transfer_handler(file_task_context.ConnectionHandler, stream)
    handler.receive_file(
        task_id,
        1,
        hashlib.sha256(b"x").hexdigest(),
        512,
        False,
    )

    response = _sent_json_messages(stream)[-1]
    assert response["code"] == 409
    assert response["data"] == {"chunk_size": 1024}
    with file_task_context.session() as session:
        assert (
            session.get(file_task_context.FileTask, task_id).status
            == FileTaskStatus.PENDING
        )


def test_empty_upload_uses_structured_v21_response(file_task_context) -> None:
    from include.database.models.files import FileTaskStatus, TransferMode

    relative_path = "uploads/empty.bin"
    task_id, file_id = _create_file_task(
        file_task_context, relative_path, mode=TransferMode.UPLOAD
    )
    stream = _FakeUploadStream([])
    handler = _new_transfer_handler(file_task_context.ConnectionHandler, stream)

    handler.receive_file(
        task_id,
        0,
        None,
        file_task_context.UPLOAD_TRANSFER_MIN_CHUNK_SIZE,
        False,
    )

    ready, conclusion = _sent_json_messages(stream)
    assert ready["action"] == "transfer_file"
    assert ready["data"]["offset"] == 0
    assert ready["data"]["supports_resume"] is False
    assert conclusion["code"] == 200
    with file_task_context.session() as session:
        task = session.get(file_task_context.FileTask, task_id)
        file = session.get(file_task_context.File, file_id)
        assert task.status == FileTaskStatus.COMPLETED
        assert file.active is True
        assert file.size == 0
        assert file.sha256 is None


class TestFileTransfer:
    @pytest.mark.asyncio
    async def test_upload_and_download_file(
        self, authenticated_client: CFMSTestClient, document_factory, tmp_path
    ):
        doc = await document_factory(
            "File Transfer Test Doc", upload_file=None
        )  # Don't upload automatically
        doc_id = doc["document_id"]

        # 1. Start an upload task
        upload_resp = await authenticated_client.upload_document(doc_id)
        task_data = assert_success(upload_resp)["task_data"]
        upload_task_id = task_data["task_id"]

        # We will upload pyproject.toml as a test file
        test_file_path = "./pyproject.toml"
        original_hash = calculate_sha256(test_file_path)

        # 2. Upload file chunks over the stream
        await authenticated_client.upload_file_to_server(upload_task_id, test_file_path)

        # 3. Get the latest revision ID
        list_resp = await authenticated_client.list_revisions(doc_id)
        revisions = assert_success(list_resp)["items"]
        current_rev = next((r for r in revisions if r["is_current"]), None)
        assert current_rev is not None
        original_size = os.path.getsize(test_file_path)
        assert _get_revision_file_size(current_rev["id"]) == original_size

        _set_revision_file_size(current_rev["id"], 1)

        # 4. Prepare download
        get_rev_resp = await authenticated_client.get_revision(current_rev["id"])
        dl_task_id = assert_success(get_rev_resp)["task_data"]["task_id"]

        # 5. Download the file utilizing the new client download stream mechanism
        download_dest = str(tmp_path / "downloaded_test_file.toml")
        await authenticated_client.download_file_from_server(dl_task_id, download_dest)

        # 6. Verify checksum matches
        downloaded_hash = calculate_sha256(download_dest)
        assert original_hash == downloaded_hash
        assert original_size == os.path.getsize(download_dest)
        assert _get_revision_file_size(current_rev["id"]) == original_size
        assert _get_file_task_status(dl_task_id) == 1

    @pytest.mark.asyncio
    async def test_download_invalid_task_id_raises_runtime_error(
        self, authenticated_client: CFMSTestClient, tmp_path
    ):
        download_dest = str(tmp_path / "invalid_download.bin")

        with pytest.raises(
            RuntimeError, match=re.escape("Download failed (404): Task not found")
        ):
            await authenticated_client.download_file_from_server(
                "missing-download-task-id", download_dest
            )

    @pytest.mark.asyncio
    async def test_download_aborted_by_server_hook(
        self, authenticated_client: CFMSTestClient, monkeypatch, tmp_path
    ):
        class FakeFrame:
            def __init__(self, data):
                self.data = data

        class FakeStream:
            def __init__(self):
                self.sent_payloads = []
                self.responses = [
                    FakeFrame(b'{"action":"transfer_file"}'),
                    FakeFrame(b'{"action":"abort"}'),
                ]

            async def send(self, data):
                self.sent_payloads.append(data)

            async def recv(self):
                return self.responses.pop(0)

        fake_stream = FakeStream()
        monkeypatch.setattr(
            authenticated_client.multiplexer, "open_stream", lambda: fake_stream
        )

        dest = tmp_path / "aborted.bin"
        with pytest.raises(RuntimeError, match="Server aborted file transfer"):
            await authenticated_client.download_file_from_server(
                "fake-task-id", str(dest)
            )

        assert not dest.exists() or dest.stat().st_size == 0

    @pytest.mark.asyncio
    async def test_empty_download_confirms_completion(
        self, authenticated_client: CFMSTestClient, monkeypatch, tmp_path
    ):
        class FakeFrame:
            def __init__(self, data):
                self.data = data

        class FakeStream:
            def __init__(self):
                self.sent_payloads = []
                self.responses = [
                    FakeFrame(b'{"action":"transfer_file","data":{"file_size":0}}'),
                    FakeFrame(
                        b'{"action":"transfer_file","data":{"flag":"empty_file"}}'
                    ),
                    FakeFrame(b'{"action":"transfer_complete","data":{}}'),
                ]

            async def send(self, data):
                self.sent_payloads.append(data)

            async def recv(self):
                return self.responses.pop(0)

        fake_stream = FakeStream()
        monkeypatch.setattr(
            authenticated_client.multiplexer, "open_stream", lambda: fake_stream
        )

        dest = tmp_path / "empty-download.bin"
        await authenticated_client.download_file_from_server(
            "empty-download-task", str(dest)
        )

        assert dest.read_bytes() == b""
        assert fake_stream.sent_payloads[-2:] == [b"ready", b"complete"]

    @pytest.mark.asyncio
    async def test_upload_missing_source_file_raises_clear_error(
        self, authenticated_client: CFMSTestClient, document_factory
    ):
        doc = await document_factory("MissingUploadSourceDoc", upload_file=None)
        doc_id = doc["document_id"]

        upload_resp = await authenticated_client.upload_document(doc_id)
        upload_task_id = assert_success(upload_resp)["task_data"]["task_id"]

        with pytest.raises(FileNotFoundError, match="Upload source file not found"):
            await authenticated_client.upload_file_to_server(
                upload_task_id, "./does-not-exist-upload-source.bin"
            )


def test_empty_download_marks_file_task_completed(file_task_context, tmp_path):
    relative_path = "empty-download.bin"
    (tmp_path / relative_path).write_bytes(b"")
    task_id, file_id = _create_file_task(file_task_context, relative_path, mode=0)

    stream = _FakeDownloadStream()
    handler = _new_transfer_handler(file_task_context.ConnectionHandler, stream)

    handler.send_file(task_id, offset=0, max_chunk_size=64 * 1024)

    with file_task_context.session() as session:
        task = session.get(file_task_context.FileTask, task_id)
        file = session.get(file_task_context.File, file_id)

        assert task.status == 1
        assert task.encryption_key is None
        assert file.size == 0

    sent_messages = _sent_json_messages(stream)
    transfer_info, transfer_end, completion = sent_messages

    assert [message["action"] for message in sent_messages] == [
        "transfer_file",
        "transfer_file",
        "transfer_complete",
    ]
    assert transfer_info["data"]["file_size"] == 0
    assert transfer_info["data"]["total_chunks"] == 0
    assert transfer_end["data"] == {"flag": "empty_file"}
    assert completion["data"] == {}
    assert stream.sent_payloads[-1].frame_type == file_task_context.FrameType.CONCLUSION


def test_download_does_not_hold_db_session_while_waiting_for_client(
    file_task_context, monkeypatch, tmp_path
):
    from include.transport import connection as connection_handler

    relative_path = "download-without-open-session.bin"
    (tmp_path / relative_path).write_bytes(b"download payload")
    task_id, _file_id = _create_file_task(file_task_context, relative_path, mode=0)
    tracker = _TrackingSessionFactory(file_task_context.session)

    monkeypatch.setattr(connection_handler, "Session", tracker)

    stream = _AssertingDownloadStream(tracker)
    handler = _new_transfer_handler(file_task_context.ConnectionHandler, stream)

    handler.send_file(task_id, offset=0, max_chunk_size=64 * 1024)

    assert tracker.active == 0


def test_exact_chunk_upload_marks_file_task_completed(
    file_task_context,
):
    relative_path = "uploads/exact-chunk.bin"
    task_id, file_id = _create_file_task(file_task_context, relative_path, mode=1)
    chunk_size = file_task_context.UPLOAD_TRANSFER_MIN_CHUNK_SIZE
    payload = b"a" * (chunk_size * 2)
    stream = _FakeUploadStream(
        [
            payload[:chunk_size],
            payload[chunk_size:],
        ]
    )
    handler = _new_transfer_handler(file_task_context.ConnectionHandler, stream)

    handler.receive_file(
        task_id,
        len(payload),
        hashlib.sha256(payload).hexdigest(),
        chunk_size,
        False,
    )

    with file_task_context.session() as session:
        task = session.get(file_task_context.FileTask, task_id)
        file = session.get(file_task_context.File, file_id)
        assert task.status == 1
        assert file.active is True
        assert file.size == len(payload)

    sent_messages = _sent_json_messages(stream)
    assert any(
        message.get("code") == 200
        and message.get("message") == "File received successfully"
        for message in sent_messages
    )


def test_upload_does_not_hold_db_session_while_receiving_chunks(
    file_task_context, monkeypatch
):
    from include.transport import connection as connection_handler

    relative_path = "uploads/without-open-session.bin"
    task_id, _file_id = _create_file_task(file_task_context, relative_path, mode=1)
    tracker = _TrackingSessionFactory(file_task_context.session)
    chunk_size = file_task_context.UPLOAD_TRANSFER_MIN_CHUNK_SIZE
    payload = b"b" * (chunk_size + 1)

    monkeypatch.setattr(connection_handler, "Session", tracker)

    stream = _AssertingUploadStream(
        [
            payload[:chunk_size],
            payload[chunk_size:],
        ],
        tracker,
    )
    handler = _new_transfer_handler(file_task_context.ConnectionHandler, stream)

    handler.receive_file(
        task_id,
        len(payload),
        hashlib.sha256(payload).hexdigest(),
        chunk_size,
        False,
    )

    assert tracker.active == 0


def test_upload_confirms_before_releasing_deduplication(file_task_context, monkeypatch):
    context = file_task_context
    relative_path = "uploads/deferred-confirmation.bin"
    task_id, file_id = _create_file_task(context, relative_path, mode=1)
    payload = b"c" * context.UPLOAD_TRANSFER_MIN_CHUNK_SIZE
    stream = _FakeUploadStream([payload])
    handler = _new_transfer_handler(context.ConnectionHandler, stream)
    release_entered = threading.Event()
    allow_release = threading.Event()
    lifecycle = []

    def before_commit(session, id, **_kwargs):
        assert id == file_id
        lifecycle.append("before_commit")
        session.add(
            context.FileDeduplicationTask(
                file_id=id,
                phase=0,
                available_at=time.time() + 300,
                attempts=0,
                created_time=time.time(),
            )
        )

    def on_uploaded(**_kwargs):
        lifecycle.append("uploaded")
        assert not any(
            message.get("code") == 200 for message in _sent_json_messages(stream)
        )

    def after_response(id, **_kwargs):
        assert id == file_id
        lifecycle.append("after_response")
        assert any(
            message.get("code") == 200 for message in _sent_json_messages(stream)
        )
        release_entered.set()
        assert allow_release.wait(2)
        return True

    monkeypatch.setattr(
        context.connection,
        "pm",
        SimpleNamespace(
            hook=SimpleNamespace(
                ext_before_file_upload_commit=before_commit,
                ext_on_empty_file_uploaded=lambda **_kwargs: None,
                ext_on_file_uploaded=on_uploaded,
                ext_post_file_upload_response=after_response,
            )
        ),
    )

    transfer_thread = threading.Thread(
        target=handler.receive_file,
        args=(
            task_id,
            len(payload),
            hashlib.sha256(payload).hexdigest(),
            context.UPLOAD_TRANSFER_MIN_CHUNK_SIZE,
            False,
        ),
    )
    transfer_thread.start()
    assert release_entered.wait(2)
    assert transfer_thread.is_alive()
    assert any(message.get("code") == 200 for message in _sent_json_messages(stream))
    allow_release.set()
    transfer_thread.join(2)
    assert not transfer_thread.is_alive()
    assert lifecycle == ["before_commit", "uploaded", "after_response"]

    with context.session() as session:
        assert session.get(context.FileDeduplicationTask, file_id) is not None


def test_upload_hook_write_rolls_back_with_completion(file_task_context, monkeypatch):
    context = file_task_context
    relative_path = "uploads/commit-hook-rollback.bin"
    task_id, file_id = _create_file_task(context, relative_path, mode=1)
    payload = b"r" * context.UPLOAD_TRANSFER_MIN_CHUNK_SIZE
    stream = _FakeUploadStream([payload])
    handler = _new_transfer_handler(context.ConnectionHandler, stream)

    def fail_before_commit(session, id, **_kwargs):
        session.add(
            context.FileDeduplicationTask(
                file_id=id,
                phase=0,
                available_at=time.time() + 300,
                attempts=0,
                created_time=time.time(),
            )
        )
        session.flush()
        raise RuntimeError("commit hook failure")

    monkeypatch.setattr(
        context.connection,
        "pm",
        SimpleNamespace(
            hook=SimpleNamespace(
                ext_before_file_upload_commit=fail_before_commit,
                ext_on_empty_file_uploaded=lambda **_kwargs: None,
                ext_on_file_uploaded=lambda **_kwargs: None,
                ext_post_file_upload_response=lambda **_kwargs: None,
            )
        ),
    )
    monkeypatch.setattr(
        handler,
        "report_error",
        lambda _error, **_kwargs: handler.conclude_request(
            500, {}, "commit hook failure"
        ),
    )

    handler.receive_file(
        task_id,
        len(payload),
        hashlib.sha256(payload).hexdigest(),
        context.UPLOAD_TRANSFER_MIN_CHUNK_SIZE,
        False,
    )

    assert [
        response["code"]
        for response in _sent_json_messages(stream)
        if "code" in response
    ] == [500]
    with context.session() as session:
        file = session.get(context.File, file_id)
        task = session.get(context.FileTask, task_id)
        assert file.active is False
        assert file.sha256 is None
        assert task.status == 0
        assert session.get(context.FileDeduplicationTask, file_id) is None


def test_post_upload_response_hook_failure_does_not_send_second_response(
    file_task_context, monkeypatch
):
    context = file_task_context
    relative_path = "uploads/post-response-failure.bin"
    task_id, _file_id = _create_file_task(context, relative_path, mode=1)
    payload = b"p" * context.UPLOAD_TRANSFER_MIN_CHUNK_SIZE
    stream = _FakeUploadStream([payload])
    handler = _new_transfer_handler(context.ConnectionHandler, stream)
    reported = []

    def fail_after_response(**_kwargs):
        raise RuntimeError("post-upload failure")

    monkeypatch.setattr(
        context.connection,
        "pm",
        SimpleNamespace(
            hook=SimpleNamespace(
                ext_before_file_upload_commit=lambda **_kwargs: None,
                ext_on_empty_file_uploaded=lambda **_kwargs: None,
                ext_on_file_uploaded=lambda **_kwargs: None,
                ext_post_file_upload_response=fail_after_response,
            )
        ),
    )
    monkeypatch.setattr(
        handler,
        "report_error",
        lambda error, **kwargs: reported.append((error, kwargs)),
    )

    handler.receive_file(
        task_id,
        len(payload),
        hashlib.sha256(payload).hexdigest(),
        context.UPLOAD_TRANSFER_MIN_CHUNK_SIZE,
        False,
    )

    responses = _sent_json_messages(stream)
    assert [response["code"] for response in responses if "code" in response] == [200]
    assert len(reported) == 1
    assert str(reported[0][0]) == "post-upload failure"
    assert reported[0][1]["send_to_client"] is False


def test_duplicate_and_unique_upload_confirmation_p95_are_close(file_task_context):
    context = file_task_context
    chunk_size = context.UPLOAD_TRANSFER_MIN_CHUNK_SIZE

    def upload_once(label, index, payload):
        relative_path = f"uploads/latency-{label}-{index}.bin"
        task_id, _file_id = _create_file_task(context, relative_path, mode=1)
        stream = _FakeUploadStream([payload])
        handler = _new_transfer_handler(context.ConnectionHandler, stream)
        started = time.perf_counter()
        handler.receive_file(
            task_id,
            len(payload),
            hashlib.sha256(payload).hexdigest(),
            chunk_size,
            False,
        )
        elapsed = time.perf_counter() - started
        assert any(
            message.get("code") == 200 for message in _sent_json_messages(stream)
        )
        return elapsed

    for index in range(5):
        upload_once("warmup", index, bytes([index]) * chunk_size)

    duplicate_payload = b"d" * chunk_size
    duplicate_times = [
        upload_once("duplicate", index, duplicate_payload) for index in range(30)
    ]
    unique_times = [
        upload_once("unique", index, bytes([index]) * chunk_size) for index in range(30)
    ]

    p95_index = 28
    duplicate_p95 = sorted(duplicate_times)[p95_index]
    unique_p95 = sorted(unique_times)[p95_index]
    assert abs(duplicate_p95 - unique_p95) <= max(0.1, unique_p95 * 0.1)
