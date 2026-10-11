import os
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

import orjson
import pytest
from sqlalchemy.orm import sessionmaker
from websockets.exceptions import ConnectionClosed


def _get_revision_file_size(database_path: Path, revision_id: str) -> int | None:
    with sqlite3.connect(database_path) as connection:
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


def _set_revision_file_size(database_path: Path, revision_id: str, size: int) -> None:
    with sqlite3.connect(database_path) as connection:
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


def _get_file_task_status(database_path: Path, task_id: str) -> int | None:
    with sqlite3.connect(database_path) as connection:
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
def file_task_context(monkeypatch, tmp_path, sqlite_engine_factory):
    import include.database.models  # noqa: F401
    import include.transport.connection as connection_handler
    from include.config.constants import UPLOAD_TRANSFER_MIN_CHUNK_SIZE
    from include.database.models.files import File, FileDeduplicationTask, FileTask
    from include.database.models.identity import User
    from include.database.models.operations import RateLimitBucket
    from include.database.session import Base
    from include.extensions.builtin.file_deduplication import (
        schedule_file_deduplication,
    )
    from include.transport.multiplexing import FrameType

    engine = sqlite_engine_factory(tmp_path / "file_tasks.db")
    Base.metadata.create_all(engine)
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
