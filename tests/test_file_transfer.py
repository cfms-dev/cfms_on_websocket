import hashlib
import os
import re
import shutil
import sqlite3
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import orjson
import pytest
from sqlalchemy import Table, create_engine
from sqlalchemy.orm import sessionmaker

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


class _FakeFrame:
    def __init__(self, data):
        self.data = data


@dataclass
class _SentPayload:
    data: object
    frame_type: object = None


class _FakeLogger:
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
        os.remove(self._resolve(path))


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
        self.responses = [_FakeFrame(b"ready")]

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


def _new_transfer_handler(connection_handler_cls, stream):
    handler = connection_handler_cls.__new__(connection_handler_cls)
    handler.stream = stream
    handler.logger = _FakeLogger()
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
    from include.config.constants import FILE_TRANSFER_MIN_CHUNK_SIZE
    from include.database.models.files import File, FileTask
    from include.database.session import Base
    from include.transport.multiplexing import FrameType

    engine = create_engine(f"sqlite:///{tmp_path / 'file_tasks.db'}")
    Base.metadata.create_all(
        engine, tables=[cast(Table, File.__table__), cast(Table, FileTask.__table__)]
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
                ext_on_empty_file_uploaded=lambda **_kwargs: None,
                ext_on_file_uploaded=lambda **_kwargs: None,
            )
        ),
    )

    return SimpleNamespace(
        session=TestingSession,
        ConnectionHandler=connection_handler.ConnectionHandler,
        FrameType=FrameType,
        File=File,
        FileTask=FileTask,
        FILE_TRANSFER_MIN_CHUNK_SIZE=FILE_TRANSFER_MIN_CHUNK_SIZE,
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
        hard_deadline = claimed.end_time
        assert claimed.status == FileTaskStatus.IN_PROGRESS
        assert claimed.start_time == 1000.0

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
        assert claimed.start_time == 1000.0
        assert claimed.end_time == hard_deadline
        assert file_tasks.complete_file_task(session, task_id) is True
        assert file_tasks.complete_file_task(session, task_id) is False


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


def test_transfer_claim_race_reports_expired_status(file_task_context) -> None:
    from include.database.models.files import FileTaskStatus, TransferMode

    task_id, _file_id = _create_file_task(
        file_task_context, "expired-download.bin", mode=TransferMode.DOWNLOAD
    )
    with file_task_context.session.begin() as session:
        session.get(file_task_context.FileTask, task_id).end_time = 1.0

    stream = _FakeDownloadStream()
    handler = _new_transfer_handler(file_task_context.ConnectionHandler, stream)
    handler.send_file(task_id, offset=0)

    response = _sent_json_messages(stream)[-1]
    assert response["code"] == 410
    assert response["data"] == {"task_status": "expired"}
    with file_task_context.session() as session:
        assert (
            session.get(file_task_context.FileTask, task_id).status
            == FileTaskStatus.EXPIRED
        )


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

    handler.send_file(task_id, offset=0)

    with file_task_context.session() as session:
        task = session.get(file_task_context.FileTask, task_id)
        file = session.get(file_task_context.File, file_id)

        assert task.status == 1
        assert task.encryption_key is None
        assert file.size == 0

    sent_messages = _sent_json_messages(stream)
    transfer_info, transfer_end = sent_messages

    assert [message["action"] for message in sent_messages] == [
        "transfer_file",
        "transfer_file",
    ]
    assert transfer_info["data"]["file_size"] == 0
    assert transfer_info["data"]["total_chunks"] == 0
    assert transfer_end["data"] == {"flag": "empty_file"}
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

    handler.send_file(task_id, offset=0)

    assert tracker.active == 0


def test_exact_chunk_upload_marks_file_task_completed(
    file_task_context,
):
    relative_path = "uploads/exact-chunk.bin"
    task_id, file_id = _create_file_task(file_task_context, relative_path, mode=1)
    chunk_size = file_task_context.FILE_TRANSFER_MIN_CHUNK_SIZE
    payload = b"a" * (chunk_size * 2)
    transfer_request = orjson.dumps(
        {
            "action": "transfer_file",
            "data": {
                "sha256": hashlib.sha256(payload).hexdigest(),
                "file_size": len(payload),
                "max_chunk_size": chunk_size,
            },
        }
    )
    stream = _FakeUploadStream(
        [
            transfer_request,
            payload[:chunk_size],
            payload[chunk_size:],
        ]
    )
    handler = _new_transfer_handler(file_task_context.ConnectionHandler, stream)

    handler.receive_file(task_id)

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
    chunk_size = file_task_context.FILE_TRANSFER_MIN_CHUNK_SIZE
    payload = b"b" * (chunk_size + 1)
    transfer_request = orjson.dumps(
        {
            "action": "transfer_file",
            "data": {
                "sha256": hashlib.sha256(payload).hexdigest(),
                "file_size": len(payload),
                "max_chunk_size": chunk_size,
            },
        }
    )

    monkeypatch.setattr(connection_handler, "Session", tracker)

    stream = _AssertingUploadStream(
        [
            transfer_request,
            payload[:chunk_size],
            payload[chunk_size:],
        ],
        tracker,
    )
    handler = _new_transfer_handler(file_task_context.ConnectionHandler, stream)

    handler.receive_file(task_id)

    assert tracker.active == 0
