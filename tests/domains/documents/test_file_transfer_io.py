import hashlib
import os
import re

import pytest

from tests.domains.documents.test_file_task_lifecycle import (
    _AssertingDownloadStream,
    _AssertingUploadStream,
    _create_file_task,
    _FakeDownloadStream,
    _FakeUploadStream,
    _get_file_task_status,
    _get_revision_file_size,
    _new_transfer_handler,
    _sent_json_messages,
    _set_revision_file_size,
    _TrackingSessionFactory,
)
from tests.support.client import CFMSTestClient, calculate_sha256
from tests.support.utils import assert_success


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
            RuntimeError,
            match=re.escape("Download failed (46000): Task cannot be claimed"),
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
