import hashlib

import pytest

from tests.domains.documents.test_file_task_lifecycle import (
    _create_file_task,
    _DisconnectBeforeCompletionStream,
    _DisconnectingUploadStream,
    _FailingUploadNegotiationStream,
    _FakeDownloadStream,
    _FakeProviderManager,
    _FakeStorage,
    _FakeUploadStream,
    _new_transfer_handler,
    _sent_json_messages,
)


class _NonResumableStorage(_FakeStorage):
    supports_resumable_uploads = False

    def open_resumable_upload(self, *args, **kwargs):
        raise AssertionError("resumable upload API must not be used")


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


def test_non_resumable_storage_completes_upload_from_zero(
    file_task_context, tmp_path, monkeypatch
) -> None:
    from include.database.models.files import FileTaskStatus, TransferMode

    chunk_size = file_task_context.UPLOAD_TRANSFER_MIN_CHUNK_SIZE
    payload = b"n" * (chunk_size + 1)
    relative_path = "uploads/non-resumable-provider.bin"
    task_id, file_id = _create_file_task(
        file_task_context, relative_path, mode=TransferMode.UPLOAD
    )
    storage = _NonResumableStorage(tmp_path)
    monkeypatch.setattr(
        file_task_context.connection,
        "ProviderManager",
        lambda: _FakeProviderManager(storage),
    )
    stream = _FakeUploadStream([payload[:chunk_size], payload[chunk_size:]])
    handler = _new_transfer_handler(file_task_context.ConnectionHandler, stream)

    handler.receive_file(
        task_id,
        len(payload),
        hashlib.sha256(payload).hexdigest(),
        chunk_size,
        False,
    )

    ready = _sent_json_messages(stream)[0]
    assert ready["data"]["offset"] == 0
    assert ready["data"]["supports_resume"] is False
    assert (tmp_path / relative_path).read_bytes() == payload
    with file_task_context.session() as session:
        task = session.get(file_task_context.FileTask, task_id)
        file = session.get(file_task_context.File, file_id)
        assert task.status == FileTaskStatus.COMPLETED
        assert task.upload_session_id is None
        assert task.upload_checkpoint_data is None
        assert file.active is True


def test_non_resumable_storage_discards_disconnect_and_retries_from_zero(
    file_task_context, tmp_path, monkeypatch
) -> None:
    from include.database.models.files import FileTaskStatus, TransferMode

    chunk_size = file_task_context.UPLOAD_TRANSFER_MIN_CHUNK_SIZE
    payload = b"r" * (chunk_size * 2)
    relative_path = "uploads/non-resumable-retry.bin"
    task_id, _file_id = _create_file_task(
        file_task_context, relative_path, mode=TransferMode.UPLOAD
    )
    storage = _NonResumableStorage(tmp_path)
    monkeypatch.setattr(
        file_task_context.connection,
        "ProviderManager",
        lambda: _FakeProviderManager(storage),
    )

    first_handler = _new_transfer_handler(
        file_task_context.ConnectionHandler,
        _DisconnectingUploadStream([payload[:chunk_size]]),
    )
    first_handler.receive_file(
        task_id,
        len(payload),
        hashlib.sha256(payload).hexdigest(),
        chunk_size,
        False,
    )

    assert not (tmp_path / relative_path).exists()
    with file_task_context.session() as session:
        task = session.get(file_task_context.FileTask, task_id)
        assert task.status == FileTaskStatus.PENDING
        assert task.upload_file_size is None
        assert task.upload_sha256 is None
        assert task.upload_session_id is None
        assert task.upload_checkpoint_size is None
        assert task.upload_checkpoint_data is None

    retry_stream = _FakeUploadStream([payload[:chunk_size], payload[chunk_size:]])
    retry_handler = _new_transfer_handler(
        file_task_context.ConnectionHandler, retry_stream
    )
    retry_handler.receive_file(
        task_id,
        len(payload),
        hashlib.sha256(payload).hexdigest(),
        chunk_size,
        False,
    )

    assert _sent_json_messages(retry_stream)[0]["data"]["offset"] == 0
    assert (tmp_path / relative_path).read_bytes() == payload


def test_non_resumable_storage_discards_stale_resumable_metadata(
    file_task_context, tmp_path, monkeypatch
) -> None:
    from include.database.models.files import FileTaskStatus, TransferMode

    chunk_size = file_task_context.UPLOAD_TRANSFER_MIN_CHUNK_SIZE
    stale_payload = b"s" * chunk_size
    replacement = b"f" * chunk_size
    relative_path = "uploads/non-resumable-stale-progress.bin"
    task_id, _file_id = _create_file_task(
        file_task_context, relative_path, mode=TransferMode.UPLOAD
    )
    storage = _NonResumableStorage(tmp_path)
    storage.makedirs("uploads", exist_ok=True)
    (tmp_path / relative_path).write_bytes(stale_payload)
    with file_task_context.session.begin() as session:
        task = session.get(file_task_context.FileTask, task_id)
        task.chunk_size = chunk_size
        task.upload_file_size = chunk_size * 2
        task.upload_sha256 = hashlib.sha256(stale_payload * 2).hexdigest()
        task.upload_session_id = "stale-session"
        task.upload_checkpoint_size = chunk_size
        task.upload_checkpoint_data = "stale-checkpoint"
    monkeypatch.setattr(
        file_task_context.connection,
        "ProviderManager",
        lambda: _FakeProviderManager(storage),
    )
    stream = _FakeUploadStream([replacement])
    handler = _new_transfer_handler(file_task_context.ConnectionHandler, stream)

    handler.receive_file(
        task_id,
        len(replacement),
        hashlib.sha256(replacement).hexdigest(),
        chunk_size,
        False,
    )

    ready = _sent_json_messages(stream)[0]
    assert ready["action"] == "transfer_file"
    assert ready["data"]["offset"] == 0
    assert ready["data"]["supports_resume"] is False
    assert (tmp_path / relative_path).read_bytes() == replacement
    with file_task_context.session() as session:
        task = session.get(file_task_context.FileTask, task_id)
        assert task.status == FileTaskStatus.COMPLETED
        assert task.upload_session_id is None
        assert task.upload_checkpoint_size is None
        assert task.upload_checkpoint_data is None


def test_non_resumable_storage_rejects_invalid_chunk_without_retaining_progress(
    file_task_context, tmp_path, monkeypatch
) -> None:
    from include.database.models.files import FileTaskStatus, TransferMode

    chunk_size = file_task_context.UPLOAD_TRANSFER_MIN_CHUNK_SIZE
    relative_path = "uploads/non-resumable-invalid-chunk.bin"
    task_id, _file_id = _create_file_task(
        file_task_context, relative_path, mode=TransferMode.UPLOAD
    )
    storage = _NonResumableStorage(tmp_path)
    monkeypatch.setattr(
        file_task_context.connection,
        "ProviderManager",
        lambda: _FakeProviderManager(storage),
    )
    stream = _FakeUploadStream([b"short"])
    handler = _new_transfer_handler(file_task_context.ConnectionHandler, stream)

    handler.receive_file(
        task_id,
        chunk_size * 2,
        hashlib.sha256(b"x" * (chunk_size * 2)).hexdigest(),
        chunk_size,
        False,
    )

    response = _sent_json_messages(stream)[-1]
    assert response["code"] == 400
    assert response["data"] == {"offset": 0}
    assert not (tmp_path / relative_path).exists()
    with file_task_context.session() as session:
        task = session.get(file_task_context.FileTask, task_id)
        assert task.status == FileTaskStatus.PENDING
        assert task.upload_file_size is None
        assert task.upload_sha256 is None


def test_non_resumable_storage_discards_progress_on_timeout(
    file_task_context, tmp_path, monkeypatch
) -> None:
    from include.database.models.files import FileTaskStatus, TransferMode

    chunk_size = file_task_context.UPLOAD_TRANSFER_MIN_CHUNK_SIZE
    payload = b"t" * (chunk_size * 2)
    relative_path = "uploads/non-resumable-timeout.bin"
    task_id, _file_id = _create_file_task(
        file_task_context, relative_path, mode=TransferMode.UPLOAD
    )
    storage = _NonResumableStorage(tmp_path)
    monkeypatch.setattr(
        file_task_context.connection,
        "ProviderManager",
        lambda: _FakeProviderManager(storage),
    )
    stream = _FakeUploadStream([payload[:chunk_size]])
    handler = _new_transfer_handler(file_task_context.ConnectionHandler, stream)
    receive_count = 0

    def receive_frame(*_args):
        nonlocal receive_count
        receive_count += 1
        if receive_count == 1:
            return stream.recv()
        raise TimeoutError("upload timed out")

    monkeypatch.setattr(handler, "_recv_file_task_frame", receive_frame)

    handler.receive_file(
        task_id,
        len(payload),
        hashlib.sha256(payload).hexdigest(),
        chunk_size,
        False,
    )

    response = _sent_json_messages(stream)[-1]
    assert response["code"] == 408
    assert not (tmp_path / relative_path).exists()
    with file_task_context.session() as session:
        task = session.get(file_task_context.FileTask, task_id)
        assert task.status == FileTaskStatus.PENDING
        assert task.upload_file_size is None
        assert task.upload_sha256 is None


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
