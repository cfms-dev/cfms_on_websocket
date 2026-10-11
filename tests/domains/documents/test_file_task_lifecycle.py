import hashlib
import time
from dataclasses import FrozenInstanceError
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from tests.domains.documents.support import (
    _create_file_task,
    _FakeDownloadStream,
    _FakeUploadStream,
    _new_transfer_handler,
    _sent_json_messages,
)


@pytest.mark.component
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


@pytest.mark.component
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


@pytest.mark.component
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


@pytest.mark.component
def test_upload_task_lifecycle_uses_two_stage_deadline(file_task_context) -> None:
    from include.database.models.files import FileTaskStatus, TransferMode
    from include.domains.documents.commands import file_tasks

    task_id, _file_id = _create_file_task(
        file_task_context, "uploads/lifecycle.bin", mode=TransferMode.UPLOAD
    )
    with file_task_context.session.begin() as session:
        task = session.get(file_task_context.FileTask, task_id)
        task.start_time = 900.0
        task.end_time = 4500.0

    with file_task_context.session.begin() as session:
        claimed = file_tasks.claim_file_task(
            session, task_id, TransferMode.UPLOAD, now=1000.0
        )
        assert isinstance(claimed, file_tasks.ClaimedFileTask)

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
        assert isinstance(claimed, file_tasks.ClaimedFileTask)
        assert (
            file_tasks.complete_file_task(session, task_id)
            == file_tasks.FileTaskStatus.COMPLETED
        )
        assert (
            file_tasks.complete_file_task(session, task_id)
            == file_tasks.FileTaskStatus.COMPLETED
        )

    with file_task_context.session() as session:
        task = session.get(file_task_context.FileTask, task_id)
        assert task.start_time == 1000.0
        assert task.end_time == hard_deadline


@pytest.mark.component
def test_claim_returns_read_only_transfer_snapshot(file_task_context) -> None:
    from include.database.models.files import FileTaskStatus, TransferMode
    from include.domains.documents.commands.file_tasks import (
        ClaimedFileTask,
        claim_file_task,
    )

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

    assert isinstance(claimed, ClaimedFileTask)
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


@pytest.mark.component
def test_claim_rejects_invalid_or_competing_requests(file_task_context) -> None:
    from include.database.models.files import FileTaskStatus, TransferMode
    from include.domains.documents.commands.file_tasks import (
        ClaimedFileTask,
        FileTaskClaimFailure,
        claim_file_task,
    )

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
            == FileTaskClaimFailure.INVALID
        )
        assert (
            claim_file_task(session, upload_task_id, TransferMode.DOWNLOAD, now=100.0)
            == FileTaskClaimFailure.INVALID
        )
        assert (
            claim_file_task(session, future_task_id, TransferMode.UPLOAD, now=100.0)
            == FileTaskClaimFailure.INVALID
        )
        assert isinstance(
            claim_file_task(session, upload_task_id, TransferMode.UPLOAD, now=100.0),
            ClaimedFileTask,
        )
        assert (
            claim_file_task(session, upload_task_id, TransferMode.UPLOAD, now=100.0)
            == FileTaskClaimFailure.IN_PROGRESS
        )

    with file_task_context.session() as session:
        assert (
            session.get(file_task_context.FileTask, upload_task_id).status
            == FileTaskStatus.IN_PROGRESS
        )


@pytest.mark.component
def test_claim_marks_due_task_expired(file_task_context) -> None:
    from include.database.models.files import FileTaskStatus, TransferMode
    from include.domains.documents.commands.file_tasks import (
        FileTaskClaimFailure,
        claim_file_task,
    )

    task_id, _file_id = _create_file_task(
        file_task_context, "uploads/expired.bin", mode=TransferMode.UPLOAD
    )
    with file_task_context.session.begin() as session:
        task = session.get(file_task_context.FileTask, task_id)
        task.end_time = 10.0

    with file_task_context.session.begin() as session:
        assert (
            claim_file_task(session, task_id, TransferMode.UPLOAD, now=11.0)
            == FileTaskClaimFailure.EXPIRED
        )

    with file_task_context.session() as session:
        assert (
            session.get(file_task_context.FileTask, task_id).status
            == FileTaskStatus.EXPIRED
        )


@pytest.mark.component
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


@pytest.mark.component
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
    assert response["code"] == 46004
    assert response["data"] == {"task_status": "expired", "retryable": False}
    with file_task_context.session() as session:
        assert (
            session.get(file_task_context.FileTask, task_id).status
            == FileTaskStatus.EXPIRED
        )


@pytest.mark.component
def test_missing_transfer_task_reports_non_enumerable_invalid_status(
    file_task_context,
) -> None:
    stream = _FakeDownloadStream()
    handler = _new_transfer_handler(file_task_context.ConnectionHandler, stream)

    handler.send_file("missing-task", offset=0, max_chunk_size=64 * 1024)

    response = _sent_json_messages(stream)[-1]
    assert response["code"] == 46000
    assert response["data"] == {"retryable": False}
    with file_task_context.session() as session:
        assert session.query(file_task_context.RateLimitBucket).count() == 0


@pytest.mark.component
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


@pytest.mark.component
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
    assert response["code"] == 46001
    assert response["data"] == {"task_status": "in_progress", "retryable": True}


@pytest.mark.component
def test_concurrent_download_reports_in_progress(file_task_context) -> None:
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
    assert response["code"] == 46001
    assert response["data"] == {"task_status": "in_progress", "retryable": True}
    with file_task_context.session() as session:
        assert session.query(file_task_context.RateLimitBucket).count() == 0


@pytest.mark.component
def test_claim_state_race_reports_retryable_conflict(
    file_task_context, monkeypatch
) -> None:
    from include.domains.documents.commands.file_tasks import FileTaskClaimFailure

    monkeypatch.setattr(
        file_task_context.connection,
        "claim_file_task",
        lambda _session, _task_id, _mode: FileTaskClaimFailure.CONFLICT,
    )
    stream = _FakeDownloadStream()
    handler = _new_transfer_handler(file_task_context.ConnectionHandler, stream)

    handler.send_file("racing-task", offset=0, max_chunk_size=64 * 1024)

    response = _sent_json_messages(stream)[-1]
    assert response["code"] == 46005
    assert response["data"] == {"retryable": True}


@pytest.mark.component
def test_wrong_mode_and_future_task_do_not_disclose_claim_details(
    file_task_context,
) -> None:
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
        assert response["code"] == 46000
        assert response["data"] == {"retryable": False}


@pytest.mark.component
@pytest.mark.parametrize(
    ("status", "expected_code", "expected_status"),
    [
        (1, 46002, "completed"),
        (2, 46003, "cancelled"),
    ],
)
def test_terminal_transfer_task_reports_specific_status(
    file_task_context, status, expected_code, expected_status
) -> None:
    from include.database.models.files import TransferMode

    task_id, _file_id = _create_file_task(
        file_task_context,
        f"{expected_status}-download.bin",
        mode=TransferMode.DOWNLOAD,
        status=status,
    )
    stream = _FakeDownloadStream()
    handler = _new_transfer_handler(file_task_context.ConnectionHandler, stream)

    handler.send_file(task_id, offset=0, max_chunk_size=64 * 1024)

    response = _sent_json_messages(stream)[-1]
    assert response["code"] == expected_code
    assert response["data"] == {
        "task_status": expected_status,
        "retryable": False,
    }


@pytest.mark.unit
def test_download_request_passes_offset_and_chunk_size_to_transfer() -> None:
    from include.domains.documents.handlers.documents import RequestDownloadFileHandler

    transfers = []
    handler = SimpleNamespace(
        data={"task_id": "task", "offset": 64, "max_chunk_size": 32 * 1024},
        send_file=lambda task_id, offset, max_chunk_size: transfers.append(
            (task_id, offset, max_chunk_size)
        ),
    )

    RequestDownloadFileHandler().handle(handler)

    assert transfers == [("task", 64, 32 * 1024)]


@pytest.mark.unit
def test_upload_request_normalizes_digest_and_passes_transfer_metadata() -> None:
    from include.domains.documents.handlers.documents import RequestUploadFileHandler

    transfers = []
    handler = SimpleNamespace(
        data={
            "task_id": "task",
            "file_size": 1,
            "sha256": "A" * 64,
            "max_chunk_size": 32 * 1024,
            "restart": True,
        },
        receive_file=lambda *args: transfers.append(args),
    )

    RequestUploadFileHandler().handle(handler)

    assert transfers == [("task", 1, "a" * 64, 32 * 1024, True)]


@pytest.mark.unit
@pytest.mark.parametrize(
    "request_data",
    [
        pytest.param({"task_id": "task"}, id="missing-chunk-size"),
        pytest.param(
            {"task_id": "task", "max_chunk_size": 8 * 1024},
            id="below-minimum",
        ),
        pytest.param(
            {"task_id": "task", "max_chunk_size": 4 * 1024 * 1024},
            id="above-maximum",
        ),
    ],
)
def test_download_request_rejects_missing_or_unbounded_chunk_size(request_data) -> None:
    from include.domains.documents.handlers.documents import RequestDownloadFileHandler

    with pytest.raises(ValidationError) as excinfo:
        RequestDownloadFileHandler.request_model.model_validate(request_data)

    assert {error["loc"] for error in excinfo.value.errors()} == {("max_chunk_size",)}


@pytest.mark.unit
def test_upload_request_accepts_required_transfer_metadata() -> None:
    from include.domains.documents.handlers.documents import RequestUploadFileHandler

    request_data = {
        "task_id": "task",
        "file_size": 1,
        "sha256": "a" * 64,
        "max_chunk_size": 512,
    }

    request = RequestUploadFileHandler.request_model.model_validate(request_data)

    assert request.model_dump(exclude_unset=True) == request_data


@pytest.mark.unit
@pytest.mark.parametrize(
    ("request_data", "error_fields"),
    [
        pytest.param(
            {"task_id": "task"},
            {("file_size",), ("sha256",), ("max_chunk_size",)},
            id="missing-transfer-metadata",
        ),
        pytest.param(
            {
                "task_id": "task",
                "file_size": 1,
                "sha256": "not-a-digest",
                "max_chunk_size": 512,
            },
            {("sha256",)},
            id="invalid-digest",
        ),
    ],
)
def test_upload_request_rejects_invalid_transfer_metadata(
    request_data, error_fields
) -> None:
    from include.domains.documents.handlers.documents import RequestUploadFileHandler

    with pytest.raises(ValidationError) as excinfo:
        RequestUploadFileHandler.request_model.model_validate(request_data)

    assert {error["loc"] for error in excinfo.value.errors()} == error_fields
