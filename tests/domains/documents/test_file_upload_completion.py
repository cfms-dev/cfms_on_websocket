import hashlib
import threading
import time
from types import SimpleNamespace

from tests.domains.documents.test_file_task_lifecycle import (
    _create_file_task,
    _FakeUploadStream,
    _new_transfer_handler,
    _sent_json_messages,
)


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
                ext_before_file_upload_finalize=before_commit,
                ext_on_file_upload_completed=after_response,
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
    assert lifecycle == ["before_commit", "after_response"]

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
                ext_before_file_upload_finalize=fail_before_commit,
                ext_on_file_upload_completed=lambda **_kwargs: None,
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
                ext_before_file_upload_finalize=lambda **_kwargs: None,
                ext_on_file_upload_completed=fail_after_response,
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
