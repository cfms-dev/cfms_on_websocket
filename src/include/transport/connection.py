import base64
import hashlib
import os
import threading
import time

import jsonschema
import orjson
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from loguru import logger as log
from websockets.exceptions import (
    ConnectionClosed,
    ConnectionClosedError,
)
from websockets.typing import Data

from include.config.constants import (
    DOWNLOAD_TRANSFER_MAX_CHUNK_SIZE,
    GLOBAL_BROADCAST_EVENT_CHANNEL,
    UPLOAD_TRANSFER_MAX_CHUNK_SIZE,
)
from include.config.settings import global_config
from include.config.validation import DocumentUploadPolicy
from include.database.models.files import File, FileTask, FileTaskStatus, TransferMode
from include.database.models.identity import User
from include.database.session import Session
from include.domains.access.permissions import Permissions
from include.domains.documents.commands.file_tasks import (
    ClaimedFileTask,
    claim_file_task,
    complete_file_task,
    expire_file_task_if_due,
    release_file_task,
)
from include.domains.documents.download_limits import (
    DownloadLimitDecision,
    check_download_transfer_limits,
)
from include.domains.documents.file_task_signals import watch_file_task
from include.extensions.manager import pm
from include.messages import Messages as smsg
from include.observability.exception_logging import log_exception_with_id
from include.providers.base import ResumableUploadSizeError
from include.providers.manager import ProviderManager
from include.transport.client_address import get_client_ip
from include.transport.multiplexing import FrameType, Stream

logger = log.bind(name="conn")


def _negotiate_file_chunk_size(
    client_max_chunk_size: int | None,
    *,
    configured_chunk_size: int,
    hard_max_chunk_size: int,
    default_client_max_chunk_size: int | None = None,
) -> int:
    if client_max_chunk_size is None:
        if default_client_max_chunk_size is None:
            raise ValueError("A client chunk-size limit or default is required")
        client_max_chunk_size = default_client_max_chunk_size
    return min(client_max_chunk_size, configured_chunk_size, hard_max_chunk_size)


class FileTaskEnded(ConnectionError):
    def __init__(self, status: FileTaskStatus) -> None:
        self.status = status
        super().__init__(f"File task ended with status {status.name.lower()}")


# JSON Schema for the top-level request envelope.
# Validates field types so downstream code can rely on concrete types.
_REQUEST_ENVELOPE_SCHEMA = {
    "type": "object",
    "properties": {
        "action": {"type": "string"},
        "data": {"type": "object"},
        "username": {"anyOf": [{"type": "string"}, {"type": "null"}]},
        "token": {"anyOf": [{"type": "string"}, {"type": "null"}]},
        "nonce": {"type": "string"},
        "timestamp": {"type": "number"},
    },
    "required": ["action", "data"],
    "dependentRequired": {
        "username": ["token"],
        "token": ["username"],
    },
}


class ConnectionHandler:
    def __init__(self, stream: Stream) -> None:
        self.stream = stream
        self.remote_address = get_client_ip(self.stream.connection._ws)

        # Since a thread is created only after a new request has been
        # received, the necessary initial data should be available
        # immediately here.
        self.request = orjson.loads(stream.recv().data)
        self.logger = logger

        # Validate the request envelope structure and field types
        jsonschema.validate(self.request, _REQUEST_ENVELOPE_SCHEMA)

        self.action: str = self.request["action"]
        self.data: dict = self.request["data"]

        self.username: str = self.request.get("username", "")
        self.token: str = self.request.get("token", "")

        self.nonce: str = self.request.get("nonce", "")
        self.request_timestamp: float = self.request.get("timestamp", 0.0)

    def conclude_permission_denial(self) -> None:
        self.conclude_request(403, {}, smsg.PERMISSION_DENIED)

    def conclude_access_denial(self) -> None:
        self.conclude_request(403, {}, smsg.ACCESS_DENIED)

    def conclude_request(
        self, code: int, data: dict | None = None, message: str = ""
    ) -> None:
        """
        Conclude the request by sending a response back to the client.

        Args:
            code: HTTP status code for the response.
            data: Data dictionary to include in the response.
            message: Message string to include in the response.
        """
        response = {
            "code": code,
            "data": data if data is not None else {},
            "message": message,
            "timestamp": time.time(),
        }

        response_json = orjson.dumps(
            response,
        )
        self.logger.debug(f"Sending response: {response_json}")

        self.stream.send(response_json, frame_type=FrameType.CONCLUSION)

    def report_error(
        self,
        exc: Exception,
        code: int = 500,
        context: str | None = None,
        send_to_client: bool = True,
    ) -> str:
        """
        Log an exception with a generated log id and optionally send a safe message to client.

        Returns the generated log id.
        """
        log_id = log_exception_with_id(exc, self.logger, context=context)
        if send_to_client:
            self.conclude_request(
                code,
                {
                    "log_id": log_id,
                },
                context if context is not None else "Internal server error",
            )
        return log_id

    @staticmethod
    def _get_file_task_status(task_id: str) -> FileTaskStatus:
        with Session() as session, session.begin():
            status = expire_file_task_if_due(session, task_id)
        return FileTaskStatus.CANCELLED if status is None else status

    def _ensure_file_task_active(
        self, task_id: str, cancelled: threading.Event
    ) -> None:
        now = time.monotonic()
        last_checks = getattr(self, "_file_task_last_checks", None)
        if last_checks is None:
            last_checks = self._file_task_last_checks = {}
        if not cancelled.is_set() and now - last_checks.get(task_id, 0.0) < 1.0:
            return
        status = self._get_file_task_status(task_id)
        last_checks[task_id] = now
        if status != FileTaskStatus.IN_PROGRESS:
            raise FileTaskEnded(status)

    def _conclude_file_task_claim_failure(
        self, task_id: str, transfer_mode: TransferMode
    ) -> None:
        with Session() as session:
            task = session.get(FileTask, task_id)
            if task is None:
                self.conclude_request(404, {}, smsg.TASK_NOT_FOUND)
                return
            status = FileTaskStatus(task.status)
        if status in (FileTaskStatus.CANCELLED, FileTaskStatus.EXPIRED):
            self.conclude_request(
                410,
                {"task_status": status.name.lower()},
                "Task is no longer available",
            )
            return
        if (
            status == FileTaskStatus.IN_PROGRESS
            and transfer_mode == TransferMode.UPLOAD
        ):
            self.conclude_request(
                409,
                {"task_status": status.name.lower()},
                "Task is already in progress",
            )
            return
        self.conclude_request(400, {}, "Task cannot be claimed")

    def _recv_file_task_frame(
        self,
        task_id: str,
        cancelled: threading.Event,
        idle_timeout: float,
    ):
        deadline = time.monotonic() + idle_timeout
        while True:
            self._ensure_file_task_active(task_id, cancelled)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("File transfer idle timeout")
            try:
                return self.stream.recv(timeout=min(1.0, remaining))
            except TimeoutError:
                continue

    def send_file(self, task_id: str, offset: int, max_chunk_size: int) -> None:
        """
        Sends a file associated with the given task ID to the client over a websocket connection using AES encryption.
        The method performs the following steps:
        1. Retrieves the file ID and file path based on the provided task ID.
        2. Calculates the SHA-256 hash and size of the file.
        3. Notifies the client of the impending file transfer, including the hash and size.
        4. Waits for the client to acknowledge readiness to receive the file.
        5. Encrypts the file using AES-256 in GCM mode with a randomly generated key and nonce.
        6. Sends the nonce with the first encrypted chunk, then sends the remaining encrypted chunks.
        7. After the file is sent, transmits the AES key and tag to the client (base64 encoded).
        8. Handles errors and logs relevant information.
        Args:
            task_id (str): The identifier for the task whose associated file is to be sent.
            offset (int): The byte offset from which to resume sending the file. Should be 0 for a new transfer.
        Raises:
            ValueError: If the file ID or file path cannot be found for the given task ID.
            Exception: If an error occurs during file encryption or transmission.
        Returns:
            None
        """

        limit_decision: DownloadLimitDecision | None = None
        with Session() as session, session.begin():
            claimed = claim_file_task(session, task_id, TransferMode.DOWNLOAD)
            if claimed is not None:
                issuer = (
                    session.get(User, claimed.issued_by_username)
                    if claimed.issued_by_username is not None
                    else None
                )
                limit_decision = check_download_transfer_limits(
                    session,
                    issuer.username if issuer is not None else None,
                    self.remote_address,
                    task_id,
                    account_created_at=(
                        issuer.created_time if issuer is not None else None
                    ),
                    bypass_rate_limit=(
                        issuer is not None
                        and Permissions.BYPASS_DOCUMENT_DOWNLOAD_RATE_LIMIT
                        in issuer.all_permissions
                    ),
                )
                if not limit_decision.allowed:
                    release_file_task(session, task_id)

        if claimed is None:
            self._conclude_file_task_claim_failure(task_id, TransferMode.DOWNLOAD)
            return
        assert limit_decision is not None
        if not limit_decision.allowed:
            self.conclude_request(
                429,
                {
                    "scope": limit_decision.scope,
                    "limit": limit_decision.limit,
                    "retry_after_seconds": limit_decision.retry_after_seconds,
                },
                "Download transfer limit exceeded. Please try again later.",
            )
            return

        with watch_file_task(task_id) as cancelled:
            try:
                self._send_claimed_file(
                    claimed,
                    offset,
                    max_chunk_size,
                    cancelled,
                    limit_decision,
                )
            except FileTaskEnded as exc:
                self.conclude_request(
                    410,
                    {"task_status": exc.status.name.lower()},
                    "Task is no longer available",
                )

    def _send_claimed_file(
        self,
        claimed: ClaimedFileTask,
        offset: int,
        max_chunk_size: int,
        cancelled: threading.Event,
        limit_decision: DownloadLimitDecision,
    ) -> None:
        task_id = claimed.task_id
        file_id = claimed.file_id
        file_path = claimed.file_path

        self.logger.info(f"Task {task_id}: preparing to send file (id: {file_id}).")

        file_size = ProviderManager().storage.getsize(file_path)
        if claimed.stored_file_size != file_size:
            with Session() as session:
                file = session.get(File, file_id)
                if not file:
                    raise ValueError(f"File not found for file_id: {file_id}")
                file.size = file_size
                session.commit()

        self.logger.info(f"Calculation complete. File size: {file_size}")
        self.logger.bind(
            name="document_download_transfer",
            task_id=task_id,
            issued_by_username=claimed.issued_by_username,
            remote_address=self.remote_address,
            remaining_bytes=max(0, file_size - offset),
            active_downloads=limit_decision.active_downloads,
            risk_level=(
                limit_decision.risk_level.value
                if limit_decision.risk_level is not None
                else None
            ),
            would_block=limit_decision.would_block,
        ).info("Document download transfer started")

        if claimed.chunk_size is not None:
            chunk_size = claimed.chunk_size
            if chunk_size > max_chunk_size:
                self.conclude_request(
                    409,
                    {"chunk_size": chunk_size},
                    "Resume chunk size exceeds the client maximum",
                )
                with Session() as session, session.begin():
                    release_file_task(session, task_id)
                return
        else:
            chunk_size = _negotiate_file_chunk_size(
                max_chunk_size,
                configured_chunk_size=global_config["server"]["file_chunk_size"],
                hard_max_chunk_size=DOWNLOAD_TRANSFER_MAX_CHUNK_SIZE,
            )
            with Session() as session, session.begin():
                file_task = session.get(FileTask, task_id)
                if not file_task:
                    raise ValueError(
                        f"File transfer task not found for task_id: {task_id}"
                    )
                file_task.chunk_size = chunk_size

        if offset > file_size:
            self.conclude_request(400, {}, "Invalid offset: exceeds file size")
            with Session() as session, session.begin():
                release_file_task(session, task_id)
            return

        if offset != file_size and offset % chunk_size != 0:
            self.conclude_request(
                400,
                {"chunk_size": chunk_size},
                "Invalid offset: must be a multiple of chunk_size or zero",
            )
            with Session() as session, session.begin():
                release_file_task(session, task_id)
            return

        total_chunks = (file_size + chunk_size - 1) // chunk_size

        self.stream.send(
            orjson.dumps(
                {
                    "action": "transfer_file",
                    "data": {
                        "file_size": file_size,
                        "chunk_size": chunk_size,
                        "total_chunks": total_chunks,
                    },
                },
            )
        )

        received_response = self._recv_file_task_frame(
            task_id,
            cancelled,
            DocumentUploadPolicy.from_config().idle_timeout_seconds,
        )
        if received_response.data != b"ready":
            self.logger.error(
                "Client did not acknowledge readiness for file "
                f"transfer: {received_response}"
            )
            self.conclude_request(400, {}, "Client not ready for file transfer")
            with Session() as session, session.begin():
                release_file_task(session, task_id)
            return

        if file_size == 0:
            self.logger.info("Empty file, no need to send")
            self.stream.send(
                orjson.dumps(
                    {
                        "action": "transfer_file",
                        "data": {
                            "flag": "empty_file",
                        },
                    },
                )
            )
            received_response = self._recv_file_task_frame(
                task_id,
                cancelled,
                DocumentUploadPolicy.from_config().idle_timeout_seconds,
            )
            if received_response.data != b"complete":
                self.conclude_request(400, {}, "Client did not confirm file completion")
                with Session() as session, session.begin():
                    release_file_task(session, task_id)
                return
            with Session() as session, session.begin():
                file_task = session.get(FileTask, task_id)
                if not file_task:
                    raise ValueError(
                        f"File transfer task not found for task_id: {task_id}"
                    )
                if not complete_file_task(session, task_id):
                    self.conclude_request(
                        410,
                        {"task_status": FileTaskStatus(file_task.status).name.lower()},
                        "Task ended",
                    )
                    return
            self.stream.send(
                orjson.dumps({"action": "transfer_complete", "data": {}}),
                FrameType.CONCLUSION,
            )
            return

        if claimed.encryption_key:
            aes_key = base64.b64decode(claimed.encryption_key)
        else:
            aes_key = get_random_bytes(32)
            encoded_key = base64.b64encode(aes_key).decode()
            with Session() as session, session.begin():
                file_task = session.get(FileTask, task_id)
                if not file_task:
                    raise ValueError(
                        f"File transfer task not found for task_id: {task_id}"
                    )
                if file_task.encryption_key:
                    aes_key = base64.b64decode(file_task.encryption_key)
                else:
                    file_task.encryption_key = encoded_key

        self.logger.info(f"File transmission begin. Offset: {offset}")

        try:
            with ProviderManager().storage.fopen(file_path) as file:
                if offset > 0:
                    if not file.seekable():
                        self.logger.error(
                            f"File is not seekable, cannot resume from offset: {offset}"
                        )
                        self.conclude_request(
                            400,
                            {},
                            "File is not seekable, cannot resume from non-zero offset",
                        )
                        with Session() as session, session.begin():
                            release_file_task(session, task_id)
                        return

                    file.seek(offset)
                    chunk_index = offset // chunk_size

                else:
                    chunk_index = 0

                while True:
                    self._ensure_file_task_active(task_id, cancelled)
                    chunk = file.read(chunk_size)
                    if not chunk:
                        break

                    prefix = get_random_bytes(8)
                    nonce = prefix + chunk_index.to_bytes(4, "big")
                    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce, mac_len=16)

                    encrypted_chunk, tag = cipher.encrypt_and_digest(chunk)
                    payload = {
                        "action": "file_chunk",
                        "data": {
                            "index": chunk_index,
                            "chunk": base64.b64encode(encrypted_chunk).decode(),
                            "tag": base64.b64encode(tag).decode(),
                            "prefix": base64.b64encode(prefix).decode(),
                        },
                    }
                    self.stream.send(
                        orjson.dumps(
                            payload,
                        )
                    )
                    chunk_index += 1

            self.stream.send(
                orjson.dumps(
                    {
                        "action": "aes_key",
                        "data": {
                            "key": base64.b64encode(aes_key).decode(),
                        },
                    },
                )
            )

            received_response = self._recv_file_task_frame(
                task_id,
                cancelled,
                DocumentUploadPolicy.from_config().idle_timeout_seconds,
            )
            if received_response.data != b"complete":
                self.conclude_request(400, {}, "Client did not confirm file completion")
                with Session() as session, session.begin():
                    release_file_task(session, task_id)
                return

            with Session() as session, session.begin():
                file_task = session.get(FileTask, task_id)
                if not file_task:
                    raise ValueError(
                        f"File transfer task not found for task_id: {task_id}"
                    )
                if not complete_file_task(session, task_id):
                    self.conclude_request(
                        410,
                        {"task_status": FileTaskStatus(file_task.status).name.lower()},
                        "Task ended",
                    )
                    return

            self.stream.send(
                orjson.dumps({"action": "transfer_complete", "data": {}}),
                FrameType.CONCLUSION,
            )

        except (
            ConnectionClosed,
            ConnectionClosedError,
        ):
            self.logger.info("File transmission aborted: Connection closed")
            with Session() as session, session.begin():
                release_file_task(session, task_id)
            return
        except FileTaskEnded:
            raise
        except Exception as e:  # noqa: BLE001 - report unexpected transfer failures to the client.
            with Session() as session, session.begin():
                release_file_task(session, task_id)
            self.report_error(e, context=f"Error sending file {file_path}")
            return

        self.logger.info(f"File {file_path} sent successfully.")

    def receive_file(
        self,
        task_id: str,
        file_size: int,
        sha256: str | None,
        max_chunk_size: int,
        restart: bool,
    ) -> None:
        with Session() as session, session.begin():
            claimed = claim_file_task(session, task_id, TransferMode.UPLOAD)

        if claimed is None:
            self._conclude_file_task_claim_failure(task_id, TransferMode.UPLOAD)
            return

        with watch_file_task(task_id) as cancelled:
            try:
                self._receive_claimed_file(
                    claimed,
                    file_size,
                    sha256,
                    max_chunk_size,
                    restart,
                    cancelled,
                )
            except FileTaskEnded as exc:
                self._discard_upload_progress(claimed)
                self.conclude_request(
                    410,
                    {"task_status": exc.status.name.lower()},
                    "Task is no longer available",
                )
            except Exception as error:  # noqa: BLE001 - top-level upload recovery.
                with Session() as session, session.begin():
                    release_file_task(session, task_id)
                self.report_error(
                    error, context=f"Error preparing file upload for task {task_id}"
                )

    @staticmethod
    def _discard_upload_progress(claimed: ClaimedFileTask) -> None:
        storage = ProviderManager().storage
        if claimed.upload_session_id is not None:
            storage.abort_resumable_upload(claimed.file_path, claimed.upload_session_id)
        storage.remove(claimed.file_path)

    @staticmethod
    def _clear_upload_state(task_id: str) -> None:
        with Session() as session, session.begin():
            task = session.get(FileTask, task_id)
            if task is None:
                return
            task.upload_file_size = None
            task.upload_sha256 = None
            task.upload_session_id = None
            task.upload_checkpoint_size = None

    @staticmethod
    def _storage_sha256(path: str) -> str:
        hasher = hashlib.sha256()
        with ProviderManager().storage.fopen(path, "rb") as stored_file:
            while data := stored_file.read(1024 * 1024):
                hasher.update(data)
        return hasher.hexdigest()

    def _receive_claimed_file(
        self,
        claimed: ClaimedFileTask,
        file_size: int,
        sha256: str | None,
        max_chunk_size: int,
        restart: bool,
        cancelled: threading.Event,
    ) -> None:
        task_id = claimed.task_id
        file_id = claimed.file_id
        file_path = claimed.file_path
        storage = ProviderManager().storage
        policy = DocumentUploadPolicy.from_config()
        resumable = sha256 is not None and file_size > 0

        if claimed.chunk_size is not None:
            chunk_size = claimed.chunk_size
            if chunk_size > max_chunk_size:
                self.conclude_request(
                    409,
                    {"chunk_size": chunk_size},
                    "Resume chunk size exceeds the client maximum",
                )
                with Session() as session, session.begin():
                    release_file_task(session, task_id)
                return
        else:
            chunk_size = _negotiate_file_chunk_size(
                max_chunk_size,
                configured_chunk_size=global_config["server"]["file_chunk_size"],
                hard_max_chunk_size=UPLOAD_TRANSFER_MAX_CHUNK_SIZE,
            )

        stored_metadata = claimed.upload_file_size is not None
        metadata_matches = (
            claimed.upload_file_size == file_size and claimed.upload_sha256 == sha256
        )
        if (
            stored_metadata
            and claimed.upload_sha256 is not None
            and not metadata_matches
            and not restart
        ):
            self.conclude_request(
                409,
                {
                    "file_size": claimed.upload_file_size,
                    "sha256": claimed.upload_sha256,
                    "chunk_size": chunk_size,
                },
                "Upload metadata does not match the resumable task",
            )
            with Session() as session, session.begin():
                release_file_task(session, task_id)
            return

        discard_existing = restart or (stored_metadata and not resumable)
        if discard_existing:
            self._discard_upload_progress(claimed)
            claimed = ClaimedFileTask(
                task_id=claimed.task_id,
                file_id=claimed.file_id,
                file_path=claimed.file_path,
                stored_file_size=claimed.stored_file_size,
                issued_by_username=claimed.issued_by_username,
                encryption_key=claimed.encryption_key,
                chunk_size=chunk_size,
                upload_file_size=None,
                upload_sha256=None,
                upload_session_id=None,
                upload_checkpoint_size=None,
            )

        with Session() as session, session.begin():
            task = session.get(FileTask, task_id)
            if task is None:
                raise ValueError(f"File transfer task not found for task_id: {task_id}")
            if task.status != FileTaskStatus.IN_PROGRESS:
                raise FileTaskEnded(FileTaskStatus(task.status))
            if task.chunk_size is None:
                task.chunk_size = chunk_size
            task.upload_file_size = file_size
            task.upload_sha256 = sha256
            if discard_existing:
                task.upload_session_id = None
                task.upload_checkpoint_size = None

        storage.makedirs(os.path.dirname(file_path), exist_ok=True)
        prior_session_id = None if discard_existing else claimed.upload_session_id
        try:
            upload = storage.open_resumable_upload(
                file_path,
                file_size=file_size,
                chunk_size=chunk_size,
                session_id=prior_session_id,
                checkpoint_size=(
                    None if discard_existing else claimed.upload_checkpoint_size
                ),
            )
        except ResumableUploadSizeError:
            with Session() as session, session.begin():
                release_file_task(session, task_id)
            self.conclude_request(413, {}, "File exceeds storage upload limits")
            return

        try:
            with Session() as session, session.begin():
                task = session.get(FileTask, task_id)
                if task is None:
                    raise ValueError(
                        f"File transfer task not found for task_id: {task_id}"
                    )
                if task.status != FileTaskStatus.IN_PROGRESS:
                    raise FileTaskEnded(FileTaskStatus(task.status))
                task.upload_session_id = upload.session_id
                task.upload_checkpoint_size = upload.checkpoint_size
        except Exception:
            if prior_session_id is None:
                upload.abort()
            else:
                upload.close()
            raise

        initial_offset = upload.offset
        hasher = hashlib.sha256()
        received_size = initial_offset
        try:
            self.stream.send(
                orjson.dumps(
                    {
                        "action": "transfer_file",
                        "data": {
                            "file_size": file_size,
                            "chunk_size": chunk_size,
                            "offset": initial_offset,
                            "supports_resume": resumable,
                        },
                    }
                )
            )
            logger.info("Receiving file: transfer started")
            while received_size < file_size:
                data = self._recv_file_task_frame(
                    task_id, cancelled, policy.idle_timeout_seconds
                ).data
                expected_size = min(chunk_size, file_size - received_size)
                if len(data) != expected_size:
                    self.conclude_request(
                        400,
                        {"offset": upload.offset},
                        "Invalid upload chunk size",
                    )
                    upload.close()
                    if not resumable:
                        upload.abort()
                        storage.remove(file_path)
                        self._clear_upload_state(task_id)
                    with Session() as session, session.begin():
                        release_file_task(session, task_id)
                    return
                upload.write(data)
                if initial_offset == 0 and sha256 is not None:
                    hasher.update(data)
                received_size += len(data)

            upload.finish()
            actual_size = storage.getsize(file_path)
            if actual_size != file_size:
                raise ValueError(
                    f"File size mismatch: expected {file_size}, got {actual_size}"
                )

            if sha256 is not None:
                actual_sha256 = (
                    hasher.hexdigest()
                    if initial_offset == 0
                    else self._storage_sha256(file_path)
                )
                if actual_sha256 != sha256:
                    storage.remove(file_path)
                    self._clear_upload_state(task_id)
                    self.conclude_request(400, {}, "SHA256 mismatch")
                    with Session() as session, session.begin():
                        release_file_task(session, task_id)
                    return

            with Session() as session, session.begin():
                file_task = session.get(FileTask, task_id)
                if file_task is None:
                    raise ValueError(
                        f"File transfer task not found for task_id: {task_id}"
                    )
                file = session.get(File, file_id)
                if file is None:
                    raise ValueError(f"File not found for file_id: {file_id}")
                if not complete_file_task(session, task_id):
                    storage.remove(file_path)
                    self.conclude_request(
                        410,
                        {"task_status": FileTaskStatus(file_task.status).name.lower()},
                        "Task ended",
                    )
                    return
                file_task.upload_session_id = None
                file_task.upload_checkpoint_size = None
                file.sha256 = sha256
                file.size = actual_size
                file.active = True
                if file_size:
                    pm.hook.ext_before_file_upload_commit(
                        session=session,
                        id=file_id,
                        path=file_path,
                        sha256=sha256,
                    )

            if file_size:
                pm.hook.ext_on_file_uploaded(id=file_id, path=file_path, sha256=sha256)
            else:
                pm.hook.ext_on_empty_file_uploaded(id=file_id, path=file_path)

            self.logger.info(
                f"File received and saved to {file_path}, total size: {actual_size}"
            )
            self.conclude_request(200, {}, "File received successfully")

            if file_size:
                try:
                    pm.hook.ext_post_file_upload_response(
                        id=file_id,
                        path=file_path,
                        sha256=sha256,
                    )
                except Exception as error:  # noqa: BLE001 - upload is acknowledged.
                    self.report_error(
                        error,
                        context="Post-upload response hook failed",
                        send_to_client=False,
                    )

        except FileTaskEnded:
            upload.abort()
            storage.remove(file_path)
            self._clear_upload_state(task_id)
            status = self._get_file_task_status(task_id)
            self.conclude_request(
                410,
                {"task_status": status.name.lower()},
                "Task is no longer available",
            )
        except ConnectionError:
            self.logger.info("File reception aborted: Connection closed")
            upload.close()
            if not resumable:
                upload.abort()
                storage.remove(file_path)
                self._clear_upload_state(task_id)
            with Session() as session, session.begin():
                release_file_task(session, task_id)
        except TimeoutError:
            self.logger.info("File reception aborted: idle timeout")
            upload.close()
            if not resumable:
                upload.abort()
                storage.remove(file_path)
                self._clear_upload_state(task_id)
            with Session() as session, session.begin():
                release_file_task(session, task_id)
            self.conclude_request(408, {}, "File upload timed out")
        except Exception as error:  # noqa: BLE001 - report transfer failures.
            upload.close()
            if not resumable:
                upload.abort()
                storage.remove(file_path)
                self._clear_upload_state(task_id)
            with Session() as session, session.begin():
                release_file_task(session, task_id)
            self.report_error(error, context=f"Error receiving file for task {task_id}")

    def broadcast(
        self,
        message: Data,
        raise_exceptions: bool = False,
    ):
        """Broadcast a message to all connected clients.

        If possible, it is recommended to avoid using local providers to publish
        broadcasts, as this can easily lead to various performance issues on a
        synchronous server implementation.

        Args:
            message: The message to broadcast. Must be a string or bytes-like object.
        """

        if isinstance(message, (bytes, bytearray, memoryview)):
            message = bytes(message).decode("utf-8")
        elif not isinstance(message, str):
            raise TypeError("data must be str or bytes")

        ProviderManager().event_bus.publish(GLOBAL_BROADCAST_EVENT_CHANNEL, message)
