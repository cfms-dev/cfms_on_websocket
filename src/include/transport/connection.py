import base64
import hashlib
import os
import time
from typing import Optional

import jsonschema
import orjson
import websockets
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from loguru import logger as log
from websockets.typing import Data

from include.config.constants import (
    FILE_TRANSFER_MAX_CHUNK_SIZE,
    FILE_TRANSFER_MIN_CHUNK_SIZE,
)
from include.config.settings import global_config
from include.database.models.files import File, FileTask
from include.database.session import Session
from include.domains.operations.messages import Messages as smsg
from include.extensions.manager import pm
from include.observability.exception_logging import log_exception_with_id
from include.providers.manager import ProviderManager
from include.transport.multiplexing import FrameType, Stream

logger = log.bind(name="conn")


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
        self.remote_address = self.stream.connection._ws.remote_address[0]

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
        self, code: int, data: Optional[dict] = None, message: str = ""
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
        context: Optional[str] = None,
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

    def send_file(self, task_id: str, offset: int) -> None:
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

        with Session() as session:
            file_task = session.get(FileTask, task_id)
            if not file_task:
                raise ValueError(f"File transfer task not found for task_id: {task_id}")
            if file_task.mode != 0:
                raise ValueError(f"Not a read-mode task: {task_id}")
            if file_task.status != 0:
                raise ValueError(
                    f"File transfer task already completed or cancelled: {task_id}"
                )
            file = session.get(File, file_task.file_id)
            if not file:
                raise ValueError(f"File not found for file_id: {file_task.file_id}")

            file_id = file.id
            file_path = file.path
            stored_file_size = file.size
            encryption_key = file_task.encryption_key

        self.logger.info(f"Task {task_id}: preparing to send file (id: {file_id}).")

        file_size = ProviderManager().storage.getsize(file_path)
        if stored_file_size != file_size:
            with Session() as session:
                file = session.get(File, file_id)
                if not file:
                    raise ValueError(f"File not found for file_id: {file_id}")
                file.size = file_size
                session.commit()

        self.logger.info(f"Calculation complete. File size: {file_size}")

        chunk_size = global_config["server"]["file_chunk_size"]
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

        received_response = self.stream.recv()
        if received_response.data != b"ready":
            self.logger.error(
                "Client did not acknowledge readiness for file "
                f"transfer: {received_response}"
            )
            self.conclude_request(400, {}, "Client not ready for file transfer")
            return

        if offset > file_size:
            self.logger.error(
                f"Invalid offset: {offset} (exceeds file size: {file_size})"
            )
            self.conclude_request(400, {}, "Invalid offset: exceeds file size")
            return

        if offset % chunk_size != 0:
            self.logger.error(
                f"Invalid offset: {offset} (not aligned to chunk size: {chunk_size})"
            )
            self.conclude_request(
                400,
                {},
                "Invalid offset: must be a multiple of chunk_size or zero",
            )
            return

        if file_size == 0:
            self.logger.info("Empty file, no need to send")
            with Session() as session:
                file_task = session.get(FileTask, task_id)
                if not file_task:
                    raise ValueError(
                        f"File transfer task not found for task_id: {task_id}"
                    )
                file_task.status = 1
                session.commit()
            self.stream.send(
                orjson.dumps(
                    {
                        "action": "transfer_file",
                        "data": {
                            "flag": "empty_file",
                        },
                    },
                ),
                FrameType.CONCLUSION,
            )
            return

        if encryption_key:
            aes_key = base64.b64decode(encryption_key)
        else:
            aes_key = get_random_bytes(32)
            encoded_key = base64.b64encode(aes_key).decode()
            with Session() as session:
                file_task = session.get(FileTask, task_id)
                if not file_task:
                    raise ValueError(
                        f"File transfer task not found for task_id: {task_id}"
                    )
                if file_task.encryption_key:
                    aes_key = base64.b64decode(file_task.encryption_key)
                else:
                    file_task.encryption_key = encoded_key
                    session.commit()

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
                        return

                    file.seek(offset)
                    chunk_index = offset // chunk_size

                else:
                    chunk_index = 0

                while True:
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

            with Session() as session:
                file_task = session.get(FileTask, task_id)
                if not file_task:
                    raise ValueError(
                        f"File transfer task not found for task_id: {task_id}"
                    )
                if file_task.status == 0:
                    file_task.status = 1
                    session.commit()
                    key_to_send = base64.b64encode(aes_key).decode()
                else:
                    key_to_send = None

            self.stream.send(
                orjson.dumps(
                    {
                        "action": "aes_key",
                        "data": {
                            "key": key_to_send,
                        },
                    },
                ),
                FrameType.CONCLUSION,
            )

        except (
            websockets.ConnectionClosed,
            websockets.exceptions.ConnectionClosedError,
        ):
            self.logger.info("File transmission aborted: Connection closed")
            return
        except Exception as e:
            self.report_error(e, context=f"Error sending file {file_path}")
            return

        self.logger.info(f"File {file_path} sent successfully.")

    def receive_file(self, task_id: str) -> None:
        """
        Receives a file from the client over a websocket connection using AES encryption.
        The method performs the following steps:
        1. Waits for the client to send the file transfer request, including the SHA-256 hash and file size.
        2. Acknowledges readiness to receive the file.
        3. Receives the encrypted file data in chunks, decrypting each chunk using AES-256 in GCM mode.
        4. Writes the decrypted data to a file on disk.
        5. Handles errors and logs relevant information.
        Returns:
            None
        """

        handshake_msg = {
            "action": "transfer_file",
            "data": {},
            "message": "waiting for file transfer",
        }

        self.stream.send(
            orjson.dumps(
                handshake_msg,
            )
        )
        self.logger.info("Receiving file: handshake sent")

        task_info = orjson.loads(self.stream.recv().data)

        try:
            jsonschema.validate(
                task_info,
                {
                    "type": "object",
                    "properties": {
                        "action": {"type": "string", "pattern": "^transfer_file$"},
                        "data": {
                            "type": "object",
                            "properties": {
                                "sha256": {
                                    "anyOf": [{"type": "string"}, {"type": "null"}]
                                },
                                "file_size": {"type": "integer"},
                                "max_chunk_size": {
                                    "type": "integer",
                                    "minimum": FILE_TRANSFER_MIN_CHUNK_SIZE,
                                },
                            },
                            "required": ["file_size"],
                            "additionalProperties": False,
                        },
                    },
                    "required": ["data"],
                    "additionalProperties": False,
                },
            )
        except jsonschema.ValidationError:
            self.conclude_request(400, {}, "Invalid request for file transfer")
            return

        sha256: str = task_info["data"].get("sha256")
        # required field, guaranteed by JSON Schema validation
        file_size: int = task_info["data"]["file_size"]
        max_chunk_size: int = task_info["data"].get(
            "max_chunk_size", FILE_TRANSFER_MAX_CHUNK_SIZE
        )

        chunk_size = (
            FILE_TRANSFER_MAX_CHUNK_SIZE
            if max_chunk_size > FILE_TRANSFER_MAX_CHUNK_SIZE
            else max_chunk_size
        )

        with Session() as session:
            file_task = session.get(FileTask, task_id)
            if not file_task:
                raise ValueError(f"File transfer task not found for task_id: {task_id}")
            if file_task.mode != 1:
                raise ValueError(f"Not a write-mode task: {task_id}")
            if file_task.status != 0:
                raise ValueError(
                    f"File transfer task already completed or cancelled: {task_id}"
                )
            file = session.get(File, file_task.file_id)
            if not file:
                raise ValueError(f"File not found for file_id: {file_task.file_id}")

            file_id = file.id
            file_path = file.path

        ProviderManager().storage.makedirs(os.path.dirname(file_path), exist_ok=True)

        if file_size == 0:
            self.stream.send("stop")

            ProviderManager().storage.fopen(file_path, "wb").close()
            with Session() as session:
                file_task = session.get(FileTask, task_id)
                if not file_task:
                    raise ValueError(
                        f"File transfer task not found for task_id: {task_id}"
                    )
                file = session.get(File, file_id)
                if not file:
                    raise ValueError(f"File not found for file_id: {file_id}")
                file_task.status = 1
                file.sha256 = sha256
                file.size = 0
                file.active = True
                session.commit()

            pm.hook.ext_on_empty_file_uploaded(id=file_id, path=file_path)
            return

        self.stream.send(f"ready {chunk_size}")
        try:
            logger.info("Receiving file: transfer started")
            with ProviderManager().storage.fopen(file_path, "wb") as f:
                try:
                    hasher = hashlib.sha256()
                    received_size = 0
                    while received_size < file_size:
                        data = self.stream.recv().data
                        if not data:
                            break

                        f.write(data)
                        hasher.update(data)
                        received_size += len(data)

                        if len(data) < chunk_size:
                            break
                except (
                    websockets.ConnectionClosed,
                    websockets.exceptions.ConnectionClosedOK,
                ):
                    raise

            actual_size = ProviderManager().storage.getsize(file_path)
            if file_size and actual_size != file_size:
                self.logger.error(
                    f"File size mismatch: expected {file_size}, got {actual_size}"
                )
                ProviderManager().storage.remove(file_path)

                self.conclude_request(
                    400,
                    {},
                    f"File size mismatch: expected {file_size}, got {actual_size}",
                )
                return

            if sha256:
                actual_sha256 = hasher.hexdigest()
                if actual_sha256 != sha256:
                    self.logger.error(
                        f"SHA256 mismatch: expected {sha256}, got {actual_sha256}"
                    )
                    ProviderManager().storage.remove(file_path)

                    self.conclude_request(
                        400,
                        {},
                        f"SHA256 mismatch: expected {sha256}, got {actual_sha256}",
                    )
                    return

            with Session() as session:
                file_task = session.get(FileTask, task_id)
                if not file_task:
                    raise ValueError(
                        f"File transfer task not found for task_id: {task_id}"
                    )
                file = session.get(File, file_id)
                if not file:
                    raise ValueError(f"File not found for file_id: {file_id}")
                file_task.status = 1
                file.sha256 = sha256
                file.size = actual_size
                file.active = True
                session.commit()

            pm.hook.ext_on_file_uploaded(id=file_id, path=file_path, sha256=sha256)

            self.logger.info(
                f"File received and saved to {file_path}, total size: {actual_size}"
            )

            self.conclude_request(200, {}, "File received successfully")

        except ConnectionError:
            self.logger.info("File reception aborted: Connection closed")
            return

        except Exception as e:
            self.report_error(e, context=f"Error receiving file for task {task_id}")
            return

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

        ProviderManager().event_bus.publish("system:broadcast", message)
