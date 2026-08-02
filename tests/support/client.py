"""
Test client for CFMS WebSocket Server.

This module provides a reusable WebSocket client for testing the CFMS server.
"""

import asyncio
import base64
import hashlib
import mmap
import os
import queue
import secrets
import ssl
import threading
import time
from pathlib import Path
from typing import Any

import orjson
from Crypto.Cipher import AES
from loguru import logger as log
from websockets.asyncio.client import ClientConnection, connect
from websockets.exceptions import ConnectionClosedOK
from websockets.typing import DataLike

from include.transport.multiplexing import (
    Frame,
    FrameType,
    decode_frame,
    encode_frame,
)

logger = log.bind(name="test_client.multiplexer")


def calculate_sha256(file_path: str) -> str:
    """
    Calculate SHA256 hash of a file using memory-mapped I/O for efficiency.

    Uses memory-mapped files for faster hash calculation of large files.

    Args:
        file_path: Path to the file to hash

    Returns:
        Hexadecimal SHA256 hash string
    """
    with open(file_path, "rb") as f:
        # Use memory-mapped files to map directly to memory
        mmapped_file = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        return hashlib.sha256(mmapped_file).hexdigest()


class AsyncStream:
    def __init__(self, connection: AsyncMultiplexConnection, frame_id: int):
        self.connection = connection
        self.frame_id = frame_id
        self._queue: queue.Queue = queue.Queue(100)

    async def send(
        self, data: DataLike, frame_type: FrameType = FrameType.PROCESS
    ) -> None:
        await self.connection._send_frame(self.frame_id, frame_type, data)

    async def recv(self, timeout: float | None = None) -> Frame:
        try:
            if timeout is None:
                frame = await asyncio.to_thread(self._queue.get)
            else:
                frame = await asyncio.to_thread(self._queue.get, True, timeout)
        except queue.Empty:
            raise TimeoutError("Stream recv timeout")

        if frame is None:
            raise ConnectionError("MultiplexedConnection has been closed")
        return frame

    def _put_incoming_frame(self, frame: Frame | None):
        self._queue.put(frame)


class AsyncMultiplexConnection:
    def __init__(self, websocket: ClientConnection):
        self._ws = websocket
        self._next_frame_id = 1
        self._id_lock = threading.Lock()
        self._streams: dict[int, AsyncStream] = {}
        self._streams_lock = threading.Lock()
        self._new_streams: queue.Queue[AsyncStream | None] = queue.Queue()
        self._is_running = True
        self._dispatcher_task = asyncio.create_task(self._recv_loop())

    def open_stream(self) -> AsyncStream:
        with self._id_lock:
            frame_id = self._next_frame_id
            self._next_frame_id += 2

        new_stream = AsyncStream(self, frame_id)
        with self._streams_lock:
            self._streams[frame_id] = new_stream

        return new_stream

    async def accept_stream(self, timeout: float | None = None) -> AsyncStream | None:
        try:
            if timeout is None:
                return await asyncio.to_thread(self._new_streams.get)
            return await asyncio.to_thread(self._new_streams.get, True, timeout)
        except queue.Empty:
            raise TimeoutError("Server stream accept timeout")

    async def _recv_loop(self) -> None:
        try:
            while self._is_running:
                raw_payload = await self._ws.recv(decode=False)
                frame = decode_frame(raw_payload)
                if frame is None:
                    continue

                with self._streams_lock:
                    target_stream = self._streams.get(frame.stream_id)
                    if target_stream is None:
                        if frame.stream_id % 2 != 0:
                            self._is_running = False
                            await self._ws.close()
                            return
                        new_stream = AsyncStream(self, frame.stream_id)
                        self._streams[frame.stream_id] = new_stream
                        self._new_streams.put(new_stream)
                        target_stream = new_stream

                target_stream._put_incoming_frame(frame)

                if frame.frame_type == FrameType.CONCLUSION:
                    with self._streams_lock:
                        self._streams.pop(frame.stream_id, None)

        except ConnectionClosedOK:
            return
        except Exception:
            logger.exception("Error in async multiplex receive loop")
        finally:
            self._is_running = False
            self._new_streams.put(None)
            with self._streams_lock:
                for stream in self._streams.values():
                    stream._put_incoming_frame(None)

    async def _send_frame(
        self, frame_id: int, frame_type: FrameType, data: DataLike
    ) -> None:
        await self._ws.send(encode_frame(frame_id, frame_type, data))

        if frame_type == FrameType.CONCLUSION:
            with self._streams_lock:
                self._streams.pop(frame_id, None)

    async def close(self):
        self._is_running = False
        try:
            await self._ws.close()
        except Exception:
            pass

        # Explicitly cancel and await _dispatcher_task.
        if hasattr(self, "_dispatcher_task") and not self._dispatcher_task.done():
            self._dispatcher_task.cancel()
            try:
                await self._dispatcher_task
            except asyncio.CancelledError:
                pass


def _env_bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.lower() not in {"0", "false", "no", "off"}


def _format_ws_host(host: str) -> str:
    if ":" in host and not host.startswith("["):
        return f"[{host}]"
    return host


class CFMSTestClient:
    """
    A test client for the CFMS WebSocket server.

    This client provides convenient methods for connecting to the server,
    sending requests, and receiving responses. It handles authentication
    and connection management automatically.
    """

    def __init__(
        self,
        host: str | None = None,
        port: int | None = None,
        use_ssl: bool | None = None,
    ):
        """
        Initialize the test client.

        Args:
            host: Server hostname
            port: Server port
            use_ssl: Whether to use SSL/TLS connection
        """
        self.host = host or os.environ.get("CFMS_TEST_HOST", "localhost")
        self.port = (
            port if port is not None else int(os.environ.get("CFMS_TEST_PORT", "5104"))
        )
        self.use_ssl = (
            use_ssl if use_ssl is not None else _env_bool("CFMS_TEST_USE_SSL", True)
        )
        self.websocket: ClientConnection | None = None
        self.multiplexer: AsyncMultiplexConnection | None = None
        self.username: str | None = None
        self.token: str | None = None

    async def connect(self) -> None:
        """
        Establish a WebSocket connection to the server with retry/backoff logic.
        """
        if self.websocket is not None:
            return

        protocol = "wss" if self.use_ssl else "ws"
        uri = f"{protocol}://{_format_ws_host(self.host)}:{self.port}"

        if self.use_ssl:
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
        else:
            ssl_context = None

        max_retries = 5
        delay = 0.5
        backoff = 2.0
        last_exc: BaseException | None = None

        for attempt in range(1, max_retries + 1):
            try:
                # connect(...) returns an async connection object
                self.websocket = await connect(uri, ssl=ssl_context, proxy=None)
                self.multiplexer = AsyncMultiplexConnection(self.websocket)
                return
            except Exception as exc:
                last_exc = exc
                if attempt == max_retries:
                    break
                await asyncio.sleep(delay)
                delay *= backoff

        # If we reach here, all attempts failed
        raise RuntimeError(
            f"Failed to connect to {uri} after {max_retries} attempts"
        ) from last_exc

    async def disconnect(self) -> None:
        """
        Close the WebSocket connection.
        """
        if self.multiplexer is not None:
            try:
                await self.multiplexer.close()
            except Exception:
                pass
            self.multiplexer = None

        if self.websocket is not None:
            try:
                await self.websocket.close()
            except Exception:
                pass
            self.websocket = None

        self.username = None
        self.token = None

    async def _parse_frame_data(self, frame: Frame) -> Any:
        if frame.data is None:
            raise RuntimeError("Received empty frame from server")

        if isinstance(frame.data, memoryview):
            raw = frame.data.tobytes()
        elif isinstance(frame.data, bytes):
            raw = frame.data
        elif isinstance(frame.data, str):
            raw = frame.data.encode("utf-8")
        else:
            raise TypeError("Unsupported frame data type")

        try:
            return orjson.loads(raw)
        except orjson.JSONDecodeError:
            # If not JSON, return raw string
            return raw.decode("utf-8", errors="ignore")

    async def _build_and_send_request(
        self,
        stream: AsyncStream,
        action: str,
        data: dict[str, Any] | None = None,
        username: str | None = None,
        token: str | None = None,
        include_auth: bool = True,
    ) -> Frame:
        request: dict[str, Any] = {
            "action": action,
            "data": data if data is not None else {},
        }

        if include_auth:
            resolved_username = username if username is not None else self.username
            resolved_token = token if token is not None else self.token

            if resolved_username is not None or resolved_token is not None:
                if resolved_username is not None:
                    request["username"] = resolved_username
                if resolved_token is not None:
                    request["token"] = resolved_token
                request["nonce"] = secrets.token_hex(16)
                request["timestamp"] = time.time()

        await stream.send(orjson.dumps(request))
        frame = await stream.recv()
        return frame

    async def send_request(
        self,
        action: str,
        data: dict[str, Any] | None = None,
        username: str | None = None,
        token: str | None = None,
        include_auth: bool = True,
    ) -> dict[str, Any]:
        """
        Send a request to the server and receive the response.

        Args:
            action: The action to perform
            data: Optional data payload for the request
            username: Optional username (defaults to stored username)
            token: Optional token (defaults to stored token)
            include_auth: Whether to include authentication credentials

        Returns:
            The response from the server as a dictionary
        """
        if self.multiplexer is None:
            raise RuntimeError("Not connected to server. Call connect() first.")

        stream = self.multiplexer.open_stream()
        frame = await self._build_and_send_request(
            stream,
            action,
            data=data,
            username=username,
            token=token,
            include_auth=include_auth,
        )

        payload = await self._parse_frame_data(frame)

        if isinstance(payload, dict):
            return payload

        # If not dict, try to parse it as JSON again
        if isinstance(payload, str):
            try:
                return orjson.loads(payload)
            except orjson.JSONDecodeError as e:
                raise RuntimeError(f"Invalid response from server: {e}") from e

        raise RuntimeError("Unexpected response format from server")

    async def accept_event(self, timeout: float | None = None) -> dict[str, Any]:
        if self.multiplexer is None:
            raise RuntimeError("Not connected to server. Call connect() first.")

        stream = await self.multiplexer.accept_stream(timeout=timeout)
        if stream is None:
            raise ConnectionError("Connection closed before receiving server event")

        frame = await stream.recv(timeout=timeout)
        payload = await self._parse_frame_data(frame)
        if not isinstance(payload, dict):
            raise RuntimeError(f"Unexpected event payload: {payload}")
        return payload

    async def send_raw_request(
        self,
        request: dict[str, Any],
    ) -> dict[str, Any]:
        """Send a raw request object (custom nonce/timestamp) via multiplex stream."""
        if self.multiplexer is None:
            raise RuntimeError("Not connected to server. Call connect() first.")

        stream = self.multiplexer.open_stream()
        await stream.send(orjson.dumps(request))

        frame = await stream.recv()
        payload = await self._parse_frame_data(frame)

        if isinstance(payload, dict):
            return payload
        if isinstance(payload, str):
            try:
                return orjson.loads(payload)
            except orjson.JSONDecodeError as e:
                raise RuntimeError(f"Invalid response from server: {e}") from e

        raise RuntimeError("Unexpected response format from server")

    async def login(
        self, username: str, password: str, two_fa_token: str | None = None
    ) -> dict[str, Any]:
        """
        Authenticate with the server.

        Args:
            username: Username to authenticate with
            password: Password for the user
            two_fa_token: Optional 2FA token for two-factor authentication

        Returns:
            The login response from the server
        """
        data = {"username": username, "password": password}
        if two_fa_token:
            data["2fa_token"] = two_fa_token

        response = await self.send_request("login", data, include_auth=False)

        if response.get("code") == 200:
            self.username = username
            self.token = response.get("data", {}).get("token")

        return response

    async def server_info(self) -> dict[str, Any]:
        """
        Get server information.

        Returns:
            Server information including version and protocol version
        """
        return await self.send_request("server_info", include_auth=False)

    async def refresh_token(self) -> dict[str, Any]:
        """
        Refresh the authentication token.

        Returns:
            Response with new token
        """
        response = await self.send_request("refresh_token")

        if response.get("code") == 200:
            self.token = response.get("data", {}).get("token")

        return response

    async def get_document(self, document_id: str) -> dict[str, Any]:
        """
        Get a document by ID.

        Args:
            document_id: The ID of the document to retrieve

        Returns:
            The document data
        """
        return await self.send_request("get_document", {"document_id": document_id})

    async def create_document(
        self, title: str, folder_id: str | None = None
    ) -> dict[str, Any]:
        """
        Create a new document.

        Args:
            title: Title of the document
            folder_id: Optional folder ID to create the document in

        Returns:
            Response with created document information
        """
        data = {"title": title}
        if folder_id is not None:
            data["folder_id"] = folder_id
        return await self.send_request("create_document", data)

    async def upload_document(
        self, document_id: str, parent_revision_id: str | None = None
    ) -> dict[str, Any]:
        data = {"document_id": document_id}
        if parent_revision_id:
            data["parent_revision_id"] = parent_revision_id
        return await self.send_request("upload_document", data)

    async def delete_document(self, document_id: str) -> dict[str, Any]:
        """
        Delete a document.

        Args:
            document_id: The ID of the document to delete

        Returns:
            Response indicating success or failure
        """
        return await self.send_request("delete_document", {"document_id": document_id})

    async def purge_document(self, document_id: str) -> dict[str, Any]:
        return await self.send_request("purge_document", {"document_id": document_id})

    async def restore_document(
        self,
        document_id: str,
        target_folder_id: str | None = None,
        new_title: str | None = None,
    ) -> dict[str, Any]:
        data = {"document_id": document_id}
        if target_folder_id is not None:
            data["target_folder_id"] = target_folder_id
        if new_title is not None:
            data["new_title"] = new_title
        return await self.send_request("restore_document", data)

    async def rename_document(self, document_id: str, new_title: str) -> dict[str, Any]:
        """
        Rename a document.

        Args:
            document_id: The ID of the document to rename
            new_title: The new title for the document

        Returns:
            Response indicating success or failure
        """
        return await self.send_request(
            "rename_document", {"document_id": document_id, "new_title": new_title}
        )

    async def get_document_info(self, document_id: str) -> dict[str, Any]:
        """
        Get information about a document.

        Args:
            document_id: The ID of the document

        Returns:
            Document information
        """
        return await self.send_request(
            "get_document_info", {"document_id": document_id}
        )

    async def set_document_tags(
        self, document_id: str, tags: list[str]
    ) -> dict[str, Any]:
        return await self.send_request(
            "set_document_tags",
            {"document_id": document_id, "tags": tags},
        )

    # --- Revisions ---
    async def list_revisions(
        self,
        document_id: str,
        page_size: int | None = None,
        cursor: str | None = None,
    ) -> dict[str, Any]:
        data: dict[str, Any] = {"document_id": document_id}
        if page_size is not None:
            data["page_size"] = page_size
        if cursor is not None:
            data["cursor"] = cursor
        return await self.send_request("list_revisions", data)

    async def get_revision(self, revision_id: str) -> dict[str, Any]:
        return await self.send_request("get_revision", {"id": revision_id})

    async def set_document_revision(
        self, document_id: str, revision_id: str
    ) -> dict[str, Any]:
        return await self.send_request(
            "set_current_revision",
            {"document_id": document_id, "revision_id": revision_id},
        )

    async def delete_revision(self, revision_id: str) -> dict[str, Any]:
        return await self.send_request("delete_revision", {"id": revision_id})

    async def list_directory(
        self,
        folder_id: str | None = None,
        page_size: int | None = None,
        cursor: str | None = None,
    ) -> dict[str, Any]:
        """
        List contents of a directory.

        Args:
            folder_id: The ID of the folder (None for root)

        Returns:
            Directory listing
        """
        data = {}
        data["folder_id"] = folder_id
        if page_size is not None:
            data["page_size"] = page_size
        if cursor is not None:
            data["cursor"] = cursor

        return await self.send_request("list_directory", data)

    async def create_directory(
        self, name: str, parent_id: str | None = None
    ) -> dict[str, Any]:
        """
        Create a new directory.

        Args:
            name: Name of the directory
            parent_id: Optional parent directory ID

        Returns:
            Response with created directory information
        """
        data = {"name": name}
        if parent_id is not None:
            data["parent_id"] = parent_id
        return await self.send_request("create_directory", data)

    async def delete_directory(self, folder_id: str) -> dict[str, Any]:
        """
        Delete a directory.

        Args:
            folder_id: The ID of the folder to delete

        Returns:
            Response indicating success or failure
        """
        return await self.send_request("delete_directory", {"folder_id": folder_id})

    async def list_deleted_items(
        self,
        folder_id: str,
        page_size: int | None = None,
        cursor: str | None = None,
    ) -> dict[str, Any]:
        data: dict[str, Any] = {"folder_id": folder_id}
        if page_size is not None:
            data["page_size"] = page_size
        if cursor is not None:
            data["cursor"] = cursor
        return await self.send_request("list_deleted_items", data)

    async def purge_directory(self, folder_id: str) -> dict[str, Any]:
        return await self.send_request("purge_directory", {"folder_id": folder_id})

    async def restore_directory(
        self,
        folder_id: str,
        target_parent_id: str | None = None,
        new_name: str | None = None,
    ) -> dict[str, Any]:
        data = {"folder_id": folder_id}
        if target_parent_id is not None:
            data["target_parent_id"] = target_parent_id
        if new_name is not None:
            data["new_name"] = new_name
        return await self.send_request("restore_directory", data)

    async def move_directory(
        self, folder_id: str, target_folder_id: str | None
    ) -> dict[str, Any]:
        """
        Move a directory to a new location.

        Args:
            folder_id: The ID of the folder to move
            target_folder_id: The ID of the target parent folder (None for root)

        Returns:
            Response indicating success or failure
        """
        return await self.send_request(
            "move_directory",
            {"folder_id": folder_id, "target_folder_id": target_folder_id},
        )

    async def search(
        self,
        query: str,
        page_size: int | None = None,
        cursor: str | None = None,
        sort_by: str | None = None,
        sort_order: str | None = None,
        search_documents: bool | None = None,
        search_directories: bool | None = None,
    ) -> dict[str, Any]:
        """
        Search for documents and directories by name.

        Args:
            query: Search query string
            page_size: Maximum number of results to return
            cursor: Cursor returned by the previous page
            sort_by: Sort field (name, created_time, size, last_modified)
            sort_order: Sort order (asc, desc)
            search_documents: Whether to search documents
            search_directories: Whether to search directories

        Returns:
            Search results with matching documents and directories
        """
        data: dict[str, Any] = {"query": query}
        if page_size is not None:
            data["page_size"] = page_size
        if cursor is not None:
            data["cursor"] = cursor
        if sort_by is not None:
            data["sort_by"] = sort_by
        if sort_order is not None:
            data["sort_order"] = sort_order
        if search_documents is not None:
            data["search_documents"] = search_documents
        if search_directories is not None:
            data["search_directories"] = search_directories
        return await self.send_request("search", data)

    async def create_user(
        self,
        username: str,
        password: str,
        nickname: str | None = None,
        groups: list | None = None,
    ) -> dict[str, Any]:
        """
        Create a new user.

        Args:
            username: Username for the new user
            password: Password for the new user
            nickname: Optional nickname
            groups: Optional list of group assignments

        Returns:
            Response with created user information
        """
        data: dict[str, Any] = {"username": username, "password": password}
        if nickname is not None:
            data["nickname"] = nickname
        if groups is not None:
            data["groups"] = groups
        return await self.send_request("create_user", data)

    async def delete_user(self, username: str) -> dict[str, Any]:
        """
        Delete a user.

        Args:
            username: Username of the user to delete

        Returns:
            Response indicating success or failure
        """
        return await self.send_request("delete_user", {"username": username})

    async def get_user_info(self, username: str) -> dict[str, Any]:
        """
        Get information about a user.

        Args:
            username: Username of the user

        Returns:
            User information
        """
        return await self.send_request("get_user_info", {"username": username})

    async def change_user_permissions(
        self, username: str, permissions: list[str]
    ) -> dict[str, Any]:
        return await self.send_request(
            "change_user_permissions",
            {"username": username, "permissions": permissions},
        )

    async def list_users(
        self, count: int | None = None, offset: int | None = None
    ) -> dict[str, Any]:
        """
        List all users.

        Args:
            count: Optional maximum number of users to return
            offset: Optional number of users to skip

        Returns:
            List of users
        """
        data: dict[str, Any] = {}
        if count is not None:
            data["count"] = count
        if offset is not None:
            data["offset"] = offset
        return await self.send_request("list_users", data)

    async def create_group(
        self, group_name: str, permissions: list | None = None
    ) -> dict[str, Any]:
        """
        Create a new user group.

        Args:
            group_name: Name of the group
            permissions: Optional list of permissions

        Returns:
            Response with created group information
        """
        data: dict[str, Any] = {"group_name": group_name}
        if permissions is not None:
            data["permissions"] = permissions
        return await self.send_request("create_group", data)

    async def list_groups(
        self, count: int | None = None, offset: int | None = None
    ) -> dict[str, Any]:
        """
        List all user groups.

        Returns:
            List of groups
        """
        data: dict[str, Any] = {}
        if count is not None:
            data["count"] = count
        if offset is not None:
            data["offset"] = offset
        return await self.send_request("list_groups", data)

    async def get_group_info(self, group_name: str) -> dict[str, Any]:
        """
        Get information about a group.

        Args:
            group_name: Name of the group

        Returns:
            Group information
        """
        return await self.send_request("get_group_info", {"group_name": group_name})

    async def download_file_from_server(self, dl_task_id: str, dest_path: str):
        if self.multiplexer is None:
            raise RuntimeError("Not connected (multiplexing missing).")

        stream = self.multiplexer.open_stream()
        frame = await self._build_and_send_request(
            stream,
            "download_file",
            {"task_id": dl_task_id, "offset": 0, "max_chunk_size": 64 * 1024},
            include_auth=True,
        )

        # 1. Parse initial transfer_file frame
        response = await self._parse_frame_data(frame)
        if isinstance(response, dict) and response.get("code") not in (None, 200):
            raise RuntimeError(
                f"Download failed ({response.get('code')}): {response.get('message', 'Unknown error')}"
            )
        if not isinstance(response, dict) or response.get("action") != "transfer_file":
            raise ValueError(f"Invalid response: {response}")

        # 2. Tell server we are ready
        await stream.send(b"ready")

        chunks = []
        aes_key = None
        empty_file = False

        while True:
            recv_frame = await stream.recv()
            if recv_frame is None:
                break
            raw_reply = recv_frame.data
            if isinstance(raw_reply, bytes):
                msg = orjson.loads(raw_reply.decode("utf-8"))
            elif isinstance(raw_reply, memoryview):
                msg = orjson.loads(raw_reply.tobytes().decode("utf-8"))
            elif isinstance(raw_reply, str):
                msg = orjson.loads(raw_reply)
            else:
                msg = raw_reply

            action = msg.get("action")
            if action == "file_chunk":
                chunk_data = msg["data"]
                encrypted_chunk = base64.b64decode(chunk_data["chunk"])
                tag = base64.b64decode(chunk_data["tag"])
                prefix = base64.b64decode(chunk_data["prefix"])
                index = chunk_data["index"]
                chunks.append((index, encrypted_chunk, tag, prefix))
            elif action == "aes_key":
                aes_key = base64.b64decode(msg["data"]["key"])
                break
            elif action == "transfer_file" and msg.get("data", {}).get("flag") == (
                "empty_file"
            ):
                empty_file = True
                break
            elif action == "abort":
                raise RuntimeError("Server aborted file transfer")

        if empty_file:
            Path(dest_path).write_bytes(b"")
        else:
            if not aes_key:
                raise RuntimeError("Did not receive AES key")

            chunks.sort(key=lambda x: x[0])
            with open(dest_path, "wb") as f:
                for index, encrypted_chunk, tag, prefix in chunks:
                    nonce = prefix + index.to_bytes(4, "big")
                    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
                    decrypted_chunk = cipher.decrypt_and_verify(encrypted_chunk, tag)
                    f.write(decrypted_chunk)

        await stream.send(b"complete")
        completion = await self._parse_frame_data(await stream.recv())
        if (
            not isinstance(completion, dict)
            or completion.get("action") != "transfer_complete"
        ):
            raise RuntimeError("Server did not confirm file transfer completion")

    async def upload_file_to_server(
        self,
        task_id: str,
        file_path: str,
        *,
        restart: bool = False,
        max_chunk_size: int = 64 * 1024,
    ):
        """
        Upload a file to the server over WebSocket connection.

        Args:
            task_id: Server task ID for this upload
            file_path: Local path to the file to upload

        Raises:
            ValueError: If server response is invalid
            RuntimeError: If upload is rejected by server
        """

        if not os.path.isfile(file_path):
            raise FileNotFoundError(f"Upload source file not found: {file_path}")

        file_size = os.path.getsize(file_path)
        sha256 = calculate_sha256(file_path) if file_size else None

        # Start stream for file upload negotiation + transfer
        if self.multiplexer is None:
            raise RuntimeError("Not connected (multiplexing missing).")

        stream = self.multiplexer.open_stream()
        frame = await self._build_and_send_request(
            stream,
            "upload_file",
            {
                "task_id": task_id,
                "file_size": file_size,
                "sha256": sha256,
                "max_chunk_size": max_chunk_size,
                "restart": restart,
            },
            include_auth=True,
        )

        response = await self._parse_frame_data(frame)
        if isinstance(response, dict) and response.get("code") not in (None, 200):
            raise RuntimeError(
                f"Upload failed ({response.get('code')}): {response.get('message', 'Unknown error')}"
            )
        if not isinstance(response, dict) or response.get("action") != "transfer_file":
            raise ValueError("Invalid action received for file transfer")

        transfer_data = response.get("data", {})
        chunk_size = transfer_data.get("chunk_size")
        offset = transfer_data.get("offset")
        if (
            transfer_data.get("file_size") != file_size
            or not isinstance(chunk_size, int)
            or not isinstance(offset, int)
            or offset < 0
            or offset > file_size
        ):
            raise RuntimeError("Invalid resumable upload response")

        with open(file_path, "rb") as f:
            f.seek(offset)
            while offset < file_size:
                chunk = f.read(min(chunk_size, file_size - offset))
                if not chunk:
                    raise RuntimeError("Upload source ended before declared file size")
                await stream.send(chunk)
                offset += len(chunk)

        server_frame = await stream.recv()
        return await self._parse_frame_data(server_frame)

    # def receive_file_from_server(
    #     self,
    #     task_id: str,
    #     file_path: str,  # filename: str | None = None
    # ):
    #     """
    #     Receives a file from the server over a websocket connection using AES encryption.

    #     Steps:
    #         1. Requests file metadata (SHA-256 hash, file size, chunk info) from the server.
    #         2. Sends readiness acknowledgment to the server.
    #         3. Receives encrypted file chunks, saves them temporarily.
    #         4. Receives AES key and tag, decrypts all chunks, verifies tag, and writes the output file.
    #         5. Deletes temporary chunk files.
    #         6. Verifies the file size and SHA-256 hash.
    #         7. Removes the output file if verification fails.

    #     Args:
    #         client (ClientConnection): The websocket client connection.
    #         task_id (str): The identifier for the file transfer task.
    #         file_path (str): The path to save the received file.

    #     Yields:
    #         tuple[int, ...]: Progress updates at various stages.

    #     Raises:
    #         ValueError: If the server response is invalid.
    #         FileSizeMismatchError: If the received file size does not match the expected size.
    #         FileHashMismatchError: If the received file hash does not match the expected hash.
    #         Exception: For other errors during transfer or decryption.
    #     """

    #     assert self.websocket

    #     # Send the request for file metadata
    #     self.websocket.send(
    #         orjson.dumps(
    #             {
    #                 "action": "download_file",
    #                 "data": {"task_id": task_id},
    #             },
    #
    #         )
    #     )

    #     # Receive file metadata from the server
    #     response = orjson.loads(self.websocket.recv())
    #     if response["action"] != "transfer_file":
    #         raise ValueError("Invalid action received for file transfer")

    #     sha256 = response["data"].get("sha256")  # SHA256 of original file
    #     file_size = response["data"].get("file_size")  # Size of original file
    #     chunk_size = response["data"].get("chunk_size", 8192)  # Chunk size
    #     total_chunks = response["data"].get("total_chunks")  # Total chunks

    #     self.websocket.send("ready")

    #     downloading_path = FLET_APP_STORAGE_TEMP + "/downloading/" + task_id
    #     await aiofiles.os.makedirs(downloading_path, exist_ok=True)

    #     if not file_size:
    #         async with aiofiles.open(file_path, "wb") as f:
    #             await f.truncate(0)
    #         return

    #     try:

    #         received_chunks = 0
    #         nonce: bytes = b""

    #         while received_chunks + 1 <= total_chunks:
    #             # Receive encrypted data from the server

    #             data = await self.recv()
    #             if not data:
    #                 raise ValueError("Received empty data from server")

    #             data_json: dict = orjson.loads(data)

    #             index = data_json["data"].get("index")
    #             if index == 0:
    #                 nonce = base64.b64decode(data_json["data"].get("nonce"))
    #             chunk_hash = data_json["data"].get("hash")  # provided but unused
    #             chunk_data = base64.b64decode(data_json["data"].get("chunk"))
    #             chunk_file_path = os.path.join(downloading_path, str(index))

    #             async with aiofiles.open(chunk_file_path, "wb") as chunk_file:
    #                 await chunk_file.write(chunk_data)

    #             received_chunks += 1

    #             if received_chunks < total_chunks:
    #                 received_file_size = chunk_size * received_chunks
    #             else:
    #                 received_file_size = file_size

    #             yield 0, received_file_size, file_size

    #         # Get decryption information
    #         decrypted_data = await self.recv()
    #         decrypted_data_json: dict = orjson.loads(decrypted_data)

    #         aes_key = base64.b64decode(decrypted_data_json["data"].get("key"))
    #         tag = base64.b64decode(decrypted_data_json["data"].get("tag"))

    #         # Decrypt chunks
    #         decrypted_chunks = 1
    #         cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)  # Initialize cipher

    #         async with aiofiles.open(file_path, "wb") as out_file:
    #             while decrypted_chunks <= total_chunks:
    #                 yield 1, decrypted_chunks, total_chunks

    #                 chunk_file_path = os.path.join(
    #                     downloading_path, str(decrypted_chunks - 1)
    #                 )

    #                 async with aiofiles.open(chunk_file_path, "rb") as chunk_file:
    #                     encrypted_chunk = await chunk_file.read()
    #                     decrypted_chunk = cipher.decrypt(encrypted_chunk)
    #                     await out_file.write(decrypted_chunk)

    #                 # os.remove(chunk_file_path)
    #                 decrypted_chunks += 1
    #         try:
    #             cipher.verify(tag)
    #         except ValueError:
    #             raise ValueError("MAC tag verification failed!")

    #         # Delete temporary folder
    #         yield 2,

    #         await asyncio.get_event_loop().run_in_executor(
    #             None, shutil.rmtree, downloading_path
    #         )

    #     except Exception:
    #         raise

    #     # Verify file

    #     async def _action_verify() -> None:

    #         if file_size != await aiofiles.os.path.getsize(file_path):
    #             raise FileSizeMismatchError(
    #                 file_size, await aiofiles.os.path.getsize(file_path)
    #             )

    #         # Verify SHA256
    #         actual_sha256 = await calculate_sha256(file_path)
    #         if sha256 and actual_sha256 != sha256:
    #             raise FileHashMismatchError(sha256, actual_sha256)

    #     yield 3,

    #     try:
    #         await _action_verify()
    #     except Exception:
    #         await aiofiles.os.remove(file_path)
    #         raise

    async def __aenter__(self):
        """Async context manager entry."""
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.disconnect()

    # Two-Factor Authentication methods

    async def setup_2fa(self) -> dict[str, Any]:
        """
        Setup two-factor authentication for the authenticated user.

        Returns:
            Response with TOTP secret, provisioning URI, and backup codes
        """
        return await self.send_request("setup_2fa", {})

    async def validate_2fa(self, token: str) -> dict[str, Any]:
        """
        Validate and enable two-factor authentication.

        Args:
            token: TOTP token from authenticator app

        Returns:
            Response indicating success or failure
        """
        return await self.send_request("validate_2fa", {"token": token})

    async def cancel_2fa_setup(self) -> dict[str, Any]:
        """
        Cancel two-factor authentication setup (before validation).

        Returns:
            Response indicating success or failure
        """
        return await self.send_request("cancel_2fa_setup", {})

    async def cancel_2fa(self, password: str) -> dict[str, Any]:
        """
        Cancel two-factor authentication for the authenticated user.

        Args:
            password: User's password for verification

        Returns:
            Response indicating success or failure
        """
        return await self.send_request("disable_2fa", {"password": password})

    async def get_2fa_status(self) -> dict[str, Any]:
        """
        Get two-factor authentication status for the authenticated user.

        Returns:
            Response with 2FA status information
        """
        return await self.send_request("get_2fa_status", {})

    async def grant_access(
        self,
        entity_type: str,
        entity_identifier: str,
        target_type: str,
        target_identifier: str,
        access_types: list[str],
        start_time: float,
        end_time: float | None = None,
    ) -> dict[str, Any]:
        """
        Grant access to a user or group for a document or directory.

        Args:
            entity_type: Type of entity ("user" or "group")
            entity_identifier: Username or group name
            target_type: Type of target ("document" or "directory")
            target_identifier: Document or folder ID
            access_types: List of access types to grant
            start_time: When access starts (timestamp)
            end_time: When access ends (timestamp, optional)

        Returns:
            Response indicating success or failure
        """
        data: dict[str, Any] = {
            "entity_type": entity_type,
            "entity_identifier": entity_identifier,
            "target_type": target_type,
            "target_identifier": target_identifier,
            "access_types": access_types,
            "start_time": start_time,
        }
        if end_time is not None:
            data["end_time"] = end_time
        return await self.send_request("grant_access", data)

    async def revoke_access(self, entry_id: int) -> dict[str, Any]:
        """
        Revoke access by deleting an access entry.

        Args:
            entry_id: ID of the access entry to revoke

        Returns:
            Response indicating success or failure
        """
        return await self.send_request("revoke_access", {"entry_id": entry_id})

    async def view_access_entries(
        self,
        object_type: str,
        object_identifier: str,
        page_size: int | None = None,
        cursor: str | None = None,
    ) -> dict[str, Any]:
        """
        View access entries for a user, group, document, or directory.

        Args:
            object_type: Type of object ("user", "group", "document", or "directory")
            object_identifier: Identifier of the object

        Returns:
            Response with list of access entries
        """
        data: dict[str, Any] = {
            "object_type": object_type,
            "object_identifier": object_identifier,
        }
        if page_size is not None:
            data["page_size"] = page_size
        if cursor is not None:
            data["cursor"] = cursor
        return await self.send_request("view_access_entries", data)

    # Keyring methods

    async def upload_keyring(
        self,
        key_content: str,
        label: str | None = None,
        target_username: str | None = None,
    ) -> dict[str, Any]:
        data: dict[str, Any] = {"content": key_content}
        if label is not None:
            data["label"] = label
        if target_username is not None:
            data["target_username"] = target_username
        return await self.send_request("upload_user_key", data)

    async def get_keyring(
        self,
        key_id: str,
    ) -> dict[str, Any]:
        return await self.send_request("get_user_key", {"id": key_id})

    async def delete_keyring(
        self,
        key_id: str,
    ) -> dict[str, Any]:
        return await self.send_request("delete_user_key", {"id": key_id})

    async def set_preference_keyring(
        self,
        key_id: str,
    ) -> dict[str, Any]:
        return await self.send_request("set_user_preference_dek", {"id": key_id})

    async def list_keyrings(
        self,
        target_username: str | None = None,
        count: int | None = None,
        offset: int | None = None,
    ) -> dict[str, Any]:
        data: dict[str, Any] = {}
        if target_username is not None:
            data["target_username"] = target_username
        if count is not None:
            data["count"] = count
        if offset is not None:
            data["offset"] = offset
        return await self.send_request("list_user_keys", data)

    # ------------------------------------------------------------------------
    # System and Management Functions
    # ------------------------------------------------------------------------
    async def list_banned_subnets(
        self,
        page_size: int | None = None,
        cursor: str | None = None,
        status: str | None = None,
    ) -> dict[str, Any]:
        data: dict[str, Any] = {}
        if page_size is not None:
            data["page_size"] = page_size
        if cursor is not None:
            data["cursor"] = cursor
        if status is not None:
            data["status"] = status
        return await self.send_request("list_banned_subnets", data)

    async def create_banned_subnet(
        self,
        subnet: str,
        reason: str | None = None,
        starts_at: float | None = None,
        expires_at: float | None = None,
        confirm_self_block: bool = False,
    ) -> dict[str, Any]:
        data: dict[str, Any] = {"subnet": subnet}
        if reason is not None:
            data["reason"] = reason
        if starts_at is not None:
            data["starts_at"] = starts_at
        if expires_at is not None:
            data["expires_at"] = expires_at
        if confirm_self_block:
            data["confirm_self_block"] = True
        return await self.send_request("create_banned_subnet", data)

    async def update_banned_subnet(
        self,
        subnet: str,
        **changes: Any,
    ) -> dict[str, Any]:
        return await self.send_request(
            "update_banned_subnet", {"subnet": subnet, **changes}
        )

    async def delete_banned_subnet(self, subnet: str) -> dict[str, Any]:
        return await self.send_request("delete_banned_subnet", {"subnet": subnet})

    async def list_auth_lockouts(
        self,
        page_size: int | None = None,
        cursor: str | None = None,
        **filters: str,
    ) -> dict[str, Any]:
        data: dict[str, Any] = dict(filters)
        if page_size is not None:
            data["page_size"] = page_size
        if cursor is not None:
            data["cursor"] = cursor
        return await self.send_request("list_auth_lockouts", data)

    async def unlock_auth_lockouts(
        self, locks: list[dict[str, str]], reason: str
    ) -> dict[str, Any]:
        return await self.send_request(
            "unlock_auth_lockouts", {"locks": locks, "reason": reason}
        )

    async def set_lockdown(
        self, status: bool, reason: str | None = None
    ) -> dict[str, Any]:
        """Enable or disable global lockdown."""
        data: dict[str, Any] = {"status": status}
        if reason is not None:
            data["reason"] = reason
        return await self.send_request("lockdown", data)

    async def update_user_status(
        self, username: str, status: str, reason: str | None = None
    ) -> dict[str, Any]:
        """Update user status ('active' or 'disabled')."""
        data = {"username": username, "status": status}
        if reason is not None:
            data["reason"] = reason
        return await self.send_request("manage_user_status", data)

    async def block_user(
        self,
        username: str,
        target_type: str,
        block_types: list[str],
        target_id: str | None = None,
    ) -> dict[str, Any]:
        """Block user from accessing certain things.
        target_type: "all", "directory", "document"
        block_types: e.g. ["read", "write"]
        """
        data = {
            "username": username,
            "target": {"type": target_type},
            "block_types": block_types,
        }
        if target_id is not None:
            data["target"]["id"] = target_id

        return await self.send_request("block_user", data)

    async def view_audit_logs(
        self,
        page_size: int | None = None,
        cursor: str | None = None,
        filters: list[str] | None = None,
    ) -> dict[str, Any]:
        """View system audit logs."""
        data: dict[str, Any] = {}
        if page_size is not None:
            data["page_size"] = page_size
        if cursor is not None:
            data["cursor"] = cursor
        if filters is not None:
            data["filters"] = filters
        return await self.send_request("view_audit_logs", data)
