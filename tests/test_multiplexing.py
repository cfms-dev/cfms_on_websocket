import asyncio
import threading
import time

import pytest

from include.domains.operations.broadcast import on_global_broadcast
from include.shared import clients, clients_lock
from include.transport.multiplexing import (
    OUTBOUND_QUEUE_SIZE,
    FrameType,
    MultiplexConnection,
)
from tests.test_client import AsyncMultiplexConnection


class _IdleWebSocket:
    def __init__(self):
        self.sent = []
        self._closed = asyncio.Event()

    async def recv(self):
        await self._closed.wait()
        return b""

    async def send(self, payload):
        self.sent.append(payload)

    async def close(self):
        self._closed.set()


@pytest.mark.asyncio
async def test_test_client_uses_odd_client_stream_ids():
    websocket = _IdleWebSocket()
    connection = AsyncMultiplexConnection(websocket)

    try:
        first = connection.create_stream()
        second = connection.create_stream()
        third = connection.create_stream()

        assert first.frame_id == 1
        assert second.frame_id == 3
        assert third.frame_id == 5
    finally:
        await connection.close()


class _OpenState:
    name = "OPEN"


class _Protocol:
    state = _OpenState()


class _SyncWebSocket:
    def __init__(
        self, *, block_send: bool = False, send_error: Exception | None = None
    ):
        self.remote_address = ("127.0.0.1", 12345)
        self.protocol = _Protocol()
        self.sent = []
        self.closed = threading.Event()
        self.send_entered = threading.Event()
        self.release_send = threading.Event()
        self.block_send = block_send
        self.send_error = send_error

    def recv(self):
        self.closed.wait()
        raise RuntimeError("closed")

    def send(self, payload):
        self.send_entered.set()
        if self.block_send:
            self.release_send.wait()
        if self.send_error is not None:
            raise self.send_error
        self.sent.append(payload)

    def close(self, *args, **kwargs):
        self.release_send.set()
        self.closed.set()


def test_stream_send_waits_until_writer_sends():
    websocket = _SyncWebSocket(block_send=True)
    connection = MultiplexConnection(websocket)
    stream = connection.create_stream()
    done = threading.Event()

    sender = threading.Thread(
        target=lambda: (stream.send(b"payload", FrameType.PROCESS), done.set())
    )
    sender.start()

    try:
        assert websocket.send_entered.wait(timeout=1)
        assert not done.wait(timeout=0.05)

        websocket.release_send.set()
        assert done.wait(timeout=1)
        sender.join(timeout=1)
        assert len(websocket.sent) == 1
    finally:
        connection.close()


def test_stream_send_nowait_does_not_wait_for_socket_io():
    websocket = _SyncWebSocket(block_send=True)
    connection = MultiplexConnection(websocket)
    stream = connection.create_stream()

    try:
        assert stream.send_nowait(b"payload", FrameType.PROCESS) is True
        assert websocket.send_entered.wait(timeout=1)
        assert websocket.sent == []

        websocket.release_send.set()
        deadline = time.monotonic() + 1
        while not websocket.sent and time.monotonic() < deadline:
            time.sleep(0.01)
        assert len(websocket.sent) == 1
    finally:
        connection.close()


def test_stream_send_nowait_returns_false_when_queue_is_full():
    websocket = _SyncWebSocket(block_send=True)
    connection = MultiplexConnection(websocket)

    try:
        assert connection.create_stream().send_nowait(b"blocked") is True
        assert websocket.send_entered.wait(timeout=1)

        for _ in range(OUTBOUND_QUEUE_SIZE):
            assert connection.create_stream().send_nowait(b"queued") is True

        assert connection.create_stream().send_nowait(b"overflow") is False
    finally:
        connection.close()


def test_stream_send_nowait_conclusion_removes_stream_when_queued():
    websocket = _SyncWebSocket(block_send=True)
    connection = MultiplexConnection(websocket)
    stream = connection.create_stream()

    try:
        assert stream.frame_id in connection._streams
        assert stream.send_nowait(b"done", FrameType.CONCLUSION) is True
        assert stream.frame_id not in connection._streams
    finally:
        connection.close()


def test_stream_send_nowait_conclusion_keeps_stream_when_queue_is_full():
    websocket = _SyncWebSocket(block_send=True)
    connection = MultiplexConnection(websocket)

    try:
        assert connection.create_stream().send_nowait(b"blocked") is True
        assert websocket.send_entered.wait(timeout=1)

        for _ in range(OUTBOUND_QUEUE_SIZE):
            assert connection.create_stream().send_nowait(b"queued") is True

        stream = connection.create_stream()
        assert stream.send_nowait(b"overflow", FrameType.CONCLUSION) is False
        assert stream.frame_id in connection._streams
    finally:
        connection.close()


def test_stream_send_raises_when_writer_fails():
    websocket = _SyncWebSocket(send_error=OSError("boom"))
    connection = MultiplexConnection(websocket)
    stream = connection.create_stream()

    try:
        with pytest.raises(ConnectionError):
            stream.send(b"payload", FrameType.PROCESS)
    finally:
        connection.close()


def test_concurrent_stream_sends_are_serialized_by_writer():
    websocket = _SyncWebSocket()
    connection = MultiplexConnection(websocket)
    barrier = threading.Barrier(6)
    errors = []

    def send_from_thread(index: int):
        try:
            stream = connection.create_stream()
            barrier.wait(timeout=1)
            stream.send(f"payload-{index}".encode(), FrameType.PROCESS)
        except Exception as exc:
            errors.append(exc)

    threads = [
        threading.Thread(target=send_from_thread, args=(index,)) for index in range(5)
    ]

    try:
        for thread in threads:
            thread.start()

        barrier.wait(timeout=1)

        for thread in threads:
            thread.join(timeout=1)

        assert errors == []
        assert len(websocket.sent) == 5
    finally:
        connection.close()


def test_broadcast_does_not_wait_for_slow_client():
    websocket = _SyncWebSocket(block_send=True)
    connection = MultiplexConnection(websocket)
    done = threading.Event()

    with clients_lock:
        clients.add(connection)

    broadcaster = threading.Thread(
        target=lambda: (on_global_broadcast("hello"), done.set())
    )
    broadcaster.start()

    try:
        assert done.wait(timeout=1)
        assert websocket.send_entered.wait(timeout=1)
        assert websocket.sent == []
    finally:
        with clients_lock:
            clients.discard(connection)
        connection.close()
        broadcaster.join(timeout=1)
