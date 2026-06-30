import asyncio
import queue
import threading
import time

import pytest

from include.domains.operations import broadcast as broadcast_module
from include.domains.operations.broadcast import on_global_broadcast
from include.shared import clients, clients_lock
from include.transport import multiplexing as multiplexing_module
from include.transport.multiplexing import (
    FRAME_HEADER,
    FRAME_HEADER_SIZE,
    OUTBOUND_QUEUE_SIZE,
    Frame,
    FrameType,
    MultiplexedConnection,
    Stream,
    encode_frame,
)
from tests.test_client import AsyncMultiplexConnection

_ORIGINAL_QUEUE = queue.Queue


class _IdleWebSocket:
    def __init__(self):
        self.sent = []
        self._closed = asyncio.Event()

    async def recv(self, decode=None):
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
        first = connection.open_stream()
        second = connection.open_stream()
        third = connection.open_stream()

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

    def recv(self, timeout=None, decode=None):
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


class _BlockingPutSignalingQueue(_ORIGINAL_QUEUE):
    def __init__(self, maxsize: int, put_blocked: threading.Event) -> None:
        super().__init__(maxsize)
        self.put_blocked = put_blocked

    def put(self, item, block=True, timeout=None):
        with self.mutex:
            if block and self.maxsize > 0 and self._qsize() >= self.maxsize:
                self.put_blocked.set()
        return super().put(item, block=block, timeout=timeout)


def test_stream_send_waits_until_writer_sends():
    websocket = _SyncWebSocket(block_send=True)
    connection = MultiplexedConnection(websocket)
    stream = connection.open_stream()
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
    connection = MultiplexedConnection(websocket)
    stream = connection.open_stream()

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
    connection = MultiplexedConnection(websocket)

    try:
        assert connection.open_stream().send_nowait(b"blocked") is True
        assert websocket.send_entered.wait(timeout=1)

        for _ in range(OUTBOUND_QUEUE_SIZE):
            assert connection.open_stream().send_nowait(b"queued") is True

        assert connection.open_stream().send_nowait(b"overflow") is False
    finally:
        connection.close()


def test_stream_send_nowait_conclusion_removes_stream_when_queued():
    websocket = _SyncWebSocket(block_send=True)
    connection = MultiplexedConnection(websocket)
    stream = connection.open_stream()

    try:
        assert stream.frame_id in connection._streams
        assert stream.send_nowait(b"done", FrameType.CONCLUSION) is True
        assert stream.frame_id not in connection._streams
    finally:
        connection.close()


def test_stream_send_nowait_conclusion_keeps_stream_when_queue_is_full():
    websocket = _SyncWebSocket(block_send=True)
    connection = MultiplexedConnection(websocket)

    try:
        assert connection.open_stream().send_nowait(b"blocked") is True
        assert websocket.send_entered.wait(timeout=1)

        for _ in range(OUTBOUND_QUEUE_SIZE):
            assert connection.open_stream().send_nowait(b"queued") is True

        stream = connection.open_stream()
        assert stream.send_nowait(b"overflow", FrameType.CONCLUSION) is False
        assert stream.frame_id in connection._streams
    finally:
        connection.close()


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        (b"payload", b"payload"),
        ("payload", b"payload"),
        (bytearray(b"payload"), b"payload"),
        (memoryview(b"payload"), b"payload"),
    ],
)
def test_encode_frame_accepts_supported_payload_types(data, expected):
    payload = encode_frame(2, FrameType.PROCESS, data)

    assert FRAME_HEADER.unpack_from(payload) == (2, FrameType.PROCESS.value)
    assert payload[FRAME_HEADER_SIZE:] == expected


def test_frame_uses_stream_id_field():
    frame = Frame(stream_id=3, frame_type=FrameType.PROCESS, data=b"payload")

    assert frame.stream_id == 3


def test_encode_frame_rejects_unsupported_payload_type():
    with pytest.raises(TypeError, match="Frame data must be"):
        encode_frame(2, FrameType.PROCESS, None)


def test_stream_recv_timeout_raises_timeout_error():
    connection = MultiplexedConnection.__new__(MultiplexedConnection)
    stream = Stream(connection, 2)

    with pytest.raises(TimeoutError):
        stream.recv(timeout=0.01)


def test_open_stream_raises_after_connection_close():
    websocket = _SyncWebSocket()
    connection = MultiplexedConnection(websocket)

    connection.close()

    with pytest.raises(ConnectionError):
        connection.open_stream()


def test_stream_send_nowait_returns_false_after_connection_close():
    websocket = _SyncWebSocket()
    connection = MultiplexedConnection(websocket)
    stream = connection.open_stream()

    connection.close()

    assert stream.send_nowait(b"payload", FrameType.PROCESS) is False
    assert websocket.sent == []


def test_close_unblocks_send_waiting_for_outbound_queue_space(monkeypatch):
    outbound_put_blocked = threading.Event()

    def queue_factory(maxsize=0):
        if maxsize == OUTBOUND_QUEUE_SIZE:
            return _BlockingPutSignalingQueue(maxsize, outbound_put_blocked)
        return _ORIGINAL_QUEUE(maxsize)

    monkeypatch.setattr(multiplexing_module.queue, "Queue", queue_factory)

    websocket = _SyncWebSocket(block_send=True)
    connection = MultiplexedConnection(websocket)
    done = threading.Event()
    errors = []

    def send_when_queue_is_full():
        try:
            connection.open_stream().send(b"blocked-on-queue", FrameType.PROCESS)
        except Exception as exc:
            errors.append(exc)
        finally:
            done.set()

    try:
        assert connection.open_stream().send_nowait(b"blocked") is True
        assert websocket.send_entered.wait(timeout=1)

        for _ in range(OUTBOUND_QUEUE_SIZE):
            assert connection.open_stream().send_nowait(b"queued") is True

        sender = threading.Thread(target=send_when_queue_is_full)
        sender.start()
        assert outbound_put_blocked.wait(timeout=1)

        connection.close()

        assert done.wait(timeout=1)
        sender.join(timeout=1)
        assert len(errors) == 1
        assert isinstance(errors[0], ConnectionError)
    finally:
        websocket.release_send.set()
        connection.close()


def test_stream_send_raises_when_writer_fails():
    websocket = _SyncWebSocket(send_error=OSError("boom"))
    connection = MultiplexedConnection(websocket)
    stream = connection.open_stream()

    try:
        with pytest.raises(ConnectionError):
            stream.send(b"payload", FrameType.PROCESS)
    finally:
        connection.close()


def test_pending_stream_sends_preserve_writer_failure_cause():
    send_error = OSError("boom")
    websocket = _SyncWebSocket(block_send=True, send_error=send_error)
    connection = MultiplexedConnection(websocket)
    errors = []

    def send_and_capture(index: int):
        try:
            stream = connection.open_stream()
            stream.send(f"payload-{index}".encode(), FrameType.PROCESS)
        except Exception as exc:
            errors.append(exc)

    threads = [
        threading.Thread(target=send_and_capture, args=(index,)) for index in range(4)
    ]

    try:
        threads[0].start()
        assert websocket.send_entered.wait(timeout=1)

        for thread in threads[1:]:
            thread.start()

        deadline = time.monotonic() + 1
        while connection._pending_outbound_frames.qsize() < len(threads) - 1:
            if time.monotonic() >= deadline:
                break
            time.sleep(0.01)

        assert connection._pending_outbound_frames.qsize() == len(threads) - 1
        websocket.release_send.set()

        for thread in threads:
            thread.join(timeout=1)

        assert len(errors) == len(threads)
        assert all(isinstance(exc, ConnectionError) for exc in errors)
        assert all(exc.__cause__ is send_error for exc in errors)
    finally:
        websocket.release_send.set()
        connection.close()
        for thread in threads:
            thread.join(timeout=1)


def test_concurrent_stream_sends_are_serialized_by_writer():
    websocket = _SyncWebSocket()
    connection = MultiplexedConnection(websocket)
    barrier = threading.Barrier(6)
    errors = []

    def send_from_thread(index: int):
        try:
            stream = connection.open_stream()
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
    connection = MultiplexedConnection(websocket)
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


def test_broadcast_logs_diagnostics_when_dropping_slow_client(monkeypatch):
    websocket = _SyncWebSocket(block_send=True)
    connection = MultiplexedConnection(websocket)
    warnings = []

    class _Logger:
        def warning(self, message):
            warnings.append(message)

    monkeypatch.setattr(broadcast_module, "logger", _Logger())

    try:
        assert connection.open_stream().send_nowait(b"blocked") is True
        assert websocket.send_entered.wait(timeout=1)

        for _ in range(OUTBOUND_QUEUE_SIZE):
            assert connection.open_stream().send_nowait(b"queued") is True

        with clients_lock:
            clients.add(connection)

        on_global_broadcast("hello")

        assert warnings == [
            "Dropped slow client during global broadcast: "
            "remote_address=('127.0.0.1', 12345), "
            f"outbound_queue_size={OUTBOUND_QUEUE_SIZE}"
        ]
    finally:
        with clients_lock:
            clients.discard(connection)
        connection.close()
