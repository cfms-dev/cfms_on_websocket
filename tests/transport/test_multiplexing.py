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
    MAX_PENDING_FRAMES_PER_STREAM,
    OUTBOUND_QUEUE_SIZE,
    ConnectionClosedError,
    CorruptedFrameError,
    Frame,
    FrameType,
    InvalidFrameError,
    InvalidFrameTypeError,
    MultiplexedConnection,
    Stream,
    decode_frame,
    encode_frame,
)
from tests.support.client import AsyncMultiplexConnection

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


class _InvalidFrameWebSocket(_SyncWebSocket):
    def recv(self, timeout=None, decode=None):
        return b"bad"


class _InboundFloodWebSocket(_SyncWebSocket):
    def __init__(self, frames):
        super().__init__()
        self.frames = iter(frames)
        self.recv_count = 0

    def recv(self, timeout=None, decode=None):
        frame = next(self.frames)
        self.recv_count += 1
        return frame


class _BlockingCloseWebSocket(_SyncWebSocket):
    def __init__(self, *, block_send: bool = False):
        super().__init__(block_send=block_send)
        self.close_entered = threading.Event()
        self.release_close = threading.Event()
        self.close_calls = []

    def close(self, *args, **kwargs):
        self.close_calls.append((args, kwargs))
        self.close_entered.set()
        self.release_close.wait()
        super().close(*args, **kwargs)


class _BlockingPutSignalingQueue(_ORIGINAL_QUEUE):
    def __init__(self, maxsize: int, put_blocked: threading.Event) -> None:
        super().__init__(maxsize)
        self.put_blocked = put_blocked

    def put(self, item, block=True, timeout=None):
        with self.mutex:
            if block and self.maxsize > 0 and self._qsize() >= self.maxsize:
                self.put_blocked.set()
        return super().put(item, block=block, timeout=timeout)


class _ShutdownRaceQueue(_ORIGINAL_QUEUE):
    def __init__(self) -> None:
        super().__init__()
        self.put_started = threading.Event()
        self.continue_put = threading.Event()

    def put(self, item, block=True, timeout=None):
        self.put_started.set()
        self.continue_put.wait()
        return super().put(item, block=block, timeout=timeout)


def _finish_connection_close(connection, websocket) -> None:
    connection.close()
    websocket.close(code=connection.close_code, reason=connection.close_reason)


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
        _finish_connection_close(connection, websocket)


def test_pending_inbound_stream_limit_closes_flooding_connection():
    websocket = _InboundFloodWebSocket(
        encode_frame(stream_id, FrameType.PROCESS, b"request")
        for stream_id in (1, 3, 5)
    )
    connection = MultiplexedConnection(websocket, max_pending_inbound_streams=2)

    try:
        connection._dispatcher.join(timeout=1)
        assert not connection._dispatcher.is_alive()
        assert not websocket.closed.is_set()
        assert connection.close_code == 1013
        assert connection.close_reason == "Too many pending request streams"
    finally:
        _finish_connection_close(connection, websocket)


def test_inbound_stream_queue_overload_closes_without_blocking_dispatcher():
    frames = [
        encode_frame(1, FrameType.PROCESS, b"queued")
        for _ in range(MAX_PENDING_FRAMES_PER_STREAM + 1)
    ]
    frames.append(encode_frame(3, FrameType.PROCESS, b"must-not-be-dispatched"))
    websocket = _InboundFloodWebSocket(frames)
    connection = MultiplexedConnection(websocket)

    try:
        connection._dispatcher.join(timeout=1)

        assert not connection._dispatcher.is_alive()
        assert websocket.recv_count == MAX_PENDING_FRAMES_PER_STREAM + 1
        assert not websocket.closed.is_set()
        assert connection.close_code == 1013
        assert connection.close_reason == "Too many pending frames for one stream"
        assert connection.accept_stream() is None
    finally:
        _finish_connection_close(connection, websocket)


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
        _finish_connection_close(connection, websocket)


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
        _finish_connection_close(connection, websocket)


def test_stream_send_nowait_conclusion_removes_stream_when_queued():
    websocket = _SyncWebSocket(block_send=True)
    connection = MultiplexedConnection(websocket)
    stream = connection.open_stream()

    try:
        assert stream.frame_id in connection._streams
        assert stream.send_nowait(b"done", FrameType.CONCLUSION) is True
        assert stream.frame_id not in connection._streams
    finally:
        _finish_connection_close(connection, websocket)


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
        _finish_connection_close(connection, websocket)


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


def test_decode_frame_rejects_short_payload_with_structured_error():
    with pytest.raises(CorruptedFrameError) as excinfo:
        decode_frame(b"bad")

    error = excinfo.value
    assert isinstance(error, InvalidFrameError)
    assert error.actual_size == 3
    assert error.minimum_size == FRAME_HEADER_SIZE
    assert error.close_code == 1002
    assert error.close_reason == "Protocol error: invalid frame"
    assert str(error) == (
        f"Frame too short: 3 bytes, expected at least {FRAME_HEADER_SIZE} bytes"
    )


def test_decode_frame_rejects_unknown_frame_type_with_structured_error():
    payload = bytearray(FRAME_HEADER_SIZE)
    FRAME_HEADER.pack_into(payload, 0, 3, 99)

    with pytest.raises(InvalidFrameTypeError) as excinfo:
        decode_frame(payload)

    error = excinfo.value
    assert isinstance(error, InvalidFrameError)
    assert error.stream_id == 3
    assert error.frame_type_value == 99
    assert error.valid_frame_type_values == (0, 1)
    assert error.__cause__ is not None
    assert str(error) == "Invalid frame type 99 for stream 3; expected one of 0, 1"


def test_stream_recv_timeout_raises_timeout_error():
    connection = MultiplexedConnection.__new__(MultiplexedConnection)
    stream = Stream(connection, 2)

    with pytest.raises(TimeoutError):
        stream.recv(timeout=0.01)


def test_stream_recv_closed_raises_connection_closed_error():
    connection = MultiplexedConnection.__new__(MultiplexedConnection)
    stream = Stream(connection, 2)
    stream._close()

    with pytest.raises(ConnectionClosedError):
        stream.recv(timeout=0.01)


def test_connection_closed_error_has_default_message():
    assert str(ConnectionClosedError()) == "Connection has been closed"


def test_open_stream_raises_after_connection_close():
    websocket = _SyncWebSocket()
    connection = MultiplexedConnection(websocket)

    try:
        connection.close()

        with pytest.raises(ConnectionClosedError):
            connection.open_stream()
    finally:
        _finish_connection_close(connection, websocket)


def test_close_is_logical_only_and_first_call_wins():
    websocket = _BlockingCloseWebSocket()
    connection = MultiplexedConnection(websocket)
    close_returned = threading.Event()

    caller = threading.Thread(
        target=lambda: (
            connection.close(code=1013, reason="first close"),
            close_returned.set(),
        )
    )
    caller.start()

    try:
        assert close_returned.wait(timeout=1)
        caller.join(timeout=1)
        assert not websocket.close_entered.is_set()

        connection.close(code=1002, reason="second close")
        assert connection.close_code == 1013
        assert connection.close_reason == "first close"
        assert websocket.close_calls == []
    finally:
        websocket.release_close.set()
        websocket.release_send.set()
        _finish_connection_close(connection, websocket)
        assert websocket.closed.is_set()
        caller.join(timeout=1)


def test_close_wakes_all_accept_stream_waiters_and_preserves_pending_frames():
    websocket = _SyncWebSocket()
    connection = MultiplexedConnection(websocket)
    stream = connection.open_stream()
    pending_frames = [
        Frame(2, FrameType.PROCESS, b"first"),
        Frame(2, FrameType.CONCLUSION, b"second"),
    ]
    accepted = []
    barrier = threading.Barrier(4)

    for frame in pending_frames:
        assert stream._put_incoming_frame(frame)

    def accept_stream():
        barrier.wait(timeout=1)
        accepted.append(connection.accept_stream())

    accepters = [threading.Thread(target=accept_stream) for _ in range(3)]
    for accepter in accepters:
        accepter.start()

    try:
        barrier.wait(timeout=1)
        connection.close()

        for accepter in accepters:
            accepter.join(timeout=1)
            assert not accepter.is_alive()
        assert accepted == [None, None, None]
        assert [stream.recv(), stream.recv()] == pending_frames
        with pytest.raises(ConnectionClosedError):
            stream.recv(timeout=0.1)
    finally:
        _finish_connection_close(connection, websocket)
        for accepter in accepters:
            accepter.join(timeout=1)


def test_close_racing_with_incoming_frame_rejects_frame():
    connection = MultiplexedConnection.__new__(MultiplexedConnection)
    stream = Stream(connection, 2)
    race_queue = _ShutdownRaceQueue()
    stream._queue = race_queue
    queued = []

    producer = threading.Thread(
        target=lambda: queued.append(
            stream._put_incoming_frame(Frame(2, FrameType.PROCESS, b"racing"))
        )
    )
    producer.start()

    try:
        assert race_queue.put_started.wait(timeout=1)
        stream._close()
    finally:
        race_queue.continue_put.set()
        producer.join(timeout=1)

    assert not producer.is_alive()
    assert queued == [False]
    with pytest.raises(ConnectionClosedError):
        stream.recv(timeout=0.1)


def test_stream_send_nowait_returns_false_after_connection_close():
    websocket = _SyncWebSocket()
    connection = MultiplexedConnection(websocket)
    stream = connection.open_stream()

    try:
        connection.close()

        assert stream.send_nowait(b"payload", FrameType.PROCESS) is False
        assert websocket.sent == []
    finally:
        _finish_connection_close(connection, websocket)


def test_invalid_inbound_frame_closes_connection_with_protocol_error():
    websocket = _InvalidFrameWebSocket()
    connection = MultiplexedConnection(websocket)

    try:
        connection._dispatcher.join(timeout=1)
        assert not connection._dispatcher.is_alive()
        assert connection.close_code == 1002
        assert connection.close_reason == "Protocol error: invalid frame"
        assert not websocket.closed.is_set()
        assert connection.accept_stream() is None
    finally:
        _finish_connection_close(connection, websocket)


def test_open_stream_raises_after_receive_loop_closes_connection():
    websocket = _InvalidFrameWebSocket()
    connection = MultiplexedConnection(websocket)

    try:
        connection._dispatcher.join(timeout=1)
        assert not connection._dispatcher.is_alive()

        with pytest.raises(ConnectionClosedError):
            connection.open_stream()
    finally:
        _finish_connection_close(connection, websocket)


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
        assert isinstance(errors[0], ConnectionClosedError)
    finally:
        websocket.release_send.set()
        _finish_connection_close(connection, websocket)


def test_stream_send_raises_when_writer_fails():
    websocket = _SyncWebSocket(send_error=OSError("boom"))
    connection = MultiplexedConnection(websocket)
    stream = connection.open_stream()

    try:
        with pytest.raises(ConnectionError):
            stream.send(b"payload", FrameType.PROCESS)
    finally:
        _finish_connection_close(connection, websocket)


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
        _finish_connection_close(connection, websocket)
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
        _finish_connection_close(connection, websocket)


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
        _finish_connection_close(connection, websocket)
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
        _finish_connection_close(connection, websocket)


def test_broadcast_does_not_start_slow_client_close_handshake(monkeypatch):
    slow_websocket = _BlockingCloseWebSocket(block_send=True)
    slow_connection = MultiplexedConnection(slow_websocket)
    healthy_websocket = _SyncWebSocket()
    healthy_connection = MultiplexedConnection(healthy_websocket)
    broadcast_done = threading.Event()

    assert slow_connection.open_stream().send_nowait(b"blocked") is True
    assert slow_websocket.send_entered.wait(timeout=1)
    for _ in range(OUTBOUND_QUEUE_SIZE):
        assert slow_connection.open_stream().send_nowait(b"queued") is True

    monkeypatch.setattr(
        broadcast_module, "clients", [slow_connection, healthy_connection]
    )
    broadcaster = threading.Thread(
        target=lambda: (on_global_broadcast("hello"), broadcast_done.set())
    )
    broadcaster.start()

    try:
        assert broadcast_done.wait(timeout=1)
        assert not slow_websocket.close_entered.is_set()
        assert healthy_websocket.send_entered.wait(timeout=1)
    finally:
        slow_websocket.release_close.set()
        slow_websocket.release_send.set()
        _finish_connection_close(slow_connection, slow_websocket)
        _finish_connection_close(healthy_connection, healthy_websocket)
        broadcaster.join(timeout=1)


def test_broadcast_ignores_already_closed_connections(monkeypatch):
    websocket = _SyncWebSocket()
    connection = MultiplexedConnection(websocket)
    messages = []

    class _Logger:
        def warning(self, message):
            messages.append(message)

        def exception(self, message):
            messages.append(message)

    try:
        monkeypatch.setattr(broadcast_module, "logger", _Logger())
        connection.close()
        with clients_lock:
            clients.add(connection)

        on_global_broadcast("hello")

        assert messages == []
    finally:
        with clients_lock:
            clients.discard(connection)
        _finish_connection_close(connection, websocket)
