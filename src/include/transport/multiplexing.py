import queue
import struct
import threading
import time
from dataclasses import dataclass
from enum import IntEnum

from loguru import logger as log
from websockets.exceptions import ConnectionClosed
from websockets.sync.server import ServerConnection
from websockets.typing import Data, DataLike

FRAME_HEADER_FORMAT = "!IB"  # 4 bytes for stream_id, 1 byte for frame_type
FRAME_HEADER = struct.Struct(FRAME_HEADER_FORMAT)
FRAME_HEADER_SIZE = FRAME_HEADER.size
OUTBOUND_QUEUE_SIZE = 1024
MAX_PENDING_FRAMES_PER_STREAM = 128
QUEUE_POLL_INTERVAL = 0.05

logger = log.bind(name="multiplexer")


class ConnectionClosedError(ConnectionError):
    """Raised when an operation is attempted after the connection closed."""

    def __init__(self, message: str = "Connection has been closed") -> None:
        super().__init__(message)


class InvalidFrameError(Exception):
    """Raised when a frame is invalid or cannot be decoded."""

    close_code = 1002
    close_reason = "Protocol error: invalid frame"


class InvalidFrameTypeError(InvalidFrameError):
    """Raised when a frame has an invalid type."""

    def __init__(
        self,
        stream_id: int,
        frame_type_value: int,
        valid_frame_type_values: tuple[int, ...],
    ) -> None:
        self.stream_id = stream_id
        self.frame_type_value = frame_type_value
        self.valid_frame_type_values = valid_frame_type_values
        super().__init__(
            f"Invalid frame type {frame_type_value} for stream {stream_id}; "
            f"expected one of {', '.join(map(str, valid_frame_type_values))}"
        )


class CorruptedFrameError(InvalidFrameError):
    """Raised when a payload cannot contain a complete frame header."""

    def __init__(self, actual_size: int, minimum_size: int) -> None:
        self.actual_size = actual_size
        self.minimum_size = minimum_size
        super().__init__(
            f"Frame too short: {actual_size} bytes, "
            f"expected at least {minimum_size} bytes"
        )


class FrameType(IntEnum):
    PROCESS = 0
    CONCLUSION = 1


@dataclass(slots=True)
class Frame:
    stream_id: int
    frame_type: FrameType
    data: bytes | memoryview  # can't be str


@dataclass(slots=True)
class _OutboundFrame:
    payload: bytearray
    done: threading.Event | None = None
    exception: Exception | None = None


def normalize_payload(data: DataLike) -> bytes | bytearray | memoryview:
    if isinstance(data, str):
        return data.encode("utf-8")
    if isinstance(data, (bytes, bytearray, memoryview)):
        return data
    raise TypeError("Frame data must be str, bytes, bytearray, or memoryview")


def encode_frame(stream_id: int, frame_type: FrameType, data: DataLike) -> bytearray:
    payload = normalize_payload(data)
    frame = bytearray(FRAME_HEADER_SIZE + len(payload))
    FRAME_HEADER.pack_into(frame, 0, stream_id, frame_type.value)
    frame[FRAME_HEADER_SIZE:] = payload

    return frame


def decode_frame(raw_payload: Data) -> Frame:
    if isinstance(raw_payload, str):
        raw_payload = raw_payload.encode("utf-8")

    if len(raw_payload) < FRAME_HEADER_SIZE:
        raise CorruptedFrameError(len(raw_payload), FRAME_HEADER_SIZE)

    stream_id, frame_type_val = FRAME_HEADER.unpack_from(raw_payload)
    try:
        frame_type = FrameType(frame_type_val)
    except ValueError as exc:
        valid_frame_type_values = tuple(frame_type.value for frame_type in FrameType)
        raise InvalidFrameTypeError(
            stream_id, frame_type_val, valid_frame_type_values
        ) from exc

    return Frame(
        stream_id=stream_id,
        frame_type=frame_type,
        data=memoryview(raw_payload)[FRAME_HEADER_SIZE:],
    )


class Stream:
    """Represent an independent communication stream, like a virtual connection."""

    def __init__(self, connection: MultiplexedConnection, frame_id: int) -> None:
        self.connection = connection
        self.frame_id = frame_id
        self._queue: queue.Queue[Frame] = queue.Queue(MAX_PENDING_FRAMES_PER_STREAM)

    def send(self, data: DataLike, frame_type: FrameType = FrameType.PROCESS) -> None:
        """Send data on this stream."""
        self.connection._send_frame(self.frame_id, frame_type, data)

    def send_nowait(
        self, data: DataLike, frame_type: FrameType = FrameType.PROCESS
    ) -> bool:
        """Queue data for sending without waiting for socket I/O."""
        return self.connection._send_frame(
            self.frame_id, frame_type, data, wait_for_write=False
        )

    def recv(self, timeout: float | None = None) -> Frame:
        """Receive data for this stream, blocking until a frame is available."""
        try:
            return self._queue.get(timeout=timeout)
        except queue.Empty as exc:
            raise TimeoutError(
                "Timed out while waiting for multiplexed stream frame"
            ) from exc
        except queue.ShutDown as exc:
            raise ConnectionClosedError from exc

    def _put_incoming_frame(self, frame: Frame) -> bool:
        """Queue a frame for this stream. Called by the dispatcher."""
        try:
            self._queue.put_nowait(frame)
        except queue.ShutDown:
            return False
        return True

    def _close(self) -> None:
        self._queue.shutdown()


class MultiplexedConnection:
    def __init__(
        self,
        websocket: ServerConnection,
        *,
        max_pending_inbound_streams: int = 16,
    ) -> None:
        """
        :param websocket: ServerConnection
        """
        self._ws = websocket
        self.remote_address = self._ws.remote_address

        self._next_frame_id = 2
        self._id_lock = threading.Lock()

        self._streams: dict[int, Stream] = {}
        self._streams_lock = threading.Lock()

        # Pending queue for inbound streams.
        self._pending_inbound_streams: queue.Queue[Stream] = queue.Queue(
            max_pending_inbound_streams
        )

        # Pending queue for outbound frames.
        #
        # The reason for setting up a queue for outbound frames but not for streams is
        # that the send loop is responsible for determining which stream to send the
        # frame to.
        self._pending_outbound_frames: queue.Queue[_OutboundFrame | None] = queue.Queue(
            OUTBOUND_QUEUE_SIZE
        )

        self._writer_error: Exception | None = None
        self._send_state_lock = threading.Lock()

        self._is_running = True
        self._close_started = False
        self.close_code = 1000
        self.close_reason = ""

        self._dispatcher = threading.Thread(target=self._recv_loop, daemon=True)
        self._dispatcher.start()
        self._writer = threading.Thread(target=self._send_loop, daemon=True)
        self._writer.start()

    def open_stream(self) -> Stream:
        """Initiate a new data stream."""
        with self._send_state_lock:
            self._raise_if_send_unavailable()

            with self._id_lock:
                frame_id = self._next_frame_id
                self._next_frame_id += 2  # Preserve parity.

            new_stream = Stream(self, frame_id)
            with self._streams_lock:
                self._streams[frame_id] = new_stream

        return new_stream

    def accept_stream(self) -> Stream | None:
        """Wait for and return a new stream created by the peer."""
        try:
            return self._pending_inbound_streams.get()
        except queue.ShutDown:
            return None

    def _recv_loop(self) -> None:
        try:
            while self._is_running:
                raw_payload = self._ws.recv(decode=False)
                frame = decode_frame(raw_payload)

                close_for_protocol_error = False
                close_for_inbound_overload = False

                with self._streams_lock:
                    if not self._is_running:
                        return
                    target_stream = self._streams.get(frame.stream_id)
                    if target_stream is None:
                        if frame.stream_id % 2 == 0:
                            logger.warning(
                                f"({self.remote_address[0]}): Client attempted to "
                                f"open server-reserved stream id {frame.stream_id}"
                            )
                            close_for_protocol_error = True
                        else:
                            # Notify the local main thread about the peer stream.
                            new_stream = Stream(self, frame.stream_id)
                            self._streams[frame.stream_id] = new_stream
                            try:
                                self._pending_inbound_streams.put_nowait(new_stream)
                            except queue.Full:
                                logger.warning(
                                    f"({self.remote_address[0]}): Too many pending "
                                    "inbound streams"
                                )
                                close_for_inbound_overload = True
                            target_stream = new_stream

                if close_for_inbound_overload:
                    self.close(
                        code=1013,
                        reason="Too many pending request streams",
                    )
                    return

                if close_for_protocol_error:
                    self.close(
                        code=1002,
                        reason="Protocol error: invalid client-initiated stream",
                    )
                    return

                if target_stream is None:
                    continue

                try:
                    frame_queued = target_stream._put_incoming_frame(frame)
                except queue.Full:
                    logger.warning(
                        f"({self.remote_address[0]}): Too many pending frames for "
                        f"stream {frame.stream_id}"
                    )
                    self.close(
                        code=1013,
                        reason="Too many pending frames for one stream",
                    )
                    return

                if not frame_queued:
                    return

                # Reclaim routing table memory when the peer sends an end frame.
                if frame.frame_type == FrameType.CONCLUSION:
                    with self._streams_lock:
                        self._streams.pop(frame.stream_id, None)

        except InvalidFrameError as exc:
            logger.warning(f"({self.remote_address[0]}): Invalid frame: {exc}")
            self.close(code=exc.close_code, reason=exc.close_reason)
        except ConnectionClosed:
            logger.info(f"({self.remote_address[0]}): WebSocket connection closed")
        except Exception:
            logger.exception(f"({self.remote_address[0]}): Error in receive loop")
        finally:
            self.close()

    def _enqueue_frame(
        self,
        frame_id: int,
        frame_type: FrameType,
        data: DataLike,
        *,
        wait_for_write: bool = True,
        timeout: float | None = None,
    ) -> bool:
        item = _OutboundFrame(
            payload=encode_frame(frame_id, frame_type, data),
            done=threading.Event() if wait_for_write else None,
        )

        if wait_for_write:
            self._put_outbound(item, timeout=timeout)
        else:
            with self._send_state_lock:
                if not self._can_send_nowait():
                    return False

                try:
                    self._pending_outbound_frames.put_nowait(item)
                except queue.Full:
                    return False

        if item.done is None:
            return True

        self._wait_for_write(item)
        if item.exception is not None:
            raise ConnectionError("Failed to send WebSocket frame") from item.exception

        return True

    def _raise_if_send_unavailable(self) -> None:
        if not self._is_running:
            raise ConnectionClosedError

        if self._writer_error is not None:
            raise ConnectionError("Connection send loop failed") from self._writer_error

    def _can_send_nowait(self) -> bool:
        return self._is_running and self._writer_error is None

    def _put_outbound(
        self, item: _OutboundFrame, *, timeout: float | None = None
    ) -> None:
        deadline = None if timeout is None else time.monotonic() + timeout

        while True:
            put_timeout = QUEUE_POLL_INTERVAL
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("Timed out while queueing WebSocket frame")
                put_timeout = min(put_timeout, remaining)

            with self._send_state_lock:
                self._raise_if_send_unavailable()
                try:
                    self._pending_outbound_frames.put(item, timeout=put_timeout)
                    return
                except queue.Full:
                    continue

    def _wait_for_write(self, item: _OutboundFrame) -> None:
        while item.done is not None and not item.done.wait(QUEUE_POLL_INTERVAL):
            if self._writer_error is not None:
                item.exception = self._writer_error
                return
            if not self._is_running:
                item.exception = ConnectionClosedError()
                return

    def _send_frame(
        self,
        frame_id: int,
        frame_type: FrameType,
        data: DataLike,
        *,
        wait_for_write: bool = True,
    ) -> bool:
        queued = self._enqueue_frame(
            frame_id, frame_type, data, wait_for_write=wait_for_write
        )

        if queued and frame_type == FrameType.CONCLUSION:
            with self._streams_lock:
                self._streams.pop(frame_id, None)

        return queued

    def _send_loop(self) -> None:
        try:
            while True:
                item = self._pending_outbound_frames.get()
                if item is None:
                    return

                try:
                    if not self._is_running:
                        raise ConnectionClosedError
                    self._ws.send(item.payload)
                except Exception as exc:  # noqa: BLE001 - a writer thread must propagate every send failure.
                    item.exception = exc
                    if item.done is not None:
                        item.done.set()
                    with self._send_state_lock:
                        self._writer_error = exc
                        self._is_running = False
                    self.close()
                    return

                if item.done is not None:
                    item.done.set()
        finally:
            error = self._writer_error or ConnectionClosedError()
            self._fail_pending_sends(error)

    def _fail_pending_sends(self, exc: Exception) -> None:
        while True:
            try:
                item = self._pending_outbound_frames.get_nowait()
            except queue.Empty:
                return

            if item is None:
                continue

            item.exception = exc
            if item.done is not None:
                item.done.set()

    def close(self, code: int = 1000, reason: str = "") -> None:
        """Request a logical close without waiting for WebSocket I/O."""
        with self._send_state_lock:
            if self._close_started:
                return
            self._close_started = True
            self.close_code = code
            self.close_reason = reason
            self._is_running = False
            close_error = self._writer_error or ConnectionClosedError(
                "Connection is closing"
            )
            self._fail_pending_sends(close_error)
            try:
                self._pending_outbound_frames.put_nowait(None)
            except queue.Full:
                # Pending senders were already failed; closing must not block.
                pass

        with self._streams_lock:
            streams = tuple(self._streams.values())
            self._streams.clear()
            self._pending_inbound_streams.shutdown(immediate=True)

        for stream in streams:
            stream._close()
