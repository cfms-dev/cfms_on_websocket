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
QUEUE_POLL_INTERVAL = 0.05

logger = log.bind(name="multiplexer")


class FrameType(IntEnum):
    DATA = 0
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
    exception: BaseException | None = None


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


def decode_frame(raw_payload: Data) -> Frame | None:
    if isinstance(raw_payload, str):
        raw_payload = raw_payload.encode("utf-8")

    if len(raw_payload) < FRAME_HEADER_SIZE:
        return None

    stream_id, frame_type_val = FRAME_HEADER.unpack_from(raw_payload)
    try:
        frame_type = FrameType(frame_type_val)
    except ValueError:
        return None

    return Frame(
        stream_id=stream_id,
        frame_type=frame_type,
        data=memoryview(raw_payload)[FRAME_HEADER_SIZE:],
    )


class Stream:
    """Represent an independent communication stream, like a virtual connection."""

    def __init__(self, connection: "MultiplexedConnection", frame_id: int) -> None:
        self.connection = connection
        self.frame_id = frame_id
        self._queue: queue.Queue[Frame | None] = queue.Queue(100)

    def send(self, data: DataLike, frame_type: FrameType = FrameType.DATA) -> None:
        """Send data on this stream."""
        self.connection._send_frame(self.frame_id, frame_type, data)

    def send_nowait(
        self, data: DataLike, frame_type: FrameType = FrameType.DATA
    ) -> bool:
        """Queue data for sending without waiting for socket I/O."""
        return self.connection._send_frame(
            self.frame_id, frame_type, data, wait_for_write=False
        )

    def recv(self, timeout: float | None = None) -> Frame:
        """Receive data for this stream, blocking until a frame is available."""
        try:
            frame = self._queue.get(timeout=timeout)
        except queue.Empty as exc:
            raise TimeoutError(
                "Timed out while waiting for multiplexed stream frame"
            ) from exc

        if frame is None:
            raise ConnectionError("MultiplexedConnection has been closed")
        return frame

    def _put_incoming_frame(self, frame: Frame | None) -> None:
        """Queue a frame for this stream. Called by the dispatcher."""
        self._queue.put(frame)


class MultiplexedConnection:
    def __init__(self, websocket: ServerConnection) -> None:
        """
        :param websocket: ServerConnection
        """
        self._ws = websocket
        self.remote_address = self._ws.remote_address

        self._next_frame_id = 2
        self._id_lock = threading.Lock()

        self._streams: dict[int, Stream] = {}
        self._streams_lock = threading.Lock()

        self._new_streams: queue.Queue[Stream | None] = queue.Queue()
        self._outbound: queue.Queue[_OutboundFrame | None] = queue.Queue(
            OUTBOUND_QUEUE_SIZE
        )
        self._writer_error: BaseException | None = None
        self._send_state_lock = threading.Lock()

        self._is_running = True
        self._dispatcher = threading.Thread(target=self._recv_loop, daemon=True)
        self._dispatcher.start()
        self._writer = threading.Thread(target=self._send_loop, daemon=True)
        self._writer.start()

    def open_stream(self) -> Stream:
        """Initiate a new data stream."""
        with self._send_state_lock:
            self._check_send_state(wait_for_write=True)

            with self._id_lock:
                frame_id = self._next_frame_id
                self._next_frame_id += 2  # Preserve parity.

            new_stream = Stream(self, frame_id)
            with self._streams_lock:
                self._streams[frame_id] = new_stream

        return new_stream

    def accept_stream(self) -> Stream | None:
        """Wait for and return a new stream created by the peer."""
        return self._new_streams.get()

    def _recv_loop(self) -> None:
        try:
            while self._is_running:
                raw_payload = self._ws.recv(decode=False)
                frame = decode_frame(raw_payload)
                if frame is None:
                    continue

                close_for_protocol_error = False

                with self._streams_lock:
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
                            self._new_streams.put(new_stream)
                            target_stream = new_stream

                if close_for_protocol_error:
                    self._ws.close(
                        code=1002,
                        reason="Protocol error: invalid client-initiated stream",
                    )
                    return

                if target_stream is None:
                    continue

                target_stream._put_incoming_frame(frame)

                # Reclaim routing table memory when the peer sends an end frame.
                if frame.frame_type == FrameType.CONCLUSION:
                    with self._streams_lock:
                        self._streams.pop(frame.stream_id, None)

        except ConnectionClosed:
            logger.info(f"({self.remote_address[0]}): WebSocket connection closed")
        except Exception:
            logger.exception(f"({self.remote_address[0]}): Error in receive loop")
        finally:
            self._is_running = False
            self._new_streams.put(None)  # Wake threads blocked in accept_stream.

            # Wake all threads blocked in Stream.recv() to prevent deadlocks.
            with self._streams_lock:
                for stream in self._streams.values():
                    stream._put_incoming_frame(None)

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
                if not self._check_send_state(wait_for_write=False):
                    return False

                try:
                    self._outbound.put_nowait(item)
                except queue.Full:
                    return False

        if item.done is None:
            return True

        self._wait_for_write(item)
        if item.exception is not None:
            raise ConnectionError("Failed to send WebSocket frame") from item.exception

        return True

    def _check_send_state(self, *, wait_for_write: bool) -> bool:
        if not self._is_running:
            if wait_for_write:
                raise ConnectionError("MultiplexedConnection has been closed")
            return False

        if self._writer_error is not None:
            if wait_for_write:
                raise ConnectionError("MultiplexedConnection send loop failed") from (
                    self._writer_error
                )
            return False

        return True

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
                self._check_send_state(wait_for_write=True)
                try:
                    self._outbound.put(item, timeout=put_timeout)
                    return
                except queue.Full:
                    continue

    def _wait_for_write(self, item: _OutboundFrame) -> None:
        while item.done is not None and not item.done.wait(QUEUE_POLL_INTERVAL):
            if self._writer_error is not None:
                item.exception = self._writer_error
                return
            if not self._is_running:
                item.exception = ConnectionError(
                    "MultiplexedConnection has been closed"
                )
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
                item = self._outbound.get()
                if item is None:
                    return

                try:
                    if not self._is_running:
                        raise ConnectionError("MultiplexedConnection has been closed")
                    self._ws.send(item.payload)
                except Exception as exc:
                    item.exception = exc
                    if item.done is not None:
                        item.done.set()
                    with self._send_state_lock:
                        self._writer_error = exc
                        self._is_running = False
                        self._fail_pending_sends(exc)
                    try:
                        self._ws.close()
                    except Exception:
                        # The send failure is already reported to callers.
                        pass
                    return

                if item.done is not None:
                    item.done.set()
        finally:
            error = self._writer_error or ConnectionError(
                "MultiplexedConnection send loop stopped"
            )
            self._fail_pending_sends(error)

    def _fail_pending_sends(self, exc: BaseException) -> None:
        while True:
            try:
                item = self._outbound.get_nowait()
            except queue.Empty:
                return

            if item is None:
                continue

            item.exception = exc
            if item.done is not None:
                item.done.set()

    def close(self) -> None:
        close_error = ConnectionError("MultiplexedConnection has been closed")
        with self._send_state_lock:
            self._is_running = False
            self._fail_pending_sends(close_error)
            try:
                self._outbound.put_nowait(None)
            except queue.Full:
                # Pending senders were already failed; closing must not block.
                pass
        try:
            self._ws.close()
        except Exception:
            # Close is best-effort because callers may invoke it repeatedly.
            pass
