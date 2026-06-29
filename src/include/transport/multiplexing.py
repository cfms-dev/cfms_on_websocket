import queue
import struct
import threading
from dataclasses import dataclass
from enum import IntEnum
from typing import Optional

import websockets
from loguru import logger as log
from websockets.sync.server import ServerConnection
from websockets.typing import Data

HEADER_FORMAT = "!IB"  # 4 bytes for frame_id, 1 byte for frame_type
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)
OUTBOUND_QUEUE_SIZE = 1024

logger = log.bind(name="multiplexer")


class FrameType(IntEnum):
    PROCESS = 0
    CONCLUSION = 1


@dataclass
class Frame:
    frame_id: int
    frame_type: FrameType
    data: bytes | memoryview  # can't be str


@dataclass
class _OutboundFrame:
    payload: bytes
    done: Optional[threading.Event] = None
    exception: Optional[BaseException] = None


class Stream:
    """Represent an independent communication stream, like a virtual connection."""

    def __init__(self, connection: "MultiplexConnection", frame_id: int):
        self.connection = connection
        self.frame_id = frame_id
        self._queue: queue.Queue = queue.Queue(100)

    def send(self, data: Data, frame_type: FrameType = FrameType.PROCESS):
        """Send data on this stream."""
        self.connection._send_frame(self.frame_id, frame_type, data)

    def send_nowait(
        self, data: Data, frame_type: FrameType = FrameType.PROCESS
    ) -> bool:
        """Queue data for sending without waiting for socket I/O."""
        return self.connection._send_frame(
            self.frame_id, frame_type, data, wait_for_write=False
        )

    def recv(self, timeout: Optional[float] = None) -> Frame:
        """Receive data for this stream, blocking until a frame is available."""
        frame = self._queue.get(timeout=timeout)
        if frame is None:
            raise ConnectionError("MultiplexConnection has been closed")
        return frame

    def _put_incoming_frame(self, frame: Optional[Frame]):
        """Queue a frame for this stream. Called by the dispatcher."""
        self._queue.put(frame)


class MultiplexConnection:
    def __init__(self, websocket: ServerConnection):
        """
        :param websocket: ServerConnection
        """
        self._ws = websocket
        self.remote_address = self._ws.remote_address

        self._next_frame_id = 2
        self._id_lock = threading.Lock()

        self._streams: dict[int, Stream] = {}
        self._streams_lock = threading.Lock()

        self._new_streams: queue.Queue[Optional[Stream]] = queue.Queue()
        self._outbound: queue.Queue[Optional[_OutboundFrame]] = queue.Queue(
            OUTBOUND_QUEUE_SIZE
        )
        self._send_error: Optional[BaseException] = None

        self._is_running = True
        self._dispatcher = threading.Thread(target=self._recv_loop, daemon=True)
        self._dispatcher.start()
        self._writer = threading.Thread(target=self._send_loop, daemon=True)
        self._writer.start()

    def create_stream(self) -> Stream:
        """Initiate a new data stream."""
        with self._id_lock:
            frame_id = self._next_frame_id
            self._next_frame_id += 2  # Preserve parity.

        new_stream = Stream(self, frame_id)
        with self._streams_lock:
            self._streams[frame_id] = new_stream

        return new_stream

    def accept_stream(self) -> Optional[Stream]:
        """Wait for and return a new stream created by the peer."""
        return self._new_streams.get()

    def _recv_loop(self):
        try:
            while self._is_running:
                raw_payload = self._ws.recv()

                if len(raw_payload) < HEADER_SIZE:
                    continue

                if isinstance(raw_payload, str):
                    raw_payload = raw_payload.encode("utf-8")

                frame_id, frame_type_val = struct.unpack_from(
                    HEADER_FORMAT, raw_payload
                )
                data = memoryview(raw_payload)[HEADER_SIZE:]

                try:
                    frame_type = FrameType(frame_type_val)
                except ValueError:
                    continue

                frame = Frame(frame_id=frame_id, frame_type=frame_type, data=data)

                with self._streams_lock:
                    if frame.frame_id not in self._streams:
                        if frame.frame_id % 2 == 0:
                            logger.warning(
                                f"({self.remote_address[0]}): Client attempted to "
                                f"open server-reserved stream id {frame.frame_id}"
                            )
                            self._ws.close(
                                code=1002,
                                reason="client-initiated streams must use odd ids",
                            )
                            return
                        # Notify the local main thread about the peer stream.
                        new_stream = Stream(self, frame.frame_id)
                        self._streams[frame.frame_id] = new_stream
                        self._new_streams.put(new_stream)

                    target_stream = self._streams[frame.frame_id]

                target_stream._put_incoming_frame(frame)

                # Reclaim routing table memory when the peer sends an end frame.
                if frame.frame_type == FrameType.CONCLUSION:
                    with self._streams_lock:
                        self._streams.pop(frame.frame_id, None)

        except websockets.exceptions.ConnectionClosed:
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

    def _encode_frame(self, frame_id: int, frame_type: FrameType, data: Data) -> bytes:
        if isinstance(data, str):
            data = data.encode("utf-8")

        data_len = len(data)
        payload = bytearray(HEADER_SIZE + data_len)

        struct.pack_into(HEADER_FORMAT, payload, 0, frame_id, frame_type.value)

        payload[HEADER_SIZE:] = data

        return bytes(payload)

    def _enqueue_frame(
        self,
        frame_id: int,
        frame_type: FrameType,
        data: Data,
        *,
        wait_for_write: bool = True,
        timeout: Optional[float] = None,
    ) -> bool:
        if not self._is_running:
            if wait_for_write:
                raise ConnectionError("MultiplexConnection has been closed")
            return False

        if self._send_error is not None:
            if wait_for_write:
                raise ConnectionError("MultiplexConnection send loop failed") from (
                    self._send_error
                )
            return False

        item = _OutboundFrame(
            payload=self._encode_frame(frame_id, frame_type, data),
            done=threading.Event() if wait_for_write else None,
        )

        try:
            if wait_for_write:
                self._outbound.put(item, timeout=timeout)
            else:
                self._outbound.put_nowait(item)
        except queue.Full:
            if wait_for_write:
                raise TimeoutError("Timed out while queueing WebSocket frame")
            return False

        if item.done is None:
            return True

        item.done.wait()
        if item.exception is not None:
            raise ConnectionError("Failed to send WebSocket frame") from item.exception

        return True

    def _send_frame(
        self,
        frame_id: int,
        frame_type: FrameType,
        data: Data,
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

    def _send_loop(self):
        try:
            while True:
                item = self._outbound.get()
                if item is None:
                    return

                try:
                    if not self._is_running:
                        raise ConnectionError("MultiplexConnection has been closed")
                    self._ws.send(item.payload)
                except Exception as exc:
                    self._send_error = exc
                    self._is_running = False
                    item.exception = exc
                    if item.done is not None:
                        item.done.set()
                    self._fail_pending_sends(exc)
                    try:
                        self._ws.close()
                    except Exception:
                        pass
                    return

                if item.done is not None:
                    item.done.set()
        finally:
            self._fail_pending_sends(
                ConnectionError("MultiplexConnection send loop stopped")
            )

    def _fail_pending_sends(self, exc: BaseException):
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

    def close(self):
        self._is_running = False
        self._fail_pending_sends(ConnectionError("MultiplexConnection has been closed"))
        try:
            self._outbound.put_nowait(None)
        except queue.Full:
            pass
        try:
            self._ws.close()
        except Exception:
            pass
