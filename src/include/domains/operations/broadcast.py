from loguru import logger

from include.shared import clients, clients_lock
from include.transport.multiplexing import ConnectionClosedError, FrameType


def on_global_broadcast(msg: str):
    encoded_msg = msg.encode("utf-8") if isinstance(msg, str) else msg
    with clients_lock:
        clients_copy = list(clients)
    for conn in clients_copy:
        try:
            stream = conn.open_stream()
            if not stream.send_nowait(encoded_msg, frame_type=FrameType.CONCLUSION):
                outbound_queue_size = conn._pending_outbound_frames.qsize()
                remote_address = conn.remote_address
                conn.close()
                logger.warning(
                    "Dropped slow client during global broadcast: "
                    f"remote_address={remote_address}, "
                    f"outbound_queue_size={outbound_queue_size}"
                )
        except ConnectionClosedError:
            continue
        except ConnectionError as e:
            logger.warning(f"Failed to forward global broadcast: {e}")
        except Exception:
            logger.exception("Failed to forward global broadcast")
