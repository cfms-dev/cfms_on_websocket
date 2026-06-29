from loguru import logger

from include.shared import clients, clients_lock
from include.transport.multiplexing import FrameType


def on_global_broadcast(msg: str):
    encoded_msg = msg.encode("utf-8") if isinstance(msg, str) else msg
    with clients_lock:
        clients_copy = list(clients)
    for conn in clients_copy:
        if conn._ws.protocol.state.name == "OPEN":
            try:
                stream = conn.create_stream()
                if not stream.send_nowait(encoded_msg, frame_type=FrameType.CONCLUSION):
                    conn.close()
                    logger.warning("Dropped slow client during global broadcast")
            except Exception as e:
                logger.warning(f"Failed to forward global broadcast: {e}")
