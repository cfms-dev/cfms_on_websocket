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
                    outbound_queue = getattr(conn, "_outbound", None)
                    outbound_queue_size = (
                        outbound_queue.qsize()
                        if outbound_queue is not None
                        and hasattr(outbound_queue, "qsize")
                        else None
                    )
                    remote_address = getattr(conn, "remote_address", None)
                    conn.close()
                    logger.warning(
                        "Dropped slow client during global broadcast: "
                        f"remote_address={remote_address}, "
                        f"outbound_queue_size={outbound_queue_size}"
                    )
            except Exception as e:
                logger.warning(f"Failed to forward global broadcast: {e}")
