import asyncio
from types import SimpleNamespace

import orjson
import pytest

from include.transport.multiplexing import Frame, FrameType
from tests.support.client import AsyncMultiplexConnection, AsyncStream, CFMSTestClient

pytestmark = pytest.mark.unit


class _IdleWebSocket:
    def __init__(self):
        self.closed = asyncio.Event()
        self.sent = []

    async def recv(self, decode=None):
        await self.closed.wait()
        return b""

    async def send(self, payload):
        self.sent.append(payload)

    async def close(self):
        self.closed.set()


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["request", "raw", "event"])
async def test_client_times_out_when_a_live_connection_returns_no_response(operation):
    websocket = _IdleWebSocket()
    connection = AsyncMultiplexConnection(websocket)
    client = CFMSTestClient(response_timeout=0.01)
    client.websocket = websocket
    client.multiplexer = connection

    try:
        if operation == "request":
            response = client.send_request("server_info", include_auth=False)
        elif operation == "raw":
            response = client.send_raw_request({"action": "server_info", "data": {}})
        else:
            response = client.accept_event()
        with pytest.raises(TimeoutError, match="timeout"):
            await response
    finally:
        await client.disconnect()

    assert connection._dispatcher_task.done()
    assert websocket.closed.is_set()
    assert client.websocket is None
    assert client.multiplexer is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("operation", "responses"),
    [
        ("upload", []),
        ("download", []),
        (
            "upload",
            [
                {
                    "action": "transfer_file",
                    "data": {"file_size": 0, "chunk_size": 64, "offset": 0},
                }
            ],
        ),
        (
            "download",
            [{"action": "transfer_file", "data": {"file_size": 0, "chunk_size": 64}}],
        ),
        (
            "download",
            [
                {"action": "transfer_file", "data": {"file_size": 0, "chunk_size": 64}},
                {"action": "transfer_file", "data": {"flag": "empty_file"}},
            ],
        ),
    ],
    ids=[
        "upload-negotiation",
        "download-negotiation",
        "upload-completion",
        "download-chunk",
        "download-completion",
    ],
)
async def test_file_protocol_waits_have_the_client_deadline(
    tmp_path, operation, responses
):
    sent = []

    async def send(frame_id, frame_type, data):
        sent.append(data)

    connection = SimpleNamespace(_send_frame=send)
    stream = AsyncStream(connection, 1)
    for response in responses:
        stream._put_incoming_frame(Frame(1, FrameType.PROCESS, orjson.dumps(response)))
    client = CFMSTestClient(response_timeout=0.01)
    client.multiplexer = SimpleNamespace(open_stream=lambda: stream)
    payload = tmp_path / "payload"
    payload.write_bytes(b"")

    if operation == "upload":
        transfer = client.upload_file_to_server("task", str(payload))
    else:
        transfer = client.download_file_from_server("task", str(payload))
    with pytest.raises(TimeoutError, match="Stream recv timeout"):
        await transfer

    assert orjson.loads(sent[0])["action"] == f"{operation}_file"


@pytest.mark.asyncio
async def test_event_deadline_can_be_overridden():
    observed = []

    async def accept_stream(timeout):
        observed.append(timeout)
        return stream

    async def recv(timeout):
        observed.append(timeout)
        return Frame(2, FrameType.PROCESS, orjson.dumps({"action": "changed"}))

    stream = SimpleNamespace(recv=recv)
    client = CFMSTestClient(response_timeout=0.01)
    client.multiplexer = SimpleNamespace(accept_stream=accept_stream)

    assert await client.accept_event(timeout=3.0) == {"action": "changed"}
    assert observed == [3.0, 3.0]
