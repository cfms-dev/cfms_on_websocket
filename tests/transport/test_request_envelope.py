import orjson
import pytest

from include.transport.multiplexing import FrameType

pytestmark = pytest.mark.integration


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload", [b"", b"{", b"secret is not json", b"\xff", b"{}", b"[]", b"null"]
)
async def test_invalid_request_returns_400_and_keeps_connection_usable(client, payload):
    stream = client.multiplexer.open_stream()
    await stream.send(payload)

    frame = await stream.recv(timeout=2)
    response = orjson.loads(frame.data)
    assert frame.frame_type is FrameType.CONCLUSION
    assert response["code"] == 400
    assert response["data"] == {}

    following = await client.send_request(
        "core.server.info.get", {}, include_auth=False
    )
    assert following["code"] == 200
