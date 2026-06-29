import asyncio

import pytest

from tests.test_client import AsyncMultiplexConnection


class _IdleWebSocket:
    def __init__(self):
        self.sent = []
        self._closed = asyncio.Event()

    async def recv(self):
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
        first = connection.create_stream()
        second = connection.create_stream()
        third = connection.create_stream()

        assert first.frame_id == 1
        assert second.frame_id == 3
        assert third.frame_id == 5
    finally:
        await connection.close()
