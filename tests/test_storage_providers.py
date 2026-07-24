from array import array
from collections.abc import Buffer
from importlib import import_module

import pytest

from include.providers.storage.local import LocalStorageProvider


def _as_bytes(data: Buffer) -> bytes:
    with memoryview(data) as source_view, source_view.cast("B") as byte_view:
        return byte_view.tobytes()


@pytest.mark.parametrize(
    "data",
    [bytearray(b"bytearray"), memoryview(b"memoryview"), array("I", [42])],
)
def test_local_file_object_writes_buffers(tmp_path, data: Buffer):
    path = tmp_path / "buffer.bin"

    with LocalStorageProvider().fopen(str(path), "wb") as file:
        written = file.write(data)

    expected = _as_bytes(data)
    assert written == len(expected)
    assert path.read_bytes() == expected


def test_s3_file_object_writes_buffers():
    pytest.importorskip("boto3")
    s3_module = import_module("include.providers.storage.s3")

    class FakeClient:
        def put_object(self, **kwargs):
            self.body = bytes(kwargs["Body"])

    client = FakeClient()
    file = s3_module.S3FileObject(client, "bucket", "key", "wb")
    data = array("I", [42])

    written = file.write(data)
    file.close()

    expected = _as_bytes(data)
    assert written == len(expected)
    assert client.body == expected
