from array import array
from collections.abc import Buffer
from importlib import import_module
from pathlib import Path

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


def test_local_resumable_upload_reopens_at_complete_chunk(tmp_path: Path):
    provider = LocalStorageProvider()
    path = tmp_path / "resumable.bin"
    path.write_bytes(b"a" * 700)

    with provider.open_resumable_upload(
        str(path), file_size=1024, chunk_size=512
    ) as upload:
        assert upload.offset == 512
        upload.write(b"b" * 512)
        upload.finish()

    assert path.read_bytes() == b"a" * 512 + b"b" * 512


def test_s3_resumable_upload_restores_committed_parts():
    pytest.importorskip("boto3")
    s3_module = import_module("include.providers.storage.s3")

    class FakeClient:
        def __init__(self):
            self.parts = {}
            self.objects = {}
            self.fail_complete_once = False

        def create_multipart_upload(self, **_kwargs):
            return {"UploadId": "upload-1"}

        def upload_part(self, PartNumber, Body, **_kwargs):
            self.parts[PartNumber] = Body.read()
            return {"ETag": f"etag-{PartNumber}"}

        def list_parts(self, PartNumberMarker, **_kwargs):
            return {
                "Parts": [
                    {
                        "PartNumber": number,
                        "ETag": f"etag-{number}",
                        "Size": len(data),
                    }
                    for number, data in sorted(self.parts.items())
                    if number > PartNumberMarker
                ],
                "IsTruncated": False,
            }

        def complete_multipart_upload(self, Key, MultipartUpload, **_kwargs):
            if self.fail_complete_once:
                self.fail_complete_once = False
                raise RuntimeError("completion interrupted")
            self.objects[Key] = b"".join(
                self.parts[part["PartNumber"]] for part in MultipartUpload["Parts"]
            )

        def abort_multipart_upload(self, **_kwargs):
            self.parts.clear()

    client = FakeClient()
    chunk_size = 64 * 1024
    checkpoint_size = 5 * 1024 * 1024
    file_size = checkpoint_size + chunk_size
    first = s3_module.S3ResumableUpload(
        client,
        "bucket",
        "key",
        file_size,
        chunk_size,
        None,
        checkpoint_size,
    )
    first.write(b"a" * checkpoint_size)
    session_id = first.session_id
    first.close()

    resumed = s3_module.S3ResumableUpload(
        client,
        "bucket",
        "key",
        file_size,
        chunk_size,
        session_id,
        checkpoint_size,
    )
    assert resumed.offset == checkpoint_size
    resumed.write(b"b" * chunk_size)
    client.fail_complete_once = True
    with pytest.raises(RuntimeError, match="completion interrupted"):
        resumed.finish()
    resumed.close()

    recovered = s3_module.S3ResumableUpload(
        client,
        "bucket",
        "key",
        file_size,
        chunk_size,
        session_id,
        checkpoint_size,
    )
    assert recovered.offset == file_size
    recovered.finish()

    assert client.objects["key"] == (b"a" * checkpoint_size + b"b" * chunk_size)
