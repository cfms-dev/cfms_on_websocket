import os
from array import array
from collections.abc import Buffer
from importlib import import_module
from io import BytesIO
from pathlib import Path

import pytest

from include.providers.base import StorageProvider
from include.providers.storage import local as local_storage
from include.providers.storage.local import LocalStorageProvider


def _as_bytes(data: Buffer) -> bytes:
    with memoryview(data) as source_view, source_view.cast("B") as byte_view:
        return byte_view.tobytes()


def test_storage_provider_requires_resumable_upload_operations():
    class IncompleteStorageProvider(StorageProvider):
        def fopen(self, path, mode="rb"):
            raise NotImplementedError

        def exists(self, path):
            raise NotImplementedError

        def remove(self, path):
            raise NotImplementedError

        def mkdir(self, path, mode=0o777):
            raise NotImplementedError

        def makedirs(self, name, mode=0o777, exist_ok=False):
            raise NotImplementedError

        def getsize(self, filename, /):
            raise NotImplementedError

    with pytest.raises(TypeError, match="abstract"):
        IncompleteStorageProvider()


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
            self.body_type = type(kwargs["Body"])
            self.body = bytes(kwargs["Body"])

    client = FakeClient()
    file = s3_module.S3FileObject(client, "bucket", "key", "wb")
    data = array("I", [42])

    written = file.write(data)
    file.close()

    expected = _as_bytes(data)
    assert written == len(expected)
    assert client.body == expected
    assert client.body_type is bytes


def test_s3_read_file_object_opens_lazily_and_closes_body():
    pytest.importorskip("boto3")
    s3_module = import_module("include.providers.storage.s3")

    class FakeClient:
        def __init__(self) -> None:
            self.requests = []
            self.body = None

        def get_object(self, **kwargs):
            self.requests.append(kwargs)
            self.body = BytesIO(b"contents")
            return {"Body": self.body, "ContentLength": 8}

    client = FakeClient()
    file = s3_module.S3FileObject(client, "bucket", "key", "rb")

    assert client.requests == []
    assert file.read(4) == b"cont"
    assert client.requests == [{"Bucket": "bucket", "Key": "key"}]
    assert file.tell() == 4

    file.close()

    assert client.body.closed is True


def test_s3_read_file_object_uses_ranges_for_seeks():
    pytest.importorskip("boto3")
    s3_module = import_module("include.providers.storage.s3")

    class FakeClient:
        def __init__(self) -> None:
            self.head_requests = []
            self.get_requests = []
            self.bodies = []

        def head_object(self, **kwargs):
            self.head_requests.append(kwargs)
            return {"ContentLength": 10}

        def get_object(self, **kwargs):
            self.get_requests.append(kwargs)
            start = int(kwargs.get("Range", "bytes=0-")[6:-1])
            body = BytesIO(b"abcdefghij"[start:])
            self.bodies.append(body)
            response = {"Body": body, "ContentLength": 10 - start}
            if start:
                response["ContentRange"] = f"bytes {start}-9/10"
            return response

    client = FakeClient()
    with s3_module.S3FileObject(client, "bucket", "key", "rb") as file:
        assert file.seekable() is True
        with pytest.raises(ValueError, match="negative seek position"):
            file.seek(-1)
        with pytest.raises(ValueError, match="invalid whence"):
            file.seek(0, 99)
        assert file.seek(4) == 4
        assert file.read(3) == b"efg"
        assert file.tell() == 7
        assert file.seek(-2, os.SEEK_END) == 8
        assert file.read() == b"ij"
        requests_at_eof = len(client.get_requests)
        assert file.seek(10) == 10
        assert file.read() == b""
        assert len(client.get_requests) == requests_at_eof
        assert file.seek(0) == 0
        assert file.read(2) == b"ab"

    assert client.head_requests == [{"Bucket": "bucket", "Key": "key"}]
    assert [request.get("Range") for request in client.get_requests] == [
        "bytes=4-",
        "bytes=8-",
        None,
    ]
    assert all(body.closed for body in client.bodies)


def test_s3_read_file_object_rejects_invalid_range_response():
    pytest.importorskip("boto3")
    s3_module = import_module("include.providers.storage.s3")

    class FakeClient:
        def head_object(self, **_kwargs):
            return {"ContentLength": 10}

        def get_object(self, **_kwargs):
            self.body = BytesIO(b"abcdefghij")
            return {"Body": self.body, "ContentLength": 10}

    client = FakeClient()
    file = s3_module.S3FileObject(client, "bucket", "key", "rb")
    file.seek(4)

    with pytest.raises(OSError, match="invalid byte range"):
        file.read(1)

    assert client.body.closed is True


def test_s3_storage_provider_uses_sdk_defaults_and_tuned_client_config(monkeypatch):
    pytest.importorskip("boto3")
    s3_module = import_module("include.providers.storage.s3")
    captured = {}

    def create_client(service_name, **kwargs):
        captured["service_name"] = service_name
        captured.update(kwargs)
        return object()

    monkeypatch.setattr(s3_module.boto3, "client", create_client)

    s3_module.S3StorageProvider(
        bucket_name="bucket",
        endpoint_url="",
        aws_access_key_id="",
        aws_secret_access_key="",
        region_name="",
        addressing_style="path",
        max_pool_connections=32,
    )

    assert captured["service_name"] == "s3"
    assert captured["endpoint_url"] is None
    assert captured["region_name"] is None
    assert "aws_access_key_id" not in captured
    assert "aws_secret_access_key" not in captured
    config = captured["config"]
    assert config.signature_version == "s3v4"
    assert config.max_pool_connections == 32
    assert config.retries == {"mode": "standard"}
    assert config.tcp_keepalive is True
    assert config.s3 == {"addressing_style": "path"}


def test_provider_bootstrap_uses_validated_s3_policy_defaults(monkeypatch):
    pytest.importorskip("boto3")
    bootstrap_module = import_module("include.providers.bootstrap")
    caching_module = import_module("include.providers.caching")
    events_module = import_module("include.providers.events")
    s3_module = import_module("include.providers.storage.s3")
    captured = {}

    class FakeS3StorageProvider:
        def __init__(self, **kwargs) -> None:
            captured.update(kwargs)

    class FakeProviderManager:
        def register(self, _provider) -> None:
            pass

    monkeypatch.setattr(s3_module, "S3StorageProvider", FakeS3StorageProvider)
    monkeypatch.setattr(caching_module, "MemoryCachingProvider", object)
    monkeypatch.setattr(events_module, "LocalEventBusProvider", object)
    monkeypatch.setattr(bootstrap_module, "ProviderManager", FakeProviderManager)

    bootstrap_module.initialize_providers(
        {
            "provider": {
                "storage": "s3",
                "caching": "memory",
                "rate_limit": "memory",
                "event_bus": "local",
            },
            "server": {
                "admission_control": {
                    "max_connections": 20,
                    "max_connections_per_ip": 10,
                }
            },
            "s3": {"bucket": "test-bucket"},
        }
    )

    assert captured == {
        "bucket_name": "test-bucket",
        "endpoint_url": "",
        "aws_access_key_id": "",
        "aws_secret_access_key": "",
        "region_name": "",
        "aws_session_token": "",
        "addressing_style": "auto",
        "max_pool_connections": 20,
    }


def test_s3_storage_provider_passes_explicit_temporary_credentials(monkeypatch):
    pytest.importorskip("boto3")
    s3_module = import_module("include.providers.storage.s3")
    captured = {}

    def create_client(_service_name, **kwargs):
        captured.update(kwargs)
        return object()

    monkeypatch.setattr(s3_module.boto3, "client", create_client)

    s3_module.S3StorageProvider(
        bucket_name="bucket",
        endpoint_url="https://storage.example",
        aws_access_key_id="access",
        aws_secret_access_key="secret",
        aws_session_token="token",
    )

    assert captured["aws_access_key_id"] == "access"
    assert captured["aws_secret_access_key"] == "secret"
    assert captured["aws_session_token"] == "token"


def test_s3_storage_provider_rejects_partial_explicit_credentials(monkeypatch):
    pytest.importorskip("boto3")
    s3_module = import_module("include.providers.storage.s3")
    monkeypatch.setattr(s3_module.boto3, "client", lambda *_args, **_kwargs: object())

    with pytest.raises(ValueError, match="must be paired"):
        s3_module.S3StorageProvider(
            bucket_name="bucket",
            endpoint_url="",
            aws_access_key_id="access",
            aws_secret_access_key="",
        )


def _s3_client_error(s3_module, status: int, code: str):
    return s3_module.ClientError(
        {
            "Error": {"Code": code, "Message": code},
            "ResponseMetadata": {"HTTPStatusCode": status},
        },
        "S3Operation",
    )


def test_s3_read_file_object_maps_missing_object_to_file_not_found():
    pytest.importorskip("boto3")
    s3_module = import_module("include.providers.storage.s3")

    class MissingClient:
        def get_object(self, **_kwargs):
            raise _s3_client_error(s3_module, 404, "NoSuchKey")

    file = s3_module.S3FileObject(MissingClient(), "bucket", "missing", "rb")

    with pytest.raises(FileNotFoundError, match="missing"):
        file.read()


def test_s3_storage_provider_maps_only_missing_objects_to_absence():
    pytest.importorskip("boto3")
    s3_module = import_module("include.providers.storage.s3")

    class MissingClient:
        def head_object(self, **_kwargs):
            raise _s3_client_error(s3_module, 404, "NoSuchKey")

        def delete_object(self, **_kwargs):
            raise _s3_client_error(s3_module, 404, "NoSuchKey")

    provider = object.__new__(s3_module.S3StorageProvider)
    provider._bucket_name = "bucket"
    provider._client = MissingClient()

    assert provider.exists("missing") is False
    assert provider.remove("missing") is False
    with pytest.raises(FileNotFoundError, match="missing"):
        provider.getsize("missing")


@pytest.mark.parametrize(
    ("status", "code"),
    [
        (403, "AccessDenied"),
        (404, "NoSuchBucket"),
        (429, "TooManyRequests"),
        (500, "InternalError"),
    ],
)
def test_s3_storage_provider_propagates_operational_errors(status, code):
    pytest.importorskip("boto3")
    s3_module = import_module("include.providers.storage.s3")

    class FailingClient:
        def head_object(self, **_kwargs):
            raise _s3_client_error(s3_module, status, code)

        def delete_object(self, **_kwargs):
            raise _s3_client_error(s3_module, status, code)

    provider = object.__new__(s3_module.S3StorageProvider)
    provider._bucket_name = "bucket"
    provider._client = FailingClient()

    with pytest.raises(s3_module.ClientError):
        provider.exists("file")
    with pytest.raises(s3_module.ClientError):
        provider.remove("file")
    with pytest.raises(s3_module.ClientError):
        provider.getsize("file")


def test_s3_storage_provider_propagates_network_errors():
    pytest.importorskip("boto3")
    s3_module = import_module("include.providers.storage.s3")
    from botocore.exceptions import EndpointConnectionError

    error = EndpointConnectionError(endpoint_url="https://storage.example")

    class FailingClient:
        def head_object(self, **_kwargs):
            raise error

        def delete_object(self, **_kwargs):
            raise error

    provider = object.__new__(s3_module.S3StorageProvider)
    provider._bucket_name = "bucket"
    provider._client = FailingClient()

    with pytest.raises(EndpointConnectionError):
        provider.exists("file")
    with pytest.raises(EndpointConnectionError):
        provider.remove("file")
    with pytest.raises(EndpointConnectionError):
        provider.getsize("file")


def test_s3_multipart_file_object_does_not_send_full_sha256_checksum():
    pytest.importorskip("boto3")
    s3_module = import_module("include.providers.storage.s3")

    class FakeClient:
        def __init__(self) -> None:
            self.complete_request = None
            self.upload_body_types = []

        def create_multipart_upload(self, **_kwargs):
            return {"UploadId": "upload-1"}

        def upload_part(self, PartNumber, Body, **_kwargs):
            self.upload_body_types.append(type(Body))
            return {"ETag": f"etag-{PartNumber}"}

        def complete_multipart_upload(self, **kwargs):
            self.complete_request = kwargs

    client = FakeClient()
    with s3_module.S3FileObject(client, "bucket", "key", "wb") as file:
        file.write(b"a" * (5 * 1024 * 1024 + 1))

    assert "ChecksumSHA256" not in client.complete_request
    assert client.upload_body_types == [bytes, bytes]


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


def test_local_resumable_upload_closes_file_when_initialization_fails(
    monkeypatch,
) -> None:
    class RecordingFile:
        def __init__(self) -> None:
            self.closed = False

        def __enter__(self):
            return self

        def __exit__(self, *_args) -> None:
            self.closed = True

        def close(self) -> None:
            self.closed = True

    opened_file = RecordingFile()
    monkeypatch.setattr("builtins.open", lambda *_args, **_kwargs: opened_file)

    def fail_getsize(_path: str) -> int:
        raise OSError("size lookup failed")

    monkeypatch.setattr(local_storage.os.path, "getsize", fail_getsize)

    with pytest.raises(OSError, match="size lookup failed"):
        LocalStorageProvider().open_resumable_upload(
            "resumable.bin", file_size=1024, chunk_size=512
        )

    assert opened_file.closed is True


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

        def list_parts(self, **_kwargs):
            return {"Parts": list(self.parts)}

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
    checkpoints = []
    first = s3_module.S3ResumableUpload(
        client,
        "bucket",
        "key",
        file_size,
        chunk_size,
        None,
        checkpoint_size,
        checkpoint_callback=checkpoints.append,
    )
    first.write(b"a" * checkpoint_size)
    session_id = first.session_id
    checkpoint_data = checkpoints[-1]
    first.close()

    resumed = s3_module.S3ResumableUpload(
        client,
        "bucket",
        "key",
        file_size,
        chunk_size,
        session_id,
        checkpoint_size,
        checkpoint_data,
        checkpoints.append,
    )
    assert resumed.offset == checkpoint_size
    resumed.write(b"b" * chunk_size)
    client.fail_complete_once = True
    with pytest.raises(RuntimeError, match="completion interrupted"):
        resumed.finish()
    checkpoint_data = checkpoints[-1]
    resumed.close()

    recovered = s3_module.S3ResumableUpload(
        client,
        "bucket",
        "key",
        file_size,
        chunk_size,
        session_id,
        checkpoint_size,
        checkpoint_data,
    )
    assert recovered.offset == file_size
    recovered.finish()

    assert client.objects["key"] == (b"a" * checkpoint_size + b"b" * chunk_size)


def test_s3_resumable_upload_retransmits_unpersisted_remote_parts():
    pytest.importorskip("boto3")
    s3_module = import_module("include.providers.storage.s3")

    class FakeClient:
        def __init__(self):
            self.parts = {}
            self.objects = {}

        def create_multipart_upload(self, **_kwargs):
            return {"UploadId": "upload-1"}

        def upload_part(self, PartNumber, Body, **_kwargs):
            self.parts[PartNumber] = Body.read()
            return {"ETag": f"etag-{PartNumber}-{len(self.parts[PartNumber])}"}

        def list_parts(self, **_kwargs):
            return {
                "Parts": [
                    {
                        "PartNumber": number,
                        "ETag": f"untrusted-{number}",
                        "Size": len(data),
                    }
                    for number, data in self.parts.items()
                ]
            }

        def complete_multipart_upload(self, Key, MultipartUpload, **_kwargs):
            self.completion_manifest = MultipartUpload["Parts"]
            self.objects[Key] = b"".join(
                self.parts[part["PartNumber"]] for part in self.completion_manifest
            )

    client = FakeClient()
    chunk_size = 64 * 1024
    checkpoint_size = 5 * 1024 * 1024
    file_size = checkpoint_size + chunk_size
    interrupted = s3_module.S3ResumableUpload(
        client,
        "bucket",
        "key",
        file_size,
        chunk_size,
        None,
        checkpoint_size,
    )
    interrupted.write(b"a" * checkpoint_size)
    session_id = interrupted.session_id
    interrupted.close()

    resumed = s3_module.S3ResumableUpload(
        client,
        "bucket",
        "key",
        file_size,
        chunk_size,
        session_id,
        checkpoint_size,
        checkpoint_data=None,
    )
    assert resumed.offset == 0

    resumed.write(b"c" * checkpoint_size)
    resumed.write(b"d" * chunk_size)
    resumed.finish()

    assert client.objects["key"] == b"c" * checkpoint_size + b"d" * chunk_size
    assert all(
        not part["ETag"].startswith("untrusted-") for part in client.completion_manifest
    )
