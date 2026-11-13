import os
import uuid
from contextlib import ExitStack
from types import SimpleNamespace

import pytest
lazy import boto3
lazy from botocore.config import Config

lazy from include.providers.storage import s3 as s3_module


@pytest.fixture
def s3_integration_provider(monkeypatch):
    if os.environ.get("CFMS_TEST_S3_WRITE") != "1":
        pytest.skip("set CFMS_TEST_S3_WRITE=1 to enable S3 compatibility tests")
    bucket = os.environ.get("CFMS_TEST_S3_BUCKET")
    if not bucket:
        pytest.fail("CFMS_TEST_S3_BUCKET must name a dedicated test bucket")

    def bounded_client(service_name, **options):
        options["config"] = options["config"].merge(
            Config(connect_timeout=2, read_timeout=5, retries={"total_max_attempts": 1})
        )
        return boto3.client(service_name, **options)

    monkeypatch.setattr(s3_module, "boto3", SimpleNamespace(client=bounded_client))
    provider = s3_module.S3StorageProvider(
        bucket_name=bucket,
        endpoint_url=os.environ.get("CFMS_TEST_S3_ENDPOINT_URL"),
        aws_access_key_id=None,
        aws_secret_access_key=None,
        region_name=os.environ.get("CFMS_TEST_S3_REGION"),
        addressing_style=os.environ.get("CFMS_TEST_S3_ADDRESSING_STYLE", "auto"),
        max_pool_connections=4,
    )
    try:
        yield provider
    finally:
        provider._client.close()


@pytest.mark.integration
def test_s3_compatible_read_write_resume_and_abort(s3_integration_provider):
    provider = s3_integration_provider
    prefix = f"cfms-integration/{uuid.uuid4().hex}"
    small_path = f"{prefix}/small.bin"
    multipart_path = f"{prefix}/multipart.bin"
    aborted_path = f"{prefix}/aborted.bin"
    with ExitStack() as cleanup:
        for path in (small_path, multipart_path, aborted_path):
            cleanup.callback(provider.remove, path)
        with provider.fopen(small_path, "wb") as target:
            target.write(b"0123456789")
        with provider.fopen(small_path, "rb") as source:
            source.seek(4)
            assert source.read() == b"456789"

        file_size = 5 * 1024 * 1024 + 512
        upload = provider.open_resumable_upload(
            multipart_path, file_size=file_size, chunk_size=512
        )
        cleanup.callback(upload.abort)
        upload.write(b"a" * upload.checkpoint_size)
        upload.close()
        resumed = provider.open_resumable_upload(
            multipart_path,
            file_size=file_size,
            chunk_size=512,
            session_id=upload.session_id,
            checkpoint_size=upload.checkpoint_size,
            checkpoint_data=upload.checkpoint_data,
        )
        cleanup.callback(resumed.abort)
        assert resumed.offset == upload.checkpoint_size
        resumed.write(b"b" * (file_size - resumed.offset))
        resumed.finish()
        assert provider.getsize(multipart_path) == file_size
        with provider.fopen(multipart_path, "rb") as source:
            assert source.read() == b"a" * upload.checkpoint_size + b"b" * 512

        abandoned = provider.open_resumable_upload(
            aborted_path, file_size=10 * 1024 * 1024, chunk_size=512
        )
        cleanup.callback(abandoned.abort)
        abandoned.write(b"c" * abandoned.checkpoint_size)
        abandoned.abort()
        assert provider.exists(aborted_path) is False
        assert (
            provider._client.list_multipart_uploads(
                Bucket=provider._bucket_name, Prefix=f"{prefix}/"
            ).get("Uploads", [])
            == []
        )

    assert all(
        not provider.exists(path) for path in (small_path, multipart_path, aborted_path)
    )


@pytest.mark.unit
def test_s3_explicit_opt_in_requires_a_dedicated_bucket(monkeypatch):
    monkeypatch.setenv("CFMS_TEST_S3_WRITE", "1")
    monkeypatch.delenv("CFMS_TEST_S3_BUCKET", raising=False)
    fixture = s3_integration_provider.__wrapped__(monkeypatch)
    with pytest.raises(pytest.fail.Exception, match="CFMS_TEST_S3_BUCKET"):
        next(fixture)


@pytest.mark.unit
def test_s3_without_opt_in_does_not_connect(monkeypatch):
    monkeypatch.delenv("CFMS_TEST_S3_WRITE", raising=False)
    fixture = s3_integration_provider.__wrapped__(monkeypatch)
    with pytest.raises(pytest.skip.Exception):
        next(fixture)
