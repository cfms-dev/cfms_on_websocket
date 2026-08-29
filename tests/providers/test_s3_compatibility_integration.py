import os
import uuid

import pytest


@pytest.fixture
def s3_integration_provider():
    if os.environ.get("CFMS_TEST_S3_WRITE") != "1":
        pytest.skip("set CFMS_TEST_S3_WRITE=1 to enable S3 compatibility tests")
    bucket = os.environ.get("CFMS_TEST_S3_BUCKET")
    if not bucket:
        pytest.skip("CFMS_TEST_S3_BUCKET must name a dedicated test bucket")

    pytest.importorskip("boto3")
    from include.providers.storage.s3 import S3StorageProvider

    return S3StorageProvider(
        bucket_name=bucket,
        endpoint_url=os.environ.get("CFMS_TEST_S3_ENDPOINT_URL"),
        aws_access_key_id=None,
        aws_secret_access_key=None,
        region_name=os.environ.get("CFMS_TEST_S3_REGION"),
        addressing_style=os.environ.get("CFMS_TEST_S3_ADDRESSING_STYLE", "auto"),
        max_pool_connections=4,
    )


def test_s3_compatible_read_write_resume_and_abort(s3_integration_provider):
    provider = s3_integration_provider
    prefix = f"cfms-integration/{uuid.uuid4().hex}"
    small_path = f"{prefix}/small.bin"
    multipart_path = f"{prefix}/multipart.bin"
    aborted_path = f"{prefix}/aborted.bin"
    created_paths = []

    try:
        with provider.fopen(small_path, "wb") as target:
            target.write(b"0123456789")
        created_paths.append(small_path)

        with provider.fopen(small_path, "rb") as source:
            source.seek(4)
            assert source.read() == b"456789"

        file_size = 5 * 1024 * 1024 + 512
        upload = provider.open_resumable_upload(
            multipart_path,
            file_size=file_size,
            chunk_size=512,
        )
        try:
            upload.write(b"a" * upload.checkpoint_size)
            upload.write(b"b" * (file_size - upload.checkpoint_size))
            upload.finish()
        finally:
            if upload.session_id is not None:
                upload.abort()
        created_paths.append(multipart_path)
        assert provider.getsize(multipart_path) == file_size

        abandoned = provider.open_resumable_upload(
            aborted_path,
            file_size=10 * 1024 * 1024,
            chunk_size=512,
        )
        try:
            abandoned.write(b"c" * abandoned.checkpoint_size)
        finally:
            abandoned.abort()
        assert provider.exists(aborted_path) is False
    finally:
        for path in reversed(created_paths):
            provider.remove(path)
