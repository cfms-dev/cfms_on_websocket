__all__ = ["S3FileObject", "S3StorageProvider"]

import base64
import hashlib
from io import UnsupportedOperation
from types import TracebackType
from typing import Any

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
from botocore.response import StreamingBody

from include.providers.base import FileObject, StorageProvider


class S3FileObject(FileObject):
    def __init__(self, client, bucket_name: str, key: str, mode: str = "rb"):
        self._client = client
        self._hasher = hashlib.sha256()
        self._bucket_name = bucket_name
        self._key = key
        self._mode = mode
        self._closed = False

        if "w" in mode:
            self._upload_id = None
            self._parts = []
            self._buffer = bytearray()
            self._part_number = 1
        else:
            response = self._client.get_object(Bucket=self._bucket_name, Key=self._key)
            self._body: StreamingBody = response["Body"]

    def read(self, size: int = -1) -> bytes:
        if "w" in self._mode:
            raise NotImplementedError
        return self._body.read(size)

    def write(self, data: bytes) -> int:
        if "w" not in self._mode:
            raise NotImplementedError
        if self._closed:
            raise ValueError("I/O operation on closed file")

        self._buffer.extend(data)
        self._hasher.update(data)
        bytes_written = len(data)

        chunk_size = 5 * 1024 * 1024
        # S3 multipart uploads require parts to be at least 5MB (except the last part)
        while len(self._buffer) >= chunk_size:
            if self._upload_id is None:
                self._upload_id = self._client.create_multipart_upload(
                    Bucket=self._bucket_name, Key=self._key
                )["UploadId"]

            view = memoryview(self._buffer)
            chunk = view[:chunk_size].tobytes()
            view.release()
            self._upload_part(chunk)
            del self._buffer[:chunk_size]

        return bytes_written

    def _upload_part(self, data: bytes):
        checksum = base64.b64encode(hashlib.sha256(data).digest()).decode()
        response = self._client.upload_part(
            Bucket=self._bucket_name,
            Key=self._key,
            PartNumber=self._part_number,
            UploadId=self._upload_id,
            Body=data,
            ChecksumSHA256=checksum,
        )
        self._parts.append({"PartNumber": self._part_number, "ETag": response["ETag"]})
        self._part_number += 1

    def close(self) -> None:
        if self._closed:
            return

        if "w" in self._mode:
            overall_checksum = base64.b64encode(self._hasher.digest()).decode()
            if self._upload_id is None:
                # Never started multipart, just do a put_object
                self._client.put_object(
                    Bucket=self._bucket_name,
                    Key=self._key,
                    Body=self._buffer,
                    ChecksumSHA256=overall_checksum,
                )
                self._buffer.clear()
            else:
                if len(self._buffer) > 0:
                    self._upload_part(self._buffer)
                    self._buffer.clear()

                self._client.complete_multipart_upload(
                    Bucket=self._bucket_name,
                    Key=self._key,
                    UploadId=self._upload_id,
                    MultipartUpload={"Parts": self._parts},
                    ChecksumSHA256=overall_checksum,
                )
        else:
            self._body.close()

        self._closed = True

    def seekable(self) -> bool:
        if "w" in self._mode:
            return False
        return self._body.seekable()

    def seek(self, offset: int, whence: int = 0, /) -> int:
        if "w" in self._mode:
            raise NotImplementedError
        return self._body.seek(offset, whence)

    def tell(self) -> int:
        if "w" in self._mode:
            raise NotImplementedError
        return self._body.tell()

    def truncate(self, size: Any = None, /) -> int:
        if "w" in self._mode:
            raise NotImplementedError
        return self._body.truncate(size)

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool | None:
        if exc_type is not None and "w" in self._mode:
            if self._upload_id is not None:
                self._client.abort_multipart_upload(
                    Bucket=self._bucket_name,
                    Key=self._key,
                    UploadId=self._upload_id,
                )
            self._closed = True
            return False

        self.close()


class S3StorageProvider(StorageProvider):
    def __init__(
        self,
        bucket_name: str,
        endpoint_url: str,
        aws_access_key_id: str,
        aws_secret_access_key: str,
        region_name: str = "us-east-1",
    ):
        self._bucket_name = bucket_name
        self._config = Config(
            s3={
                "signature_version": "s3v4",
                "addressing_style": "virtual",
            }
        )
        self._client = boto3.client(
            "s3",
            endpoint_url=endpoint_url,
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            config=self._config,
            region_name=region_name,
        )

    def fopen(self, path: str, mode: str = "rb") -> FileObject:
        return S3FileObject(
            client=self._client,
            bucket_name=self._bucket_name,
            key=path.lstrip("/"),
            mode=mode,
        )

    def exists(self, path: str) -> bool:
        if path.endswith("/"):
            return True

        try:
            self._client.head_object(Bucket=self._bucket_name, Key=path.lstrip("/"))
            return True
        except ClientError as e:
            if e.response["Error"]["Code"] == "404":
                return False
            raise

    def remove(self, path: str) -> bool:
        if path.endswith("/"):
            raise UnsupportedOperation("Cannot call remove() on a directory")

        try:
            self._client.delete_object(Bucket=self._bucket_name, Key=path.lstrip("/"))
            return True
        except ClientError:
            return False

    def mkdir(self, path: str, mode: int = 511) -> None:
        return None

    def makedirs(self, name: str, mode: int = 0o777, exist_ok: bool = False) -> None:
        return None

    def getsize(self, filename: str, /) -> int:
        filename = filename.lstrip("/")

        try:
            response = self._client.head_object(Bucket=self._bucket_name, Key=filename)
            return response["ContentLength"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "404":
                raise FileNotFoundError(f"No such file: '{filename}'")
            raise
