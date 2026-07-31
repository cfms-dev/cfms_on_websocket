__all__ = ["S3FileObject", "S3StorageProvider"]

import base64
import hashlib
from collections.abc import Buffer, Callable
from io import UnsupportedOperation
from tempfile import SpooledTemporaryFile
from types import TracebackType
from typing import Any

import boto3
import orjson
from botocore.config import Config
from botocore.exceptions import ClientError
from botocore.response import StreamingBody

from include.providers.base import (
    FileObject,
    ResumableUpload,
    ResumableUploadSizeError,
    StorageProvider,
)

_S3_MIN_PART_SIZE = 5 * 1024 * 1024
_S3_MAX_PART_SIZE = 5 * 1024 * 1024 * 1024
_S3_MAX_PARTS = 10_000


def _s3_checkpoint_size(file_size: int, chunk_size: int) -> int:
    minimum_size = max(
        _S3_MIN_PART_SIZE,
        (file_size + _S3_MAX_PARTS - 1) // _S3_MAX_PARTS,
    )
    checkpoint_size = ((minimum_size + chunk_size - 1) // chunk_size) * chunk_size
    if checkpoint_size > _S3_MAX_PART_SIZE:
        raise ResumableUploadSizeError("File exceeds the S3 multipart upload limit")
    return checkpoint_size


class S3ResumableUpload(ResumableUpload):
    def __init__(
        self,
        client,
        bucket_name: str,
        key: str,
        file_size: int,
        chunk_size: int,
        session_id: str | None,
        checkpoint_size: int | None,
        checkpoint_data: str | None = None,
        checkpoint_callback: Callable[[str], None] | None = None,
    ) -> None:
        self._client = client
        self._bucket_name = bucket_name
        self._key = key
        self._file_size = file_size
        self.checkpoint_size = checkpoint_size or _s3_checkpoint_size(
            file_size, chunk_size
        )
        self._parts: list[dict[str, Any]] = []
        self.checkpoint_data = checkpoint_data
        self._checkpoint_callback = checkpoint_callback
        self._buffer = SpooledTemporaryFile(max_size=8 * 1024 * 1024)
        self._buffer_size = 0
        self._closed = False
        self._completed = False

        if file_size == 0:
            self.session_id = None
            self.offset = 0
            return

        self.session_id = session_id
        if session_id is None:
            self.session_id = self._client.create_multipart_upload(
                Bucket=self._bucket_name,
                Key=self._key,
            )["UploadId"]
            self.offset = 0
            return

        try:
            self._client.list_parts(
                Bucket=self._bucket_name,
                Key=self._key,
                UploadId=self.session_id,
                MaxParts=1,
            )
        except ClientError as error:
            if error.response.get("Error", {}).get("Code") not in {
                "404",
                "NoSuchUpload",
            }:
                raise
            try:
                response = self._client.head_object(
                    Bucket=self._bucket_name, Key=self._key
                )
            except ClientError:
                raise error
            if response["ContentLength"] != file_size:
                raise error
            self.session_id = None
            self.offset = file_size
            self._completed = True
            return

        self._load_checkpoint()

    def _load_checkpoint(self) -> None:
        if self.checkpoint_data is None:
            self.offset = 0
            return
        try:
            parts = orjson.loads(self.checkpoint_data)
        except orjson.JSONDecodeError as exc:
            raise ValueError("S3 multipart upload checkpoint is invalid") from exc
        if not isinstance(parts, list):
            raise ValueError("S3 multipart upload checkpoint is invalid")

        expected_part_number = 1
        self.offset = 0
        for part in parts:
            try:
                part_number = part["PartNumber"]
                part_size = part["Size"]
                etag = part["ETag"]
            except (KeyError, TypeError) as exc:
                raise ValueError("S3 multipart upload checkpoint is invalid") from exc
            if (
                type(part_number) is not int
                or type(part_size) is not int
                or not isinstance(etag, str)
                or part_number != expected_part_number
                or (
                    part_size != self.checkpoint_size
                    and not (
                        part_size < self.checkpoint_size
                        and self.offset + part_size == self._file_size
                    )
                )
            ):
                raise ValueError("S3 multipart upload has invalid checkpoint parts")
            self._parts.append(
                {"PartNumber": part_number, "ETag": etag, "Size": part_size}
            )
            self.offset += part_size
            expected_part_number += 1
        if self.offset > self._file_size:
            raise ValueError("S3 upload progress exceeds the declared file size")

    def _upload_part(self) -> None:
        self._buffer.seek(0)
        part_number = len(self._parts) + 1
        response = self._client.upload_part(
            Bucket=self._bucket_name,
            Key=self._key,
            PartNumber=part_number,
            UploadId=self.session_id,
            Body=self._buffer,
            ContentLength=self._buffer_size,
        )
        self._parts.append(
            {
                "PartNumber": part_number,
                "ETag": response["ETag"],
                "Size": self._buffer_size,
            }
        )
        self.offset += self._buffer_size
        self.checkpoint_data = orjson.dumps(self._parts).decode()
        if self._checkpoint_callback is not None:
            self._checkpoint_callback(self.checkpoint_data)
        self._buffer.close()
        self._buffer = SpooledTemporaryFile(max_size=8 * 1024 * 1024)
        self._buffer_size = 0

    def write(self, data: Buffer) -> int:
        if self._completed:
            raise ValueError("S3 multipart upload is already complete")
        with memoryview(data) as source_view, source_view.cast("B") as byte_view:
            written = self._buffer.write(byte_view)
        self._buffer_size += written
        if self._buffer_size == self.checkpoint_size:
            self._upload_part()
        elif self._buffer_size > self.checkpoint_size:
            raise ValueError("Upload write crossed the S3 checkpoint boundary")
        return written

    def finish(self) -> None:
        if self._completed:
            self.close()
            return
        if self._file_size == 0:
            self._client.put_object(Bucket=self._bucket_name, Key=self._key, Body=b"")
            self._completed = True
            self.close()
            return
        if self.offset + self._buffer_size != self._file_size:
            raise ValueError("S3 multipart upload is incomplete")
        if self._buffer_size:
            self._upload_part()
        self._client.complete_multipart_upload(
            Bucket=self._bucket_name,
            Key=self._key,
            UploadId=self.session_id,
            MultipartUpload={
                "Parts": [
                    {"PartNumber": part["PartNumber"], "ETag": part["ETag"]}
                    for part in self._parts
                ]
            },
        )
        self.session_id = None
        self._completed = True
        self.close()

    def close(self) -> None:
        if self._closed:
            return
        self._buffer.close()
        self._closed = True

    def abort(self) -> None:
        self.close()
        if self.session_id is not None:
            try:
                self._client.abort_multipart_upload(
                    Bucket=self._bucket_name,
                    Key=self._key,
                    UploadId=self.session_id,
                )
            except ClientError as error:
                if error.response.get("Error", {}).get("Code") not in {
                    "404",
                    "NoSuchUpload",
                }:
                    raise
        self.session_id = None
        self.offset = 0
        self.checkpoint_data = None


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

    def write(self, data: Buffer) -> int:
        if "w" not in self._mode:
            raise NotImplementedError
        if self._closed:
            raise ValueError("I/O operation on closed file")

        with memoryview(data) as source_view, source_view.cast("B") as byte_view:
            self._buffer.extend(byte_view)
            self._hasher.update(byte_view)
            bytes_written = byte_view.nbytes

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

    def _upload_part(self, data: Buffer):
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
    supports_resumable_uploads = True

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

    def open_resumable_upload(
        self,
        path: str,
        *,
        file_size: int,
        chunk_size: int,
        session_id: str | None = None,
        checkpoint_size: int | None = None,
        checkpoint_data: str | None = None,
        checkpoint_callback: Callable[[str], None] | None = None,
    ) -> S3ResumableUpload:
        return S3ResumableUpload(
            self._client,
            self._bucket_name,
            path.lstrip("/"),
            file_size,
            chunk_size,
            session_id,
            checkpoint_size,
            checkpoint_data,
            checkpoint_callback,
        )

    def abort_resumable_upload(self, path: str, session_id: str) -> None:
        try:
            self._client.abort_multipart_upload(
                Bucket=self._bucket_name,
                Key=path.lstrip("/"),
                UploadId=session_id,
            )
        except ClientError as error:
            if error.response.get("Error", {}).get("Code") not in {
                "404",
                "NoSuchUpload",
            }:
                raise
