__all__ = ["S3FileObject", "S3StorageProvider"]

import base64
import hashlib
import os
from collections.abc import Buffer, Callable
from io import UnsupportedOperation
from tempfile import SpooledTemporaryFile
from types import TracebackType
from typing import TYPE_CHECKING, Any, Literal

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

if TYPE_CHECKING:
    from types_boto3_s3.client import S3Client
    from types_boto3_s3.type_defs import GetObjectRequestTypeDef

_S3_MIN_PART_SIZE = 5 * 1024 * 1024
_S3_MAX_PART_SIZE = 5 * 1024 * 1024 * 1024
_S3_MAX_PARTS = 10_000
_S3_NOT_FOUND_CODES = {"404", "NoSuchKey", "NotFound"}


def _is_not_found_error(error: ClientError) -> bool:
    response = error.response
    code = response.get("Error", {}).get("Code")
    return code in _S3_NOT_FOUND_CODES or (
        not code and response.get("ResponseMetadata", {}).get("HTTPStatusCode") == 404
    )


def _is_missing_upload_error(error: ClientError) -> bool:
    return (
        _is_not_found_error(error)
        or error.response.get("Error", {}).get("Code") == "NoSuchUpload"
    )


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
        client: S3Client,
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
        self._buffer = SpooledTemporaryFile(max_size=8 * 1024 * 1024)  # noqa: SIM115
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
                UploadId=session_id,
                MaxParts=1,
            )
        except ClientError as error:
            if not _is_missing_upload_error(error):
                raise
            try:
                response = self._client.head_object(
                    Bucket=self._bucket_name, Key=self._key
                )
            except ClientError as head_error:
                if _is_not_found_error(head_error):
                    raise error
                raise
            if response["ContentLength"] != file_size:
                raise
            self.session_id = None
            self.offset = file_size
            self._completed = True
            return

        self._load_checkpoint()

    def _load_checkpoint(self) -> None:
        if self.checkpoint_data is None:
            self._parts = []
            self.offset = 0
            return

        try:
            parts = orjson.loads(self.checkpoint_data)
        except orjson.JSONDecodeError as exc:
            raise ValueError("S3 multipart upload checkpoint is invalid") from exc

        if not isinstance(parts, list):
            raise TypeError("S3 multipart upload checkpoint is invalid")

        loaded_parts = []
        offset = 0

        for expected_part_number, part in enumerate(parts, start=1):
            if not isinstance(part, dict):
                raise TypeError("S3 multipart upload checkpoint is invalid")

            try:
                part_number = part["PartNumber"]
                part_size = part["Size"]
                etag = part["ETag"]
            except KeyError as exc:
                raise TypeError("S3 multipart upload checkpoint is invalid") from exc

            if (
                type(part_number) is not int
                or type(part_size) is not int
                or not isinstance(etag, str)
                or part_number != expected_part_number
                or part_size <= 0
            ):
                raise ValueError("S3 multipart upload has invalid checkpoint parts")

            next_offset = offset + part_size

            if next_offset > self._file_size:
                raise ValueError("S3 upload progress exceeds the declared file size")

            is_regular_part = part_size == self.checkpoint_size
            is_final_part = (
                part_size < self.checkpoint_size and next_offset == self._file_size
            )

            if not (is_regular_part or is_final_part):
                raise ValueError("S3 multipart upload has invalid checkpoint parts")

            loaded_parts.append(
                {
                    "PartNumber": part_number,
                    "ETag": etag,
                    "Size": part_size,
                }
            )
            offset = next_offset

        self._parts = loaded_parts
        self.offset = offset

    def _upload_part(self) -> None:
        session_id = self.session_id
        if session_id is None:
            raise RuntimeError("S3 multipart upload has not been initialized")
        self._buffer.seek(0)
        part_number = len(self._parts) + 1
        response = self._client.upload_part(
            Bucket=self._bucket_name,
            Key=self._key,
            PartNumber=part_number,
            UploadId=session_id,
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
        self._buffer = SpooledTemporaryFile(max_size=8 * 1024 * 1024)  # noqa: SIM115
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
        session_id = self.session_id
        if session_id is None:
            raise RuntimeError("S3 multipart upload has not been initialized")
        self._client.complete_multipart_upload(
            Bucket=self._bucket_name,
            Key=self._key,
            UploadId=session_id,
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
                if not _is_missing_upload_error(error):
                    raise
        self.session_id = None
        self.offset = 0
        self.checkpoint_data = None


class S3FileObject(FileObject):
    def __init__(
        self,
        client: S3Client,
        bucket_name: str,
        key: str,
        mode: str = "rb",
    ) -> None:
        self._client = client
        self._bucket_name = bucket_name
        self._key = key
        self._mode = mode
        self._closed = False

        if "w" in mode:
            self._hasher = hashlib.sha256()
            self._upload_id = None
            self._parts = []
            self._buffer = bytearray()
            self._part_number = 1
        else:
            self._body: StreamingBody | None = None
            self._position = 0
            self._object_size: int | None = None

    def _ensure_open(self) -> None:
        if self._closed:
            raise ValueError("I/O operation on closed file")

    def _load_object_size(self) -> int:
        if self._object_size is not None:
            return self._object_size
        try:
            response = self._client.head_object(
                Bucket=self._bucket_name,
                Key=self._key,
            )
        except ClientError as error:
            if _is_not_found_error(error):
                raise FileNotFoundError(f"No such file: '{self._key}'") from error
            raise
        self._object_size = response["ContentLength"]
        return self._object_size

    def _open_read_body(self) -> StreamingBody:
        request: GetObjectRequestTypeDef = {
            "Bucket": self._bucket_name,
            "Key": self._key,
        }
        if self._position:
            request["Range"] = f"bytes={self._position}-"
        try:
            response = self._client.get_object(**request)
        except ClientError as error:
            if _is_not_found_error(error):
                raise FileNotFoundError(f"No such file: '{self._key}'") from error
            raise

        body = response["Body"]
        if self._position:
            content_range = response.get("ContentRange", "")
            try:
                unit, value = content_range.split(" ", 1)
                byte_range, total = value.split("/", 1)
                start, _end = byte_range.split("-", 1)
                object_size = int(total)
                range_start = int(start)
            except (TypeError, ValueError) as error:
                body.close()
                raise OSError("S3 endpoint returned an invalid byte range") from error
            if unit != "bytes" or range_start != self._position:
                body.close()
                raise OSError("S3 endpoint returned an unexpected byte range")
            self._object_size = object_size
        else:
            self._object_size = response["ContentLength"]
        self._body = body
        return body

    def read(self, size: int = -1) -> bytes:
        if "w" in self._mode:
            raise UnsupportedOperation("not readable")
        self._ensure_open()
        if size == 0:
            return b""
        if self._object_size is not None and self._position >= self._object_size:
            return b""
        body = self._body
        if body is None:
            body = self._open_read_body()
        data = body.read(None if size < 0 else size)
        self._position += len(data)
        return data

    def write(self, data: Buffer) -> int:
        if "w" not in self._mode:
            raise UnsupportedOperation("not writable")
        self._ensure_open()

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
        upload_id = self._upload_id
        if upload_id is None:
            raise RuntimeError("S3 multipart upload has not been initialized")
        part_data = bytes(data)
        checksum = base64.b64encode(hashlib.sha256(part_data).digest()).decode()
        response = self._client.upload_part(
            Bucket=self._bucket_name,
            Key=self._key,
            PartNumber=self._part_number,
            UploadId=upload_id,
            Body=part_data,
            ChecksumSHA256=checksum,
        )
        self._parts.append({"PartNumber": self._part_number, "ETag": response["ETag"]})
        self._part_number += 1

    def close(self) -> None:
        if self._closed:
            return

        if "w" in self._mode:
            if self._upload_id is None:
                overall_checksum = base64.b64encode(self._hasher.digest()).decode()
                # Never started multipart, just do a put_object
                self._client.put_object(
                    Bucket=self._bucket_name,
                    Key=self._key,
                    Body=bytes(self._buffer),
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
                )
        else:
            if self._body is not None:
                self._body.close()

        self._closed = True

    def seekable(self) -> bool:
        self._ensure_open()
        return "w" not in self._mode

    def seek(self, offset: int, whence: int = 0, /) -> int:
        if "w" in self._mode:
            raise UnsupportedOperation("not seekable")
        self._ensure_open()
        match whence:
            case os.SEEK_SET:
                position = offset
            case os.SEEK_CUR:
                position = self._position + offset
            case os.SEEK_END:
                position = self._load_object_size() + offset
            case _:
                raise ValueError(f"invalid whence ({whence}, should be 0, 1 or 2)")
        if position < 0:
            raise ValueError(f"negative seek position {position}")
        if position and self._object_size is None:
            self._load_object_size()
        if position != self._position:
            if self._body is not None:
                self._body.close()
                self._body = None
            self._position = position
        return self._position

    def tell(self) -> int:
        if "w" in self._mode:
            raise UnsupportedOperation("not seekable")
        self._ensure_open()
        return self._position

    def truncate(self, size: Any = None, /) -> int:
        self._ensure_open()
        raise UnsupportedOperation("truncate")

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
        endpoint_url: str | None,
        aws_access_key_id: str | None,
        aws_secret_access_key: str | None,
        region_name: str | None = None,
        aws_session_token: str | None = None,
        addressing_style: Literal["auto", "virtual", "path"] = "auto",
        max_pool_connections: int = 64,
    ):
        endpoint_url = endpoint_url or None
        region_name = region_name or None
        aws_access_key_id = aws_access_key_id or None
        aws_secret_access_key = aws_secret_access_key or None
        aws_session_token = aws_session_token or None
        if (aws_access_key_id is None) != (aws_secret_access_key is None):
            raise ValueError("S3 access key ID and secret access key must be paired")
        if aws_session_token is not None and aws_access_key_id is None:
            raise ValueError("S3 session token requires explicit access credentials")

        self._bucket_name = bucket_name
        self._config = Config(
            signature_version="s3v4",
            max_pool_connections=max_pool_connections,
            retries={"mode": "standard"},
            tcp_keepalive=True,
            s3={"addressing_style": addressing_style},
        )
        client_options = {
            "endpoint_url": endpoint_url,
            "config": self._config,
            "region_name": region_name,
        }
        if aws_access_key_id is not None:
            client_options["aws_access_key_id"] = aws_access_key_id
            client_options["aws_secret_access_key"] = aws_secret_access_key
            if aws_session_token is not None:
                client_options["aws_session_token"] = aws_session_token
        self._client = boto3.client("s3", **client_options)

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
        except ClientError as error:
            if _is_not_found_error(error):
                return False
            raise

    def remove(self, path: str) -> bool:
        if path.endswith("/"):
            raise UnsupportedOperation("Cannot call remove() on a directory")

        try:
            self._client.delete_object(Bucket=self._bucket_name, Key=path.lstrip("/"))
            return True
        except ClientError as error:
            if _is_not_found_error(error):
                return False
            raise

    def mkdir(self, path: str, mode: int = 511) -> None:
        return None

    def makedirs(self, name: str, mode: int = 0o777, exist_ok: bool = False) -> None:
        return None

    def getsize(self, filename: str, /) -> int:
        filename = filename.lstrip("/")

        try:
            response = self._client.head_object(Bucket=self._bucket_name, Key=filename)
            return response["ContentLength"]
        except ClientError as error:
            if _is_not_found_error(error):
                raise FileNotFoundError(f"No such file: '{filename}'") from error
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
            if not _is_missing_upload_error(error):
                raise
