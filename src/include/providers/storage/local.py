__all__ = ["LocalFileObject", "LocalStorageProvider"]

import os
from collections.abc import Buffer, Callable
from contextlib import ExitStack
from types import TracebackType
from typing import IO, Any

from include.providers.base import FileObject, ResumableUpload, StorageProvider


class LocalResumableUpload(ResumableUpload):
    def __init__(self, path: str, file_size: int, chunk_size: int) -> None:
        self._path = path
        with ExitStack() as resources:
            self._file = resources.enter_context(
                open(path, "r+b" if os.path.exists(path) else "w+b")
            )
            existing_size = os.path.getsize(path)
            if existing_size > file_size:
                raise ValueError(
                    "Stored upload progress exceeds the declared file size"
                )
            self.offset = (
                file_size
                if existing_size == file_size
                else existing_size - existing_size % chunk_size
            )
            self._file.truncate(self.offset)
            self._file.seek(self.offset)
            self.session_id = None
            self.checkpoint_size = chunk_size
            self.checkpoint_data = None
            self._closed = False
            self._resources = resources.pop_all()

    def write(self, data: Buffer) -> int:
        written = self._file.write(data)
        self._file.flush()
        self.offset += written
        return written

    def finish(self) -> None:
        self.close()

    def close(self) -> None:
        if self._closed:
            return
        try:
            self._file.flush()
        finally:
            self._resources.close()
            self._closed = True

    def abort(self) -> None:
        self.close()
        try:
            os.remove(self._path)
        except FileNotFoundError:
            pass
        self.offset = 0


class LocalFileObject(FileObject):
    def __init__(self, file: IO[Any]):
        self._file = file

    def read(self, size: int = -1) -> bytes:
        return self._file.read(size)

    def write(self, data: Buffer) -> int:
        return self._file.write(data)

    def close(self) -> None:
        self._file.close()

    def seekable(self) -> bool:
        return self._file.seekable()

    def seek(self, offset: int, whence: int = 0, /) -> int:
        return self._file.seek(offset, whence)

    def tell(self) -> int:
        return self._file.tell()

    def truncate(self, size: Any = None, /) -> int:
        return self._file.truncate(size)

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool | None:
        self._file.close()


class LocalStorageProvider(StorageProvider):
    def fopen(self, path: str, mode: str = "rb") -> LocalFileObject:
        return LocalFileObject(open(path, mode))

    def exists(self, path: str) -> bool:
        return os.path.exists(path)

    def remove(self, path: str) -> bool:
        if os.path.exists(path):
            os.remove(path)
            return True
        return False

    def mkdir(self, path: str, mode: int = 511) -> None:
        os.mkdir(path, mode=mode)

    def makedirs(self, name: str, mode: int = 0o777, exist_ok: bool = False) -> None:
        os.makedirs(name, mode=mode, exist_ok=exist_ok)

    def getsize(self, filename: str, /) -> int:
        return os.path.getsize(filename)

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
    ) -> LocalResumableUpload:
        return LocalResumableUpload(path, file_size, chunk_size)

    def abort_resumable_upload(self, path: str, session_id: str) -> None:
        return None
