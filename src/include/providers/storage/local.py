__all__ = ["LocalFileObject", "LocalStorageProvider"]

import os
from collections.abc import Buffer
from types import TracebackType
from typing import IO, Any

from include.providers.base import FileObject, StorageProvider


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
