from collections.abc import Callable
from dataclasses import dataclass
from typing import Any


class BackupError(RuntimeError):
    pass


class BackupFormatError(BackupError):
    pass


class BackupIntegrityError(BackupError):
    pass


class BackupRestoreError(BackupError):
    pass


class BackupWarning(UserWarning):
    pass


BackupWarningHandler = Callable[[str], None]


@dataclass(frozen=True)
class BackupHeader:
    format_version: int
    created_at: str
    core_version: str
    compression: str
    encryption: str
    nonce: str

    @classmethod
    def from_mapping(cls, data: dict[str, Any]) -> BackupHeader:
        try:
            format_version = data["format_version"]
            created_at = data["created_at"]
            core_version = data["core_version"]
            compression = data["compression"]
            encryption = data["encryption"]
            nonce = data["nonce"]
        except (KeyError, TypeError) as exc:
            raise BackupFormatError("Backup header is missing required fields") from exc
        if (
            isinstance(format_version, bool)
            or not isinstance(format_version, int)
            or not isinstance(created_at, str)
            or not isinstance(core_version, str)
            or not isinstance(compression, str)
            or not isinstance(encryption, str)
            or not isinstance(nonce, str)
        ):
            raise BackupFormatError("Backup header contains invalid field types")
        return cls(
            format_version=format_version,
            created_at=created_at,
            core_version=core_version,
            compression=compression,
            encryption=encryption,
            nonce=nonce,
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "format_version": self.format_version,
            "created_at": self.created_at,
            "core_version": self.core_version,
            "compression": self.compression,
            "encryption": self.encryption,
            "nonce": self.nonce,
        }
