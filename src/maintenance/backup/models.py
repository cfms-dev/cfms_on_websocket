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
            return cls(
                format_version=int(data["format_version"]),
                created_at=str(data["created_at"]),
                core_version=str(data["core_version"]),
                compression=str(data["compression"]),
                encryption=str(data["encryption"]),
                nonce=str(data["nonce"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise BackupFormatError("Backup header is missing required fields") from exc

    def as_dict(self) -> dict[str, Any]:
        return {
            "format_version": self.format_version,
            "created_at": self.created_at,
            "core_version": self.core_version,
            "compression": self.compression,
            "encryption": self.encryption,
            "nonce": self.nonce,
        }
