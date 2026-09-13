import struct
from pathlib import Path

from maintenance.operations.exceptions import MaintenanceOperationError

_ZIP_END_SIGNATURE = b"PK\x05\x06"
_ZIP_END_RECORD_BYTES = 22
_ZIP_MAX_COMMENT_BYTES = 65_535


def validate_zip_member_count(
    path: Path,
    *,
    maximum: int,
    description: str,
) -> None:
    try:
        size = path.stat().st_size
        tail_size = min(size, _ZIP_END_RECORD_BYTES + _ZIP_MAX_COMMENT_BYTES)
        with path.open("rb") as package_file:
            package_file.seek(size - tail_size)
            tail = package_file.read(tail_size)
    except OSError as exc:
        raise MaintenanceOperationError(
            f"Unable to read {description} {path}: {exc}"
        ) from exc

    end_offset = tail.rfind(_ZIP_END_SIGNATURE)
    if end_offset < 0 or len(tail) - end_offset < _ZIP_END_RECORD_BYTES:
        return
    (
        _,
        disk_number,
        directory_disk,
        disk_members,
        total_members,
        _,
        _,
        _,
    ) = struct.unpack_from("<4s4H2LH", tail, end_offset)
    if disk_number != 0 or directory_disk != 0 or disk_members != total_members:
        raise MaintenanceOperationError(
            f"Multi-disk {description} archives are not supported"
        )
    if total_members == 0xFFFF or total_members > maximum:
        raise MaintenanceOperationError(
            f"{description.capitalize()} contains more than {maximum} members"
        )
