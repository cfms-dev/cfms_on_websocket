import base64
import binascii
import contextlib
import datetime as dt
import enum
import logging
import lzma
import os
import tarfile
from pathlib import Path
from typing import Any

import orjson
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from maintenance.backup.archive import _add_staged_file
from maintenance.backup.constants import (
    BACKUP_FORMAT_VERSION,
    BACKUP_MAGIC,
    GCM_NONCE_BYTES,
    GCM_TAG_BYTES,
    HEADER_LENGTH_BYTES,
    HUMAN_KEY_ALPHABET,
    HUMAN_KEY_DATA_LENGTH,
    HUMAN_KEY_GROUP_SIZE,
    HUMAN_KEY_MAX_VALUE,
    HUMAN_KEY_SEPARATOR,
    MAX_HEADER_BYTES,
)
from maintenance.backup.models import (
    BackupFormatError,
    BackupHeader,
    BackupIntegrityError,
)
from maintenance.backup.progress import _BackupProgressReporter
from maintenance.backup.selection import BACKUP_TABLE_NAMES

LOGGER = logging.getLogger(__name__)


def read_backup_header(
    backup_path: str | os.PathLike[str],
) -> BackupHeader:
    header, _header_bytes, _ciphertext_offset = _read_header_bytes(backup_path)
    _validate_header(header)
    return header


def encode_backup_key(key: bytes) -> str:
    if len(key) != 32:
        raise ValueError("Backup key must be exactly 32 bytes")
    value = int.from_bytes(key, "big")
    chars = []
    for _ in range(HUMAN_KEY_DATA_LENGTH):
        value, index = divmod(value, len(HUMAN_KEY_ALPHABET))
        chars.append(HUMAN_KEY_ALPHABET[index])
    if value:
        raise ValueError("Backup key is too large for the human-readable format")

    encoded = "".join(reversed(chars))
    groups = [
        encoded[index : index + HUMAN_KEY_GROUP_SIZE]
        for index in range(0, len(encoded), HUMAN_KEY_GROUP_SIZE)
    ]
    return HUMAN_KEY_SEPARATOR.join(groups)


def decode_backup_key(value: str) -> bytes:
    normalized = value.strip()
    if not normalized:
        raise ValueError("Backup key cannot be empty")
    padding = "=" * (-len(normalized) % 4)
    try:
        decoded = base64.urlsafe_b64decode(normalized + padding)
        if len(decoded) == 32:
            return decoded
    except (binascii.Error, ValueError) as exc:
        if _looks_like_human_backup_key(normalized):
            return _decode_human_backup_key(normalized)
        raise ValueError("Backup key is not valid base64url") from exc
    if _looks_like_human_backup_key(normalized):
        return _decode_human_backup_key(normalized)
    raise ValueError("Backup key must decode to exactly 32 bytes")


def _decode_human_backup_key(value: str) -> bytes:
    data = _normalize_human_backup_key(value)
    if len(data) != HUMAN_KEY_DATA_LENGTH:
        raise ValueError(
            f"Human-readable backup key must contain {HUMAN_KEY_DATA_LENGTH} "
            "data characters"
        )

    number = 0
    alphabet_index = {
        character: index for index, character in enumerate(HUMAN_KEY_ALPHABET)
    }
    for character in data:
        try:
            digit = alphabet_index[character]
        except KeyError as exc:
            raise ValueError(
                f"Human-readable backup key contains invalid character {character!r}"
            ) from exc
        number = number * len(HUMAN_KEY_ALPHABET) + digit

    if number >= HUMAN_KEY_MAX_VALUE:
        raise ValueError("Human-readable backup key value is out of range")
    return number.to_bytes(32, "big")


def _looks_like_human_backup_key(value: str) -> bool:
    data = _normalize_human_backup_key(value)
    return len(data) == HUMAN_KEY_DATA_LENGTH or HUMAN_KEY_SEPARATOR in value


def _normalize_human_backup_key(value: str) -> str:
    return value.replace(HUMAN_KEY_SEPARATOR, "").replace(" ", "")


def _write_encrypted_archive(
    output_path: Path,
    staging_dir: Path,
    header_bytes: bytes,
    key: bytes,
    nonce: bytes,
    *,
    progress_reporter: _BackupProgressReporter | None = None,
) -> None:
    prefix = _header_prefix(header_bytes)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
    encryptor = cipher.encryptor()
    encryptor.authenticate_additional_data(prefix)

    compressed_payload = staging_dir / "payload.tar.xz"
    temp_output = output_path.with_name(f".{output_path.name}.{os.getpid()}.tmp")
    LOGGER.debug("Writing encrypted archive via temporary file %s", temp_output)
    try:
        _write_compressed_payload(
            compressed_payload,
            staging_dir,
            progress_reporter=progress_reporter,
        )
        with temp_output.open("wb") as raw_output:
            raw_output.write(prefix)
            with compressed_payload.open("rb") as source:
                while chunk := source.read(1024 * 1024):
                    raw_output.write(encryptor.update(chunk))
            raw_output.write(encryptor.finalize())
            raw_output.write(encryptor.tag)
        os.replace(temp_output, output_path)
        LOGGER.debug("Encrypted archive written to %s", output_path)
    except Exception:
        with contextlib.suppress(FileNotFoundError):
            temp_output.unlink()
        raise


def _write_compressed_payload(
    output_path: Path,
    staging_dir: Path,
    *,
    progress_reporter: _BackupProgressReporter | None = None,
) -> None:
    LOGGER.debug("Creating compressed payload at %s", output_path)
    staged_files = sorted((staging_dir / "files").iterdir())
    staged_tables = staging_dir / "tables"
    archive_members = [
        (staging_dir / "manifest.json", "manifest.json"),
        *(
            (
                staged_tables / f"{table_name}.jsonl",
                f"tables/{table_name}.jsonl",
            )
            for table_name in BACKUP_TABLE_NAMES
            if (staged_tables / f"{table_name}.jsonl").is_file()
        ),
        *((staged_file, f"files/{staged_file.name}") for staged_file in staged_files),
    ]
    total_members = len(archive_members)
    with (
        lzma.open(output_path, "wb", preset=6) as compressed,
        tarfile.open(fileobj=compressed, mode="w|") as tar,
    ):
        for member_index, (source_path, archive_path) in enumerate(
            archive_members,
            start=1,
        ):
            _add_staged_file(
                tar,
                source_path,
                archive_path,
                progress_reporter=progress_reporter,
                member_index=member_index,
                total_members=total_members,
            )
    LOGGER.debug("Compressed payload created at %s", output_path)


def _decrypt_payload(
    backup_path: str | os.PathLike[str],
    output_path: Path,
    key: bytes,
    header: BackupHeader,
    header_bytes: bytes,
    ciphertext_offset: int,
) -> None:
    nonce = _decode_bytes(header.nonce)
    backup = Path(backup_path)
    size = backup.stat().st_size
    ciphertext_length = size - ciphertext_offset - GCM_TAG_BYTES
    if ciphertext_length < 0:
        raise BackupFormatError("Backup file is truncated")
    LOGGER.debug(
        "Decrypting backup payload: ciphertext_bytes=%d output=%s",
        ciphertext_length,
        output_path,
    )

    with backup.open("rb") as source:
        source.seek(size - GCM_TAG_BYTES)
        tag = source.read(GCM_TAG_BYTES)
        source.seek(ciphertext_offset)

        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))
        decryptor = cipher.decryptor()
        decryptor.authenticate_additional_data(_header_prefix(header_bytes))

        remaining = ciphertext_length
        try:
            with output_path.open("wb") as target:
                while remaining:
                    chunk = source.read(min(1024 * 1024, remaining))
                    if not chunk:
                        raise BackupFormatError("Backup file ended unexpectedly")
                    remaining -= len(chunk)
                    target.write(decryptor.update(chunk))
                target.write(decryptor.finalize())
        except InvalidTag as exc:
            with contextlib.suppress(FileNotFoundError):
                output_path.unlink()
            raise BackupIntegrityError(
                "Backup decryption failed; the key may be wrong or the file was "
                "modified"
            ) from exc
    LOGGER.debug("Decrypted payload written to %s", output_path)


def _read_header_bytes(
    backup_path: str | os.PathLike[str],
) -> tuple[BackupHeader, bytes, int]:
    LOGGER.debug("Reading backup header from %s", backup_path)
    with Path(backup_path).open("rb") as f:
        magic = f.read(len(BACKUP_MAGIC))
        if magic != BACKUP_MAGIC:
            raise BackupFormatError("File is not a CFMS backup")
        raw_length = f.read(HEADER_LENGTH_BYTES)
        if len(raw_length) != HEADER_LENGTH_BYTES:
            raise BackupFormatError("Backup header length is missing")
        header_length = int.from_bytes(raw_length, "big")
        if header_length <= 0 or header_length > MAX_HEADER_BYTES:
            raise BackupFormatError("Backup header length is invalid")
        header_bytes = f.read(header_length)
        if len(header_bytes) != header_length:
            raise BackupFormatError("Backup header is truncated")
        try:
            data = orjson.loads(header_bytes)
        except orjson.JSONDecodeError as exc:
            raise BackupFormatError("Backup header is not valid JSON") from exc
    return (
        BackupHeader.from_mapping(data),
        header_bytes,
        len(BACKUP_MAGIC) + HEADER_LENGTH_BYTES + header_length,
    )


def _validate_header(header: BackupHeader) -> None:
    if header.format_version != BACKUP_FORMAT_VERSION:
        raise BackupFormatError(
            f"Unsupported backup format version: {header.format_version}"
        )
    if header.compression != "xz":
        raise BackupFormatError(f"Unsupported compression: {header.compression}")
    if header.encryption != "AES-256-GCM":
        raise BackupFormatError(f"Unsupported encryption: {header.encryption}")
    if len(_decode_bytes(header.nonce)) != GCM_NONCE_BYTES:
        raise BackupFormatError("Backup header nonce length is invalid")


def _encode_header(header: BackupHeader) -> bytes:
    return orjson.dumps(header.as_dict(), option=orjson.OPT_SORT_KEYS)


def _header_prefix(header_bytes: bytes) -> bytes:
    return (
        BACKUP_MAGIC
        + len(header_bytes).to_bytes(HEADER_LENGTH_BYTES, "big")
        + header_bytes
    )


def _serialize_value(value: Any) -> Any:
    if isinstance(value, dt.datetime):
        return value.isoformat()
    if isinstance(value, enum.Enum):
        return value.value
    if isinstance(value, dict):
        return {str(key): _serialize_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_serialize_value(item) for item in value]
    if isinstance(value, tuple):
        return [_serialize_value(item) for item in value]
    return value


def _serialize_table_value(table_name: str, column_name: str, value: Any) -> Any:
    if (
        value is not None
        and table_name == "comments"
        and column_name == "content_digest"
    ):
        if not isinstance(value, (bytes, bytearray, memoryview)):
            raise BackupIntegrityError("Invalid binary comment digest in database")
        digest = bytes(value)
        if len(digest) != 32:
            raise BackupIntegrityError("Invalid binary comment digest in database")
        return digest.hex()
    return _serialize_value(value)


def _encode_bytes(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _decode_bytes(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)
