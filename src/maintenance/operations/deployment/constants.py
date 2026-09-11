import re
import zipfile

MAX_PACKAGE_BYTES = 64 * 1024 * 1024
MAX_UNCOMPRESSED_BYTES = 256 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 4096
_COPY_CHUNK_BYTES = 1024 * 1024
_SHA256_PATTERN = re.compile(r"[0-9a-fA-F]{64}").fullmatch
_VERSION_PATTERN = re.compile(r"\d+\.\d+\.\d+").fullmatch
_EXTENSION_IDENTIFIER_PATTERN = re.compile(r"[a-z][a-z0-9_]{0,254}").fullmatch
_ALLOWED_ZIP_COMPRESSIONS = {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
_REQUIRED_RELEASE_FILES = {
    "pyproject.toml",
    "uv.lock",
    "src/alembic.ini",
    "src/config.toml.sample",
    "src/main.py",
}
_OPERATOR_OWNED_PREFIXES = (
    "src/.maintenance/",
    "src/content/files/",
    "src/content/logs/",
)
