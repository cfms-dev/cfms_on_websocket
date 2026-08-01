__all__ = [
    "AVAILABLE_ACCESS_TYPES",
    "AVAILABLE_BLOCK_TYPES",
    "CORE_VERSION",
    "DEFAULT_SSL_CERT_VALIDITY_DAYS",
    "DEFAULT_TOKEN_EXPIRY_SECONDS",
    "DEFAULT_TRUSTED_PROXY_NETWORKS",
    "DOWNLOAD_TRANSFER_MAX_CHUNK_SIZE",
    "DOWNLOAD_TRANSFER_MIN_CHUNK_SIZE",
    "FILE_TASK_DEFAULT_DURATION_SECONDS",
    "FILE_TASK_EVENT_CHANNEL",
    "GLOBAL_BROADCAST_EVENT_CHANNEL",
    "LOGIN_GUARD_EVENT_CHANNEL",
    "MAX_PARAM_SIZE",
    "NONCE_MIN_LENGTH",
    "PAGINATION_DEFAULT_PAGE_SIZE",
    "PAGINATION_MAX_PAGE_SIZE",
    "PROTOCOL_VERSION",
    "QUERY_CHUNK_SIZE",
    "REPLAY_PROTECTION_TIME_WINDOW_SECONDS",
    "ROOT_ABSPATH",
    "ROOT_DIRECTORY_ID",
    "UPLOAD_TRANSFER_MAX_CHUNK_SIZE",
    "UPLOAD_TRANSFER_MIN_CHUNK_SIZE",
    "USERNAME_DATABASE_MAX_LENGTH",
    "USERNAME_MAX_LENGTH",
]

from pathlib import Path

from include.config.version import Version

CORE_VERSION = Version("0.4.1.260801_alpha")
PROTOCOL_VERSION = 21

ROOT_ABSPATH = Path(__file__).resolve().parents[2]

# Event bus channels
GLOBAL_BROADCAST_EVENT_CHANNEL = "system:broadcast"
LOGIN_GUARD_EVENT_CHANNEL = "security:login_guard"
FILE_TASK_EVENT_CHANNEL = "documents:file_tasks"

AVAILABLE_ACCESS_TYPES = ["read", "write", "move", "manage"]
AVAILABLE_BLOCK_TYPES: set = {"read", "write", "move"}

# Authentication and Security Constants
DEFAULT_TOKEN_EXPIRY_SECONDS = 3600  # 1 hour
DEFAULT_SSL_CERT_VALIDITY_DAYS = 365  # 1 year
USERNAME_MAX_LENGTH = 64  # Must not exceed USERNAME_DATABASE_MAX_LENGTH

# File Transfer Constants
DOWNLOAD_TRANSFER_MIN_CHUNK_SIZE = 16 * 1024
DOWNLOAD_TRANSFER_MAX_CHUNK_SIZE = 2 * 1024 * 1024
UPLOAD_TRANSFER_MAX_CHUNK_SIZE = (
    1024 * 64
)  # 64KB - size threshold for determining end of transfer
UPLOAD_TRANSFER_MIN_CHUNK_SIZE = 512
FILE_TASK_DEFAULT_DURATION_SECONDS = 3600  # 1 hour

# Replay Attack Protection Constants
REPLAY_PROTECTION_TIME_WINDOW_SECONDS = 15  # Maximum age of a request timestamp
NONCE_MIN_LENGTH = 16  # Minimum length of a nonce string

# Root directory virtual folder ID — used to store access rules for the root directory
ROOT_DIRECTORY_ID = "/"

# Pagination Constants
PAGINATION_DEFAULT_PAGE_SIZE = 128
PAGINATION_MAX_PAGE_SIZE = 128

# Database Constants
USERNAME_DATABASE_MAX_LENGTH = 256  # Maximum length of username field in the database
MAX_PARAM_SIZE = 950  # Maximum number of parameters in a single SQL query
QUERY_CHUNK_SIZE = 576  # used to prevent hitting the limit of bind variables per query

# Networks of trusted reverse proxies that may set X-Forwarded-For / X-Real-IP.
DEFAULT_TRUSTED_PROXY_NETWORKS = ("127.0.0.1/32", "::1/128")
