__all__ = [
    "CORE_VERSION",
    "PROTOCOL_VERSION",
    "ROOT_ABSPATH",
    "AVAILABLE_ACCESS_TYPES",
    "AVAILABLE_BLOCK_TYPES",
    "DEFAULT_TOKEN_EXPIRY_SECONDS",
    "DEFAULT_SSL_CERT_VALIDITY_DAYS",
    "FILE_TRANSFER_MAX_CHUNK_SIZE",
    "FILE_TRANSFER_MIN_CHUNK_SIZE",
    "FILE_TASK_DEFAULT_DURATION_SECONDS",
    "REPLAY_PROTECTION_TIME_WINDOW_SECONDS",
    "NONCE_MIN_LENGTH",
    "ROOT_DIRECTORY_ID",
    "PAGINATION_DEFAULT_PAGE_SIZE",
    "PAGINATION_MAX_PAGE_SIZE",
    "MAX_PARAM_SIZE",
    "QUERY_CHUNK_SIZE",
    "TRUSTED_PROXY_IPS",
]

from pathlib import Path

from include.config.version import Version

CORE_VERSION = Version("0.4.0.260719_alpha")
PROTOCOL_VERSION = 16

ROOT_ABSPATH = Path(__file__).resolve().parents[2]

AVAILABLE_ACCESS_TYPES = ["read", "write", "move", "manage"]
AVAILABLE_BLOCK_TYPES: set = {"read", "write", "move"}

# Authentication and Security Constants
DEFAULT_TOKEN_EXPIRY_SECONDS = 3600  # 1 hour
DEFAULT_SSL_CERT_VALIDITY_DAYS = 365  # 1 year

# File Transfer Constants
FILE_TRANSFER_MAX_CHUNK_SIZE = (
    1024 * 64
)  # 64KB - size threshold for determining end of transfer
FILE_TRANSFER_MIN_CHUNK_SIZE = 512
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
MAX_PARAM_SIZE = 950  # Maximum number of parameters in a single SQL query
QUERY_CHUNK_SIZE = 576  # used to prevent hitting the limit of bind variables per query

# IP addresses of trusted reverse proxies that may set X-Forwarded-For / X-Real-IP.
# Adjust this set as needed for your deployment environment.
TRUSTED_PROXY_IPS = frozenset({"127.0.0.1", "::1"})
