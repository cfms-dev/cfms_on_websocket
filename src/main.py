"""
Main entry module.

Initializes a fresh database and seeds application data on first startup. Schema
upgrades for existing databases remain explicit maintenance operations.
"""

import os
import socket
import ssl
import sys

from loguru import logger
from websockets.sync.server import serve

import include.database.models  # noqa: F401
from include.config.constants import (
    CORE_VERSION,
    DEFAULT_SSL_CERT_VALIDITY_DAYS,
    FILE_TASK_EVENT_CHANNEL,
    GLOBAL_BROADCAST_EVENT_CHANNEL,
    LOGIN_GUARD_EVENT_CHANNEL,
    ROOT_DIRECTORY_ID,
)
from include.config.paths import (
    EXECUTABLE_ABSPATH,
    EXTENSION_ROOT,
)
from include.config.settings import global_config
from include.config.validation import get_config_warnings, get_enabled_extensions
from include.database.initialization import initialize_database_schema
from include.database.models.documents import (
    Document,
    DocumentMetadata,
    DocumentRevision,
    Folder,
)
from include.database.models.files import File
from include.database.session import Base, Session, engine
from include.domains.access.authorization.access_rules import set_access_rules
from include.domains.access.permissions import Permissions
from include.domains.documents.commands.upload_cleanup import (
    try_reclaim_abandoned_uploads,
)
from include.domains.documents.file_task_signals import on_file_task_event
from include.domains.operations.broadcast import on_global_broadcast
from include.domains.security.guards.login import LoginGuard
from include.domains.security.guards.request_rate_control import (
    validate_handler_rate_limit_costs,
)
from include.domains.security.handlers.debugging import RequestThrowExceptionHandler
from include.extensions.manager import (
    load_extensions_from_directory,
    pm,
)
from include.providers.bootstrap import initialize_providers
from include.providers.manager import ProviderManager
from include.runtime_lock import RuntimeLockError, server_runtime_lock
from include.transport.client_address import get_bind_options
from include.transport.request_entrypoint import global_process_request
from include.transport.request_handler import validate_request_handler_models
from include.transport.router import (
    available_functions,
    handle_connection,
    whitelisted_functions,
)
from include.transport.tls import create_server_ssl_context

# fix
os.makedirs(EXECUTABLE_ABSPATH / "content" / "logs", exist_ok=True)
os.makedirs(EXECUTABLE_ABSPATH / "content" / "ssl", exist_ok=True)


def ensure_root_folder():
    """
    Ensure that the sentinel Folder record for the root directory exists in
    the database.

    This record has no children of its own; it exists only so access rules
    and ObjectAccessEntries can be attached to the root directory through the
    normal access-control mechanism.

    When created, the root folder is configured with default access rules that
    restrict read, write, and manage access to the ``sysop`` group only.
    """
    _sysop_rule = {
        "match": "all",
        "match_groups": [
            {
                "match": "all",
                "groups": {"match": "all", "require": ["sysop"]},
            }
        ],
    }
    _DEFAULT_ROOT_ACCESS_RULES = {
        "read": [],
        "write": [_sysop_rule],
        "manage": [_sysop_rule],
    }

    with Session() as session:
        if not session.get(Folder, ROOT_DIRECTORY_ID):
            root = Folder(id=ROOT_DIRECTORY_ID, name="/")
            session.add(root)
            set_access_rules(root, _DEFAULT_ROOT_ACCESS_RULES, inherit_parent=False)
            session.commit()


def server_init():
    """
    Initialize the server by checking whether the database is already set up.

    If it is not, create the necessary tables and a default admin user.
    """
    import datetime
    import secrets

    from include.domains.identity.commands.groups import create_group

    initialize_database_schema(engine, Base.metadata)

    # Ensure the root folder exists before seeding any objects that reference it.
    ensure_root_folder()

    create_group(
        group_name="user",
        permissions=[
            {"permission": Permissions.SET_PASSWD},
            {"permission": Permissions.SEARCH},
        ],
    )
    create_group(
        group_name="sysop",
        permissions=[
            {"permission": Permissions.MOVE},
            {"permission": Permissions.SHUTDOWN},
            {"permission": Permissions.SUPER_CREATE_DOCUMENT},
            {"permission": Permissions.SUPER_CREATE_DIRECTORY},
            {"permission": Permissions.SUPER_LIST_DIRECTORY},
            {"permission": Permissions.CREATE_DOCUMENT},
            {"permission": Permissions.CREATE_DIRECTORY},
            {"permission": Permissions.DELETE_DOCUMENT},
            {"permission": Permissions.RENAME_DOCUMENT},
            {"permission": Permissions.DELETE_DIRECTORY},
            {"permission": Permissions.RENAME_DIRECTORY},
            {"permission": Permissions.MANAGE_SYSTEM},
            {"permission": Permissions.DIAGNOSTICS},
            {"permission": Permissions.VIEW_SCHEDULES},
            {"permission": Permissions.MANAGE_SCHEDULES},
            {"permission": Permissions.CREATE_USER},
            {"permission": Permissions.DELETE_USER},
            {"permission": Permissions.RENAME_USER},
            {"permission": Permissions.MANAGE_USER_STATUS},
            {"permission": Permissions.GET_USER_INFO},
            {"permission": Permissions.SET_USER_PERMISSIONS},
            {"permission": Permissions.GET_GROUP_INFO},
            {"permission": Permissions.CHANGE_USER_GROUPS},
            {"permission": Permissions.SUPER_SET_PASSWD},
            {"permission": Permissions.VIEW_ACCESS_RULES},
            {"permission": Permissions.SET_ACCESS_RULES},
            {"permission": Permissions.VIEW_METADATA},
            {"permission": Permissions.SET_METADATA_TAGS},
            {"permission": Permissions.LIST_USERS},
            {"permission": Permissions.LIST_GROUPS},
            {"permission": Permissions.CREATE_GROUP},
            {"permission": Permissions.DELETE_GROUP},
            {"permission": Permissions.RENAME_GROUP},
            {"permission": Permissions.SET_GROUP_PERMISSIONS},
            {"permission": Permissions.BYPASS_LOCKDOWN},
            {"permission": Permissions.BYPASS_DOCUMENT_CREATION_RATE_LIMIT},
            {"permission": Permissions.BYPASS_DOCUMENT_DOWNLOAD_RATE_LIMIT},
            {"permission": Permissions.BYPASS_REQUEST_RATE_LIMIT},
            {"permission": Permissions.APPLY_LOCKDOWN},
            {"permission": Permissions.VIEW_AUDIT_LOGS},
            {"permission": Permissions.MANAGE_ACCESS},
            {"permission": Permissions.VIEW_ACCESS_ENTRIES},
            {"permission": Permissions.BLOCK},
            {"permission": Permissions.UNBLOCK},
            {"permission": Permissions.SUPER_SET_USER_AVATAR},
            {"permission": Permissions.DEBUGGING},
            {"permission": Permissions.MANAGE_2FA},
            {"permission": Permissions.LIST_REVISIONS},
            {"permission": Permissions.VIEW_REVISION},
            {"permission": Permissions.SET_CURRENT_REVISION},
            {"permission": Permissions.DELETE_REVISION},
            {"permission": Permissions.MANAGE_KEYRINGS},
            {"permission": Permissions.LIST_USER_BLOCKS},
            {"permission": Permissions.LIST_BANNED_SUBNETS},
            {"permission": Permissions.MANAGE_BANNED_SUBNETS},
            {"permission": Permissions.LIST_AUTH_LOCKOUTS},
            {"permission": Permissions.UNLOCK_AUTH_LOCKOUTS},
            {"permission": Permissions.PURGE},
            {"permission": Permissions.RESTORE},
            {"permission": Permissions.LIST_DELETED_ITEMS},
            {"permission": Permissions.SUPER_RENAME_USER},
            {"permission": Permissions.SET_USER_AVATAR},
        ],
    )

    # Initialize providers, since we need to use the storage provider later.
    initialize_providers()

    # Read from sample document source and write back to storage.
    # This is necessary because the storage provider cannot be determined in advance.
    sample_source_path = EXECUTABLE_ABSPATH / "content" / "hello"

    today = datetime.datetime.now(datetime.UTC).date()
    real_filename = secrets.token_hex(32)
    sample_target_path = f"content/files/{today.year}/{today.month}/{real_filename}"

    # Ensure the directory structure exists before writing the file
    ProviderManager().storage.makedirs(
        os.path.dirname(sample_target_path), exist_ok=True
    )

    with (
        open(sample_source_path, "rb") as source,
        ProviderManager().storage.fopen(sample_target_path, "wb") as f,
    ):
        f.write(source.read())

    with Session() as session:
        # not using `ROOT_ABSPATH` here to allow easy migration
        init_file = File(
            id="init",
            path=sample_target_path,
            size=os.path.getsize(sample_source_path),
            active=True,
        )
        session.add(init_file)

        init_document = Document(
            id="hello", title="Hello World", folder_id=ROOT_DIRECTORY_ID
        )
        init_document.metadata_record = DocumentMetadata()
        init_document_revision = DocumentRevision(file_id=init_file.id)
        init_document.revisions.append(init_document_revision)
        init_document.current_revision = init_document_revision
        session.add(init_document)
        session.add(init_document_revision)
        session.commit()

    import secrets
    import string

    from include.domains.identity.commands.users import create_user

    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{};:,.<>?/"
    password = "".join(secrets.choice(alphabet) for _ in range(16))

    create_user(
        username="admin",
        password=password,
        nickname="管理员",
        permissions=[],
        groups=[
            {
                "group_name": "sysop",
                "start_time": 0,
                "end_time": None,
            },
            {
                "group_name": "user",
                "start_time": 0,
                "end_time": None,
            },
        ],
    )

    # Write the generated password to admin_password.txt in the project root.
    with open(
        EXECUTABLE_ABSPATH / "admin_password.txt", "w", encoding="utf-8"
    ) as pwd_file:
        pwd_file.write(f"{password}\n")

    # Logs, certificates, and private keys are all stored on the server's file system;
    # therefore, the `os` library is used for read/write operations instead of
    # `StorageProvider`.
    os.makedirs(EXECUTABLE_ABSPATH / "content", exist_ok=True)

    import datetime

    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    cert_path = global_config["server"]["ssl_certfile"]
    key_path = global_config["server"]["ssl_keyfile"]

    # Generate a self-signed certificate and private key with cryptography.
    if not (os.path.exists(cert_path) and os.path.exists(key_path)):
        # Generate the ECC private key.
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())

        # Generate the self-signed certificate.
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(
                    NameOID.COMMON_NAME, global_config["server"]["host"]
                ),
            ]
        )
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.UTC))
            .not_valid_after(
                datetime.datetime.now(datetime.UTC)
                + datetime.timedelta(days=DEFAULT_SSL_CERT_VALIDITY_DAYS)
            )
            .add_extension(
                x509.SubjectAlternativeName(
                    [x509.DNSName(global_config["server"]["host"])]
                ),
                critical=False,
            )
            .sign(private_key, hashes.SHA256(), default_backend())
        )

        # Write the private key.
        with open(key_path, "wb") as f:
            f.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )

        # Write the certificate.
        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

    with open(EXECUTABLE_ABSPATH / "init", "w") as f:
        f.write("This file indicates that the database has been initialized.\n")


def prepare_handlers():
    """
    Prepare the available request handlers by loading built-in handlers and
    extension handlers.

    This function populates the `available_functions` dictionary with handlers
    for processing client requests.

    It also populates the `whitelisted_functions` list with actions that are
    allowed even during lockdown.
    """
    if global_config["debug"]:  # Debugging
        available_functions["throw_exception"] = RequestThrowExceptionHandler

    # Load available request handlers from extensions
    extension_handlers = pm.hook.ext_register_handlers()

    # If multiple extensions attempt to register the same action, the behavior is
    # undefined.
    for handler_dict in extension_handlers:
        available_functions.update(handler_dict)

    ext_unregistered_handlers = pm.hook.ext_unregister_handlers()
    for i in ext_unregistered_handlers:
        for handler_name in i:
            if handler_name in available_functions:
                del available_functions[handler_name]

    validate_request_handler_models(available_functions)

    for ext_whitelisted_actions in pm.hook.ext_register_whitelisted_actions():
        whitelisted_functions.extend(ext_whitelisted_actions)

    for action in validate_handler_rate_limit_costs(available_functions):
        logger.warning(
            f"Configured request rate-limit cost references unknown action {action!r}"
        )


def prepare_logger():
    """
    Prepare the logger using Loguru with both console and file handlers.

    The console handler outputs colored logs at INFO level, while the file
    handler writes detailed logs at DEBUG level with automatic rotation and
    compression.

    The log file is located at "./content/logs/server.log".
    """

    log_file = EXECUTABLE_ABSPATH / "content" / "logs" / "server.log"
    fmt = "[<green>{time:YYYY-MM-DD HH:mm:ss,SSS}</green> <level>{level: <8}</level>] <level>{message}</level>"

    # reset default logger to avoid conflicts with loguru's configuration
    logger.remove()

    logger.configure(extra={"name": "main"})
    logger.add(
        sys.stderr,
        level="INFO",
        format=fmt,
    )
    logger.add(
        log_file,
        level="DEBUG",
        format="{time:YYYY-MM-DD HH:mm:ss,SSS} {level: <8} | {extra[name]}:{function}:{line} - {message}",
        rotation="10 MB",
        retention="1 week",
        compression="zip",
        enqueue=True,
    )


def _run_server():
    prepare_logger()

    if not os.path.exists(EXECUTABLE_ABSPATH / "init"):
        logger.info("Database not initialized, initializing now...")
        server_init()

    logger.info("Initializating CFMS WebSocket server...")
    logger.info(f"CFMS Core Version: {CORE_VERSION}")

    # TODO: Add support for TLS ECH when upstream libraries support it.
    security_cfg = global_config.get("security", {})
    require_client_cert = security_cfg.get("require_client_cert", False)
    ssl_context = create_server_ssl_context(
        global_config["server"]["ssl_certfile"],
        global_config["server"]["ssl_keyfile"],
        require_client_cert=require_client_cert,
        client_ca_path=(
            security_cfg["client_cert_ca_path"] if require_client_cert else None
        ),
    )
    if require_client_cert:
        logger.info(
            f"Mutual TLS enabled: client certificates will be verified "
            f"against CA path '{security_cfg['client_cert_ca_path']}'."
        )

    for warning in get_config_warnings(global_config):
        logger.warning(warning)

    if ssl.OPENSSL_VERSION_INFO < (3, 5):
        logger.warning(
            "The version of OpenSSL bundled with Python is too low "
            f"({ssl.OPENSSL_VERSION}) and therefore **does not support"
            " post-quantum encryption**. Communication without post-quantum "
            'encryption may be vulnerable to "harvest now, decrypt later" '
            "attacks. Consider using a Python distribution that bundles "
            "OpenSSL 3.5 or later to resolve this issue."
        )

    # Ensure the root folder record exists (handles upgrades from older versions)
    ensure_root_folder()

    initialize_providers()

    # Register global broadcast handler
    ProviderManager().event_bus.subscribe(
        GLOBAL_BROADCAST_EVENT_CHANNEL, on_global_broadcast
    )
    ProviderManager().event_bus.subscribe(
        LOGIN_GUARD_EVENT_CHANNEL, LoginGuard.handle_event
    )
    ProviderManager().event_bus.subscribe(FILE_TASK_EVENT_CHANNEL, on_file_task_event)

    # Register extensions after database initialization
    load_extensions_from_directory(
        EXTENSION_ROOT,
        get_enabled_extensions(global_config),
        config=global_config,
    )

    # Initialize available request handlers
    prepare_handlers()

    # Preload banned subnet list into memory for LoginGuard
    LoginGuard.reload_networks()

    host = global_config["server"]["host"]
    port = global_config["server"]["port"]
    socket_family, dualstack_ipv6 = get_bind_options(
        host, global_config["server"]["dualstack_ipv6"]
    )

    try_reclaim_abandoned_uploads()

    try:
        with serve(
            handle_connection,
            host,
            port,
            ssl=ssl_context,
            family=socket_family,
            dualstack_ipv6=dualstack_ipv6,
            process_request=global_process_request,
        ) as server:
            bound_address = server.socket.getsockname()
            bound_host = bound_address[0]
            display_host = (
                f"[{bound_host}]"
                if server.socket.family == socket.AF_INET6
                else bound_host
            )
            try:
                pm.hook.ext_on_startup(server=server)
                logger.info(
                    "CFMS WebSocket server started at "
                    f"wss://{display_host}:{bound_address[1]}"
                )
                server.serve_forever()
            finally:
                pm.hook.ext_on_shutdown()
    finally:
        global_config.stop()


def main():
    try:
        with server_runtime_lock(EXECUTABLE_ABSPATH):
            _run_server()
    except RuntimeLockError as exc:
        logger.error(str(exc))
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
