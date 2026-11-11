import datetime as dt
import hashlib
import os
import ssl
import threading
import time
from pathlib import Path
from types import TracebackType
from typing import Self

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from loguru import logger as log
from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer
from watchdog.observers.api import BaseObserver, ObservedWatch

from include.config.validation import ServerTLSReloadPolicy


def create_server_ssl_context(
    certfile: str,
    keyfile: str,
    *,
    require_client_cert: bool = False,
    client_ca_path: str | None = None,
) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=certfile, keyfile=keyfile, password=b"")
    context.minimum_version = ssl.TLSVersion.TLSv1_3

    # TODO: Consider mandating the use of X25519MLKEM768 when practical,
    # rather than retaining X25519 as a fallback.
    context.set_groups("X25519MLKEM768/X25519")

    if require_client_cert:
        if client_ca_path is None:
            raise ValueError(
                "A client certificate CA path is required when mTLS is enabled"
            )
        context.verify_mode = ssl.CERT_REQUIRED
        context.verify_flags |= ssl.VERIFY_X509_STRICT
        context.load_verify_locations(capath=client_ca_path)

    return context


class _CertificateEvents(FileSystemEventHandler):
    def __init__(self, tls: ReloadableServerTLS):
        self._tls = tls

    def on_any_event(self, event: FileSystemEvent) -> None:
        if event.event_type not in {"created", "modified", "deleted", "moved"}:
            return
        paths = {
            Path(os.path.abspath(os.fsdecode(path)))
            for path in (event.src_path, event.dest_path)
            if path
        }
        with self._tls._condition:
            targets = (
                self._tls._directories if event.is_directory else self._tls._targets
            )
            if paths & targets and not self._tls._stopped:
                self._tls._changed_at = time.monotonic()
                self._tls._condition.notify()


class ReloadableServerTLS:
    def __init__(
        self,
        certfile: str,
        keyfile: str,
        *,
        policy: ServerTLSReloadPolicy,
        require_client_cert: bool = False,
        client_ca_path: str | None = None,
        name: str = "wss",
    ):
        self._certfile = Path(os.path.abspath(certfile))
        self._keyfile = Path(os.path.abspath(keyfile))

        self._policy = policy
        self._require_client_cert = require_client_cert
        self._client_ca_path = client_ca_path

        self._name = name
        self._logger = log.bind(name="tls", listener=name)

        self._condition = threading.Condition()
        self._stopped = False
        self._started = False
        self._changed_at: float | None = None

        self._observer: BaseObserver | None = None
        self._worker: threading.Thread | None = None

        self._watches: dict[Path, ObservedWatch] = {}
        self._targets: set[Path] = set()
        self._directories: set[Path] = set()

        self._watch_errors: dict[Path, str] = {}
        self._last_error: tuple[type[Exception], str] | None = None

        self._handler = _CertificateEvents(self)

        self._active, self._fingerprint, _ = self._load_candidate()
        self.context = self._active

        if policy.ssl_reload_enabled:
            self.context, _, _ = self._load_candidate()
            self.context.sni_callback = self._select_context

    def _select_context(
        self,
        connection: ssl.SSLSocket | ssl.SSLObject,
        server_name: str | None,
        initial_context: ssl.SSLContext,
    ) -> None:
        with self._condition:
            connection.context = self._active

    def _read_fingerprint(self) -> tuple[bytes, bytes]:
        return (
            hashlib.sha256(self._certfile.read_bytes()).digest(),
            hashlib.sha256(self._keyfile.read_bytes()).digest(),
        )

    def _load_candidate(
        self,
    ) -> tuple[ssl.SSLContext, tuple[bytes, bytes], x509.Certificate]:
        before = self._read_fingerprint()
        certificate = x509.load_pem_x509_certificate(self._certfile.read_bytes())

        now = dt.datetime.now(dt.UTC)

        if (
            not certificate.not_valid_before_utc
            <= now
            < certificate.not_valid_after_utc
        ):
            raise ValueError("The server certificate is outside its validity period")

        context = create_server_ssl_context(
            str(self._certfile),
            str(self._keyfile),
            require_client_cert=self._require_client_cert,
            client_ca_path=self._client_ca_path,
        )

        if before != self._read_fingerprint():
            with self._condition:
                self._changed_at = time.monotonic()
                self._condition.notify()
            raise ValueError("Certificate files changed while loading")

        return context, before, certificate

    def _refresh_watches(self) -> None:
        # Retain both the original path and the resolved path to account for cases
        # such as symbolic links.
        targets = {self._certfile, self._keyfile}
        for path in (self._certfile, self._keyfile):
            try:
                targets.add(path.resolve())
            except OSError, RuntimeError:
                # The next scan retries broken or temporarily cyclic links.
                pass

        # Get parent directories of actual target files.
        directories = {path.parent for path in targets}

        with self._condition:
            self._targets = targets
            self._directories = directories

        observer = self._observer
        if observer is None:
            return

        # Remove watches for directories that are no longer relevant, and add watches
        # for new directories.
        for directory in self._watches.keys() - directories:
            observer.unschedule(self._watches.pop(directory))
            self._watch_errors.pop(directory, None)
        for directory in directories - self._watches.keys():
            try:
                self._watches[directory] = observer.schedule(
                    self._handler, str(directory), recursive=False
                )
            except OSError as exc:
                if self._watch_errors.get(directory) != str(exc):
                    self._logger.warning(
                        f"Cannot watch TLS directory {directory}; periodic scanning "
                        f"remains active: {exc}"
                    )
                self._watch_errors[directory] = str(exc)
            else:
                self._watch_errors.pop(directory, None)

    def _reload(self) -> None:
        try:
            if self._read_fingerprint() == self._fingerprint:
                self._last_error = None
                return  # No changes detected; skip reloading.

            # Otherwise, attempt to load the new certificate and key files.
            context, fingerprint, certificate = self._load_candidate()
        except (OSError, ValueError) as exc:
            error = (type(exc), str(exc))

            # Deduplicate repeated errors to avoid log spam
            if error != self._last_error:
                self._logger.bind(
                    event="tls_reload_failed", error_type=type(exc).__name__
                ).warning(
                    "TLS certificate reload rejected; keeping previous certificate: {}",
                    exc,
                )

            self._last_error = error
            return

        with self._condition:
            if self._stopped:
                return
            self._active = context
            self._fingerprint = fingerprint

        self._last_error = None
        self._logger.bind(
            event="tls_reload_succeeded",
            serial_number=certificate.serial_number,
            certificate_sha256=certificate.fingerprint(hashes.SHA256()).hex(),
            expires_at=certificate.not_valid_after_utc.isoformat(),
        ).info(
            "TLS certificate reloaded (serial={}, expires={})",
            certificate.serial_number,
            certificate.not_valid_after_utc,
        )

    def _run(self) -> None:
        scan_at = time.monotonic()
        while True:
            with self._condition:
                while not self._stopped:
                    deadline = scan_at
                    if self._changed_at is not None:
                        deadline = min(
                            deadline,
                            self._changed_at + self._policy.ssl_reload_debounce_seconds,
                        )
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        self._changed_at = None
                        break
                    self._condition.wait(remaining)
                if self._stopped:
                    return

            self._refresh_watches()
            self._reload()
            scan_at = time.monotonic() + self._policy.ssl_reload_scan_interval_seconds

    def __enter__(self) -> Self:
        if self._started or self._stopped:
            raise RuntimeError("TLS certificate monitoring cannot be started twice")
        self._started = True

        if not self._policy.ssl_reload_enabled:
            return self

        try:
            try:
                self._observer = Observer()
                self._refresh_watches()  # initialize watches
                self._observer.start()
            except (OSError, RuntimeError) as exc:
                if self._observer is not None:
                    self._observer.stop()
                    if self._observer.ident is not None:
                        self._observer.join()
                self._observer = None
                self._watches.clear()
                self._logger.warning(
                    f"TLS file monitoring unavailable; using periodic scans: {exc}"
                )
            self._worker = threading.Thread(
                target=self._run,
                name=f"cfms-tls-reload-{self._name}",
                daemon=False,
            )
            self._worker.start()
        except BaseException:
            self.close()
            raise

        return self

    def close(self) -> None:
        with self._condition:
            self._stopped = True
            self._condition.notify_all()

        # wait for the worker and observer threads to finish, if they exist
        if self._worker is not None and self._worker.ident is not None:
            self._worker.join()

        if self._observer is not None:
            self._observer.stop()
            if self._observer.ident is not None:
                self._observer.join()

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()
