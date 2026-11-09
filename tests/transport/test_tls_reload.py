import hashlib
import os
import ssl
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, contextmanager
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from loguru import logger
from watchdog.events import FileClosedNoWriteEvent, FileModifiedEvent, FileOpenedEvent
from websockets.exceptions import InvalidHandshake
from websockets.sync.client import connect
from websockets.sync.server import serve

from include.config.validation import ServerTLSReloadPolicy
from include.transport import tls as tls_module
from include.transport.tls import ReloadableServerTLS
from tests.support.tls import (
    client_context,
    create_ca,
    issue_certificate,
    peer_serial,
    wait_until,
)


@pytest.fixture
def certificates(tmp_path):
    ca = create_ca()
    first = issue_certificate(ca, 1)
    second = issue_certificate(ca, 2)
    certfile, keyfile = tmp_path / "cert.pem", tmp_path / "key.pem"
    certfile.write_bytes(first[0])
    keyfile.write_bytes(first[1])
    return ca, first, second, certfile, keyfile


@contextmanager
def websocket_listener(tls, *, monitor=True):
    def echo(websocket):
        for message in websocket:
            websocket.send(message)

    with ExitStack() as resources:
        resources.callback(tls.close)
        if monitor:
            resources.enter_context(tls)
        server = resources.enter_context(serve(echo, "127.0.0.1", 0, ssl=tls.context))
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        try:
            yield f"wss://127.0.0.1:{server.socket.getsockname()[1]}"
        finally:
            server.shutdown()
            thread.join(5)
            assert not thread.is_alive()


@pytest.mark.integration
@pytest.mark.parametrize("hostname", ["localhost", "127.0.0.1"])
@pytest.mark.parametrize("publication", ["overwrite", "replace", "scan"])
def test_wss_rotates_certificate_without_disconnecting_existing_client(
    certificates, hostname, publication, monkeypatch
):
    ca, _, second, certfile, keyfile = certificates
    tls = ReloadableServerTLS(
        str(certfile),
        str(keyfile),
        policy=ServerTLSReloadPolicy(
            ssl_reload_debounce_seconds=0.03,
            ssl_reload_scan_interval_seconds=0.1 if publication == "scan" else 30,
        ),
    )
    if publication == "scan":

        def unavailable():
            raise OSError("file notifications unavailable")

        monkeypatch.setattr(tls_module, "Observer", unavailable)
    with websocket_listener(tls) as uri:
        context = client_context(ca[0])
        with connect(uri, ssl=context, server_hostname=hostname) as old:
            assert peer_serial(old.socket) == 1
            if publication == "replace":
                replacement = certfile.with_suffix(".tmp")
                replacement.write_bytes(second[0])
                os.replace(replacement, certfile)
                replacement = keyfile.with_suffix(".tmp")
                replacement.write_bytes(second[1])
                os.replace(replacement, keyfile)
            else:
                certfile.write_bytes(second[0])
                keyfile.write_bytes(second[1])

            def new_certificate():
                with connect(uri, ssl=context, server_hostname=hostname) as new:
                    assert new.socket.version() == "TLSv1.3"
                    new.send("new connection")
                    assert new.recv() == "new connection"
                    return peer_serial(new.socket) == 2

            wait_until(new_certificate)
            old.send("existing connection")
            assert old.recv() == "existing connection"
            assert peer_serial(old.socket) == 1
    tls.close()
    assert not tls._worker.is_alive()
    if tls._observer is not None:
        assert not tls._observer.is_alive()


@pytest.mark.integration
@pytest.mark.parametrize(
    "invalid",
    ["pem", "mismatch", "missing", "permission", "expired", "future", "encrypted"],
)
def test_invalid_publication_preserves_certificate_and_recovers(
    certificates, invalid, monkeypatch
):
    ca, _, second, certfile, keyfile = certificates
    tls = ReloadableServerTLS(
        str(certfile), str(keyfile), policy=ServerTLSReloadPolicy()
    )
    with websocket_listener(tls, monitor=False) as uri:
        if invalid == "pem":
            certfile.write_bytes(b"incomplete PEM")
        elif invalid == "mismatch":
            certfile.write_bytes(second[0])
        elif invalid == "missing":
            keyfile.unlink()
        elif invalid == "encrypted":
            key = serialization.load_pem_private_key(second[1], password=None)
            certfile.write_bytes(second[0])
            keyfile.write_bytes(
                key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.BestAvailableEncryption(b"test-password"),
                )
            )
        elif invalid == "permission":
            original_read = Path.read_bytes

            def denied(path):
                if path == keyfile:
                    raise PermissionError("test read denial")
                return original_read(path)

            monkeypatch.setattr(Path, "read_bytes", denied)
        else:
            expired = issue_certificate(ca, 3, validity=invalid)
            certfile.write_bytes(expired[0])
            keyfile.write_bytes(expired[1])
        tls._reload()
        context = client_context(ca[0])
        with connect(uri, ssl=context) as client:
            assert peer_serial(client.socket) == 1
        monkeypatch.undo()
        certfile.write_bytes(second[0])
        keyfile.write_bytes(second[1])
        tls._reload()
        with connect(uri, ssl=context) as client:
            assert peer_serial(client.socket) == 2


@pytest.mark.integration
def test_symbolic_link_targets_are_refreshed(certificates, tmp_path):
    ca, _, second, certfile, keyfile = certificates
    live = tmp_path / "live"
    live.mkdir()
    certlink, keylink = live / "cert.pem", live / "key.pem"
    try:
        certlink.symlink_to(certfile)
        keylink.symlink_to(keyfile)
    except OSError:
        pytest.skip("This Windows account cannot create symbolic links")
    tls = ReloadableServerTLS(
        str(certlink),
        str(keylink),
        policy=ServerTLSReloadPolicy(ssl_reload_debounce_seconds=0.03),
    )
    with websocket_listener(tls) as uri:
        archive = tmp_path / "new-archive"
        archive.mkdir()
        next_cert, next_key = archive / "cert.pem", archive / "key.pem"
        next_cert.write_bytes(second[0])
        next_key.write_bytes(second[1])
        for link, destination in ((certlink, next_cert), (keylink, next_key)):
            temporary = link.with_suffix(".tmp")
            temporary.symlink_to(destination)
            os.replace(temporary, link)

        def rotated():
            with connect(uri, ssl=client_context(ca[0])) as client:
                return peer_serial(client.socket) == 2

        wait_until(rotated)
        third = issue_certificate(ca, 3)
        next_cert.write_bytes(third[0])
        next_key.write_bytes(third[1])

        def target_changed():
            with connect(uri, ssl=client_context(ca[0])) as client:
                return peer_serial(client.socket) == 3

        wait_until(target_changed)


@pytest.mark.unit
def test_disabled_reload_keeps_static_certificate(certificates):
    ca, _, second, certfile, keyfile = certificates
    tls = ReloadableServerTLS(
        str(certfile),
        str(keyfile),
        policy=ServerTLSReloadPolicy(ssl_reload_enabled=False),
    )
    with websocket_listener(tls) as uri:
        certfile.write_bytes(second[0])
        keyfile.write_bytes(second[1])
        with connect(uri, ssl=client_context(ca[0])) as client:
            assert peer_serial(client.socket) == 1
        assert tls._worker is None
        assert tls.context.sni_callback is None


@pytest.mark.unit
def test_read_events_do_not_schedule_reloads(certificates):
    _, _, _, certfile, keyfile = certificates
    tls = ReloadableServerTLS(
        str(certfile), str(keyfile), policy=ServerTLSReloadPolicy()
    )
    tls._refresh_watches()
    tls._handler.dispatch(FileOpenedEvent(str(certfile)))
    tls._handler.dispatch(FileClosedNoWriteEvent(str(keyfile)))
    assert tls._changed_at is None
    tls._handler.dispatch(FileModifiedEvent(str(certfile)))
    assert tls._changed_at is not None
    tls.close()


@pytest.mark.unit
def test_files_changed_during_loading_are_not_published(certificates, monkeypatch):
    _, _, second, certfile, keyfile = certificates
    tls = ReloadableServerTLS(
        str(certfile), str(keyfile), policy=ServerTLSReloadPolicy()
    )
    certfile.write_bytes(second[0])
    keyfile.write_bytes(second[1])
    original_create = tls_module.create_server_ssl_context

    def replace_after_load(*args, **kwargs):
        context = original_create(*args, **kwargs)
        certfile.write_bytes(b"publication still in progress")
        return context

    monkeypatch.setattr(tls_module, "create_server_ssl_context", replace_after_load)
    tls._reload()
    assert tls._fingerprint[0] != hashlib.sha256(second[0]).digest()
    assert tls._changed_at is not None
    tls.close()


@pytest.mark.unit
def test_shutdown_during_candidate_load_prevents_publication(certificates, monkeypatch):
    _, first, second, certfile, keyfile = certificates
    tls = ReloadableServerTLS(
        str(certfile), str(keyfile), policy=ServerTLSReloadPolicy()
    )
    certfile.write_bytes(second[0])
    keyfile.write_bytes(second[1])
    loaded = threading.Event()
    release = threading.Event()
    original_load = tls._load_candidate

    def paused_load():
        candidate = original_load()
        loaded.set()
        assert release.wait(5)
        return candidate

    monkeypatch.setattr(tls, "_load_candidate", paused_load)
    with ThreadPoolExecutor(max_workers=1) as executor:
        pending = executor.submit(tls._reload)
        try:
            assert loaded.wait(5)
            tls.close()
        finally:
            release.set()
        pending.result(5)
    assert tls._fingerprint[0] == hashlib.sha256(first[0]).digest()


@pytest.mark.integration
def test_mtls_is_enforced_after_rotation(certificates, tmp_path, monkeypatch):
    ca, _, second, certfile, keyfile = certificates
    ca_file = tmp_path / "ca.pem"
    ca_file.write_bytes(ca[0].public_bytes(serialization.Encoding.PEM))
    client_files = tmp_path / "client.pem", tmp_path / "client.key"
    client_material = issue_certificate(ca, 10, client=True)
    for path, data in zip(client_files, client_material, strict=True):
        path.write_bytes(data)
    original_create = tls_module.create_server_ssl_context

    def create_with_test_ca(*args, **kwargs):
        context = original_create(*args, **kwargs)
        # Configure a file-backed test CA before use, without requiring openssl rehash.
        context.load_verify_locations(cafile=ca_file)
        return context

    monkeypatch.setattr(tls_module, "create_server_ssl_context", create_with_test_ca)
    tls = ReloadableServerTLS(
        str(certfile),
        str(keyfile),
        policy=ServerTLSReloadPolicy(),
        require_client_cert=True,
        client_ca_path=str(tmp_path),
    )
    with websocket_listener(tls, monitor=False) as uri:
        trusted = client_context(ca[0])
        trusted.load_cert_chain(*client_files)
        with connect(uri, ssl=trusted) as old:
            assert peer_serial(old.socket) == 1
            certfile.write_bytes(second[0])
            keyfile.write_bytes(second[1])
            tls._reload()
            with connect(uri, ssl=trusted) as new:
                assert peer_serial(new.socket) == 2
                new.send("authenticated")
                assert new.recv() == "authenticated"
            with pytest.raises((ssl.SSLError, OSError, InvalidHandshake)):
                connect(uri, ssl=client_context(ca[0]))
            untrusted = issue_certificate(create_ca(), 11, client=True)
            for path, data in zip(client_files, untrusted, strict=True):
                path.write_bytes(data)
            stranger = client_context(ca[0])
            stranger.load_cert_chain(*client_files)
            with pytest.raises((ssl.SSLError, OSError, InvalidHandshake)):
                connect(uri, ssl=stranger)
            old.send("still authenticated")
            assert old.recv() == "still authenticated"


@pytest.mark.integration
def test_concurrent_handshakes_during_rotation(certificates):
    ca, _, second, certfile, keyfile = certificates
    tls = ReloadableServerTLS(
        str(certfile), str(keyfile), policy=ServerTLSReloadPolicy()
    )
    with websocket_listener(tls, monitor=False) as uri:
        context = client_context(ca[0])
        barrier = threading.Barrier(5)

        def connect_during_rotation():
            barrier.wait(timeout=5)
            serials = []
            for _ in range(4):
                with connect(uri, ssl=context) as client:
                    serials.append(peer_serial(client.socket))
                    client.send("concurrent")
                    assert client.recv() == "concurrent"
            return serials

        with ThreadPoolExecutor(max_workers=4) as executor:
            pending = [executor.submit(connect_during_rotation) for _ in range(4)]
            certfile.write_bytes(second[0])
            keyfile.write_bytes(second[1])
            barrier.wait(timeout=5)
            tls._reload()
            for result in pending:
                assert set(result.result(5)) <= {1, 2}
        with connect(uri, ssl=context) as client:
            assert peer_serial(client.socket) == 2


@pytest.mark.unit
def test_hello_retry_request_keeps_handshake_certificate(certificates):
    ca, _, second, certfile, keyfile = certificates
    tls = ReloadableServerTLS(
        str(certfile), str(keyfile), policy=ServerTLSReloadPolicy()
    )
    context = client_context(ca[0])
    context.set_groups("P-256/X25519")
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    client_in, client_out = ssl.MemoryBIO(), ssl.MemoryBIO()
    server = tls.context.wrap_bio(incoming, outgoing, server_side=True)
    client = context.wrap_bio(client_in, client_out, server_hostname="localhost")
    with pytest.raises(ssl.SSLWantReadError):
        client.do_handshake()
    incoming.write(client_out.read())
    with pytest.raises(ssl.SSLWantReadError):
        server.do_handshake()
    retry = outgoing.read()
    # RFC 8446 defines this fixed ServerHello.random for HelloRetryRequest.
    assert (
        bytes.fromhex(
            "CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C"
        )
        in retry
    )
    selected = server.context
    assert selected is not tls.context
    assert selected.sni_callback is None
    certfile.write_bytes(second[0])
    keyfile.write_bytes(second[1])
    tls._reload()
    client_in.write(retry)
    completed = set()
    for _ in range(20):
        for label, endpoint in (("client", client), ("server", server)):
            if label not in completed:
                try:
                    endpoint.do_handshake()
                except ssl.SSLWantReadError:
                    pass
                else:
                    completed.add(label)
        if client_out.pending:
            incoming.write(client_out.read())
        if outgoing.pending:
            client_in.write(outgoing.read())
        if len(completed) == 2:
            break
    assert completed == {"client", "server"}
    assert peer_serial(client) == 1
    assert server.context is selected
    tls.close()


@pytest.mark.unit
def test_worker_start_failure_closes_file_observer(certificates, monkeypatch):
    _, _, _, certfile, keyfile = certificates
    tls = ReloadableServerTLS(
        str(certfile), str(keyfile), policy=ServerTLSReloadPolicy()
    )
    original_start = threading.Thread.start

    def fail_worker(thread):
        if thread.name.startswith("cfms-tls-reload-"):
            raise RuntimeError("worker startup failure")
        original_start(thread)

    monkeypatch.setattr(threading.Thread, "start", fail_worker)
    with pytest.raises(RuntimeError), tls:
        pytest.fail("worker startup must fail")
    assert tls._stopped
    assert not tls._observer.is_alive()
    assert not tls._worker.is_alive()
    tls.close()


@pytest.mark.unit
def test_persistent_failure_is_logged_once_and_success_clears_it(certificates):
    _, _, second, certfile, keyfile = certificates
    tls = ReloadableServerTLS(
        str(certfile), str(keyfile), policy=ServerTLSReloadPolicy()
    )
    records = []
    sink = logger.add(lambda message: records.append(message.record))
    try:
        certfile.write_bytes(b"bad certificate")
        tls._reload()
        tls._reload()
        assert [r["extra"].get("event") for r in records] == ["tls_reload_failed"]
        certfile.write_bytes(second[0])
        keyfile.write_bytes(second[1])
        tls._reload()
        assert records[-1]["extra"]["event"] == "tls_reload_succeeded"
        assert records[-1]["extra"]["serial_number"] == 2
        assert tls._last_error is None
    finally:
        logger.remove(sink)
        tls.close()


@pytest.mark.integration
def test_worker_recovers_after_partial_publication_and_merges_events(
    certificates, monkeypatch
):
    ca, _, second, certfile, keyfile = certificates
    tls = ReloadableServerTLS(
        str(certfile),
        str(keyfile),
        policy=ServerTLSReloadPolicy(ssl_reload_debounce_seconds=0.03),
    )
    initial_scan = threading.Event()
    original_reload = tls._reload

    def observed_reload():
        original_reload()
        initial_scan.set()

    monkeypatch.setattr(tls, "_reload", observed_reload)
    records = []
    sink = logger.add(lambda message: records.append(message.record))
    try:
        with websocket_listener(tls) as uri:
            assert initial_scan.wait(5)
            certfile.write_bytes(second[0])
            wait_until(lambda: tls._last_error is not None)
            with connect(uri, ssl=client_context(ca[0])) as client:
                assert peer_serial(client.socket) == 1
            keyfile.write_bytes(second[1])
            for _ in range(50):
                tls._handler.dispatch(FileModifiedEvent(str(keyfile)))

            def recovered():
                with connect(uri, ssl=client_context(ca[0])) as client:
                    return peer_serial(client.socket) == 2

            wait_until(recovered)
        successes = [
            record
            for record in records
            if record["extra"].get("event") == "tls_reload_succeeded"
        ]
        assert len(successes) == 1
    finally:
        logger.remove(sink)


@pytest.mark.unit
@pytest.mark.parametrize("invalid", ["pem", "expired", "future"])
def test_invalid_initial_certificate_does_not_start_monitoring(certificates, invalid):
    ca, _, _, certfile, keyfile = certificates
    if invalid == "pem":
        certfile.write_bytes(b"invalid PEM")
    else:
        material = issue_certificate(ca, 3, validity=invalid)
        certfile.write_bytes(material[0])
        keyfile.write_bytes(material[1])
    threads = {thread.ident for thread in threading.enumerate()}
    with pytest.raises(ValueError):  # noqa: PT011 - certificate parser messages aren't a contract.
        ReloadableServerTLS(str(certfile), str(keyfile), policy=ServerTLSReloadPolicy())
    assert {thread.ident for thread in threading.enumerate()} == threads
