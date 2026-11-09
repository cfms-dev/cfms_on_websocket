# TLS certificate reload

WSS and the optional HTTP API automatically apply certificate and private-key
file changes without restarting the process or rebinding their listening ports.
New full TLS handshakes use the latest successfully loaded pair. Established
WebSocket connections and HTTPS keep-alive connections continue using their
original TLS sessions. TLS session resumption need not send a certificate again;
reload does not force existing sessions to authenticate again.

## Configuration

The following settings in `[server]` apply to both listeners:

```toml
ssl_reload_enabled = true
ssl_reload_debounce_seconds = 0.5
ssl_reload_scan_interval_seconds = 30.0
```

Defaults also apply when these keys are absent. The switch must be a boolean and
both intervals must be finite positive numbers. Settings, certificate paths and
mTLS configuration are captured when each listener starts; changing them requires
a restart. Setting `ssl_reload_enabled = false` keeps startup-only loading.

The HTTP API inherits `server.ssl_certfile` and `server.ssl_keyfile` unless its
existing `extensions.http_api.ssl_certfile` and `ssl_keyfile` settings specify a
separate pair. Each listener reloads independently, so a short difference between
their active certificate versions is possible.

## Publishing and renewing certificates

1. Obtain a PEM certificate chain (leaf first, followed by intermediates) and its
   matching unencrypted PEM private key. Keep the existing configured paths and
   service-account read permissions. Certificate issuance remains external.
2. Prefer writing complete temporary files beside the configured files and
   replacing each destination atomically. Symbolic-link updates, including
   Certbot `live` links, and direct overwrites are supported too.
3. Publish both files. File events are merged using the debounce interval;
   successfully loaded updates normally appear about a second after publication
   finishes. A partially published or mismatched pair keeps the previous
   certificate until another event or scan succeeds.
4. Check the `TLS certificate reloaded` log and make a fresh TLS connection to
   inspect the peer certificate fingerprint. Existing connections intentionally
   retain their original session.

The loader validates PEM parsing, certificate/key matching and the leaf
certificate's UTC validity period before publication. TLS 1.3, configured key
exchange groups and client-certificate requirements remain in effect. Server-side
loading is not a substitute for client verification of the hostname and chain.

## Recovery and rollback

An invalid, missing or unreadable file logs `TLS certificate reload rejected`
and leaves the last successfully loaded context active. The same persistent
failure is logged once rather than on every scan. Fix the files or their access
permissions; no process restart is necessary. A failure to enable filesystem
notifications logs a warning and retains periodic scanning at the configured
interval. Scans also recover missed events and changed symlink targets.

To roll back, republish the previous valid certificate and its matching private
key to the same paths. A certificate that is expired or not yet valid is rejected.
Retaining an older context does not extend its certificate's validity; renew
before expiration.

Success logs include listener, serial number, public-certificate SHA-256 and UTC
expiration as structured fields. Private keys and PEM contents are never logged.
No certificate material is rewritten by the loader.

Client CA changes, mTLS policy changes and certificate-path changes are outside
the reload contract. In particular, the existing OpenSSL CA-directory lookup
behavior is retained; this feature does not provide a frozen CA-store snapshot.
Install this implementation with one normal restart; later certificate renewal
does not require downtime. No database migration or new dependency is required.
