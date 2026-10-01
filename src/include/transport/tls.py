import ssl


def create_server_ssl_context(
    certfile: str,
    keyfile: str,
    *,
    require_client_cert: bool = False,
    client_ca_path: str | None = None,
) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=certfile, keyfile=keyfile)
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
