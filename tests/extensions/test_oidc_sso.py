from include.extensions.oidc_sso import _extension as extension


def test_oidc_configuration_uses_extension_identifier_namespace(monkeypatch):
    monkeypatch.setattr(
        extension,
        "global_config",
        {
            "extensions": {
                "oidc_sso": {
                    "issuer": "https://new.example/",
                    "client_id": "new-client",
                    "redirect_uri": "https://client.example/callback",
                }
            },
            "sso": {
                "oidc": {
                    "issuer": "https://legacy.example",
                    "client_id": "legacy-client",
                    "redirect_uri": "https://legacy.example/callback",
                }
            },
        },
    )

    config = extension._get_oidc_config()

    assert config["issuer"] == "https://new.example"
    assert config["client_id"] == "new-client"
    assert config["redirect_uri"] == "https://client.example/callback"
