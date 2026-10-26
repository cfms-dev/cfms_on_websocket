from types import SimpleNamespace

import pytest

from tests.support.request_names import REQUEST_RENAMES


@pytest.mark.unit
@pytest.mark.parametrize("debug", [False, True])
def test_request_registry_matches_protocol_29(
    monkeypatch, protected_test_config, debug
):
    monkeypatch.chdir(protected_test_config.src_dir)
    import main as server_main
    from include.config.constants import PROTOCOL_VERSION
    from include.extensions.builtin import _extension as builtin
    from include.extensions.oidc_sso import _extension as oidc

    core_handlers = dict(server_main.available_functions)
    assert len(core_handlers) == 86
    monkeypatch.setattr(server_main, "available_functions", core_handlers)
    monkeypatch.setattr(
        server_main, "whitelisted_functions", list(server_main.whitelisted_functions)
    )
    monkeypatch.setattr(server_main, "global_config", {"debug": debug})
    monkeypatch.setattr(
        server_main,
        "pm",
        SimpleNamespace(
            hook=SimpleNamespace(
                ext_register_auth_methods=list,
                ext_register_handlers=lambda: [
                    builtin.ext_register_handlers(),
                    oidc.ext_register_handlers(),
                ],
                ext_unregister_handlers=list,
                ext_register_whitelisted_actions=lambda: [
                    oidc.ext_register_whitelisted_actions()
                ],
            )
        ),
    )
    server_main.prepare_handlers()

    expected = {
        new: handler
        for old, new, handler in REQUEST_RENAMES
        if debug or old != "throw_exception"
    }
    actual = {
        action: f"{handler.__module__}.{handler.__qualname__}"
        for action, handler in core_handlers.items()
    }
    assert PROTOCOL_VERSION == 29
    assert len(REQUEST_RENAMES) == len({new for _, new, _ in REQUEST_RENAMES}) == 92
    assert actual == expected
    assert set(core_handlers).isdisjoint(old for old, _, _ in REQUEST_RENAMES)
    assert set(server_main.whitelisted_functions) == {
        "core.server.info.get",
        "core.auth.login",
        "core.auth.token.exchange",
        "core.auth.token.refresh",
        "core.user.authentication.totp.setup.confirm",
        "core.file.upload",
        "core.file.download",
        "core.server.lockdown.set",
        "oidc_sso.session.start",
        "oidc_sso.session.callback",
    }


@pytest.mark.integration
@pytest.mark.asyncio
@pytest.mark.parametrize("old_action", [old for old, _, _ in REQUEST_RENAMES])
async def test_old_request_names_are_rejected_and_connection_remains_usable(
    client, old_action
):
    response = await client.send_request(old_action, {}, include_auth=False)
    assert response["code"] == 400
    assert response["data"] == {}
    following = await client.send_request(
        "core.server.info.get", {}, include_auth=False
    )
    assert following["code"] == 200
    assert following["data"]["protocol_version"] == 29
