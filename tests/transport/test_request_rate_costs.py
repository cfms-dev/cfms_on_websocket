import ast
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

PROJECT_ROOT = Path(__file__).resolve().parents[2]

EXPECTED_CORE_ACTION_COSTS = {
    "core.auth.login": 5,
    "core.auth.token.exchange": 2,
    "core.user.authentication.get": 2,
    "core.user.authentication.policy.set": 5,
    "core.user.authentication.public_key.register": 5,
    "core.user.authentication.public_key.update": 2,
    "core.user.authentication.public_key.delete": 3,
    "core.auth.token.refresh": 2,
    "core.user.authentication.totp.setup": 20,
    "core.user.authentication.totp.setup.cancel": 1,
    "core.user.authentication.totp.setup.confirm": 2,
    "core.user.authentication.totp.delete": 5,
    "core.user.authentication.totp.status.get": 1,
    "core.security.banned_subnet.list": 2,
    "core.security.banned_subnet.create": 5,
    "core.security.banned_subnet.update": 5,
    "core.security.banned_subnet.delete": 5,
    "core.security.auth_lockout.list": 3,
    "core.security.auth_lockout.unlock": 10,
    "core.document.get": 3,
    "core.document.create": 5,
    "core.document.upload": 5,
    "core.document.delete": 5,
    "core.document.restore": 3,
    "core.document.purge": 10,
    "core.document.rename": 3,
    "core.document.move": 3,
    "core.document.info.get": 3,
    "core.document.access_rule.get": 2,
    "core.document.access_rule.set": 5,
    "core.document.tag.set": 3,
    "core.document.revision.list": 2,
    "core.document.revision.get": 3,
    "core.document.revision.current.set": 3,
    "core.document.revision.delete": 5,
    "core.file.download": 5,
    "core.file.upload": 5,
    "core.directory.list": 3,
    "core.directory.info.get": 3,
    "core.directory.access_rule.get": 2,
    "core.directory.access_rule.set": 5,
    "core.directory.create": 3,
    "core.directory.delete": 10,
    "core.directory.restore": 10,
    "core.directory.purge": 20,
    "core.directory.rename": 3,
    "core.directory.move": 3,
    "core.directory.deleted_item.list": 3,
    "core.search.query": 3,
    "core.user.status.set": 3,
    "core.user.block.create": 3,
    "core.user.block.update": 3,
    "core.user.block.delete": 2,
    "core.user.block.list": 3,
    "core.user.list": 3,
    "core.user.create": 5,
    "core.user.delete": 5,
    "core.user.rename": 5,
    "core.user.info.get": 2,
    "core.user.avatar.get": 3,
    "core.user.avatar.set": 3,
    "core.user.group.change": 3,
    "core.user.permission.change": 3,
    "core.user.password.set": 10,
    "core.group.list": 3,
    "core.group.create": 3,
    "core.group.delete": 5,
    "core.group.rename": 5,
    "core.group.info.get": 3,
    "core.group.permission.change": 3,
    "core.access.entry.grant": 3,
    "core.access.entry.revoke": 2,
    "core.access.entry.list": 3,
    "core.server.lockdown.set": 10,
    "core.audit.entry.list": 3,
    "core.schedule.task_type.list": 1,
    "core.schedule.create": 3,
    "core.schedule.get": 1,
    "core.schedule.list": 1,
    "core.schedule.update": 3,
    "core.schedule.delete": 3,
    "core.user.key.upload": 2,
    "core.user.key.get": 1,
    "core.user.key.delete": 2,
    "core.user.preferred_dek.set": 2,
    "core.user.key.list": 2,
}

EXPECTED_EXTRA_HANDLER_COSTS = {
    "RequestDiagnosticsHandler": 3,
    "RequestServerInfoHandler": 1,
    "RequestShutdownHandler": 1,
    "RequestOIDCStartHandler": 3,
    "RequestOIDCCallbackHandler": 10,
    "RequestThrowExceptionHandler": 3,
}


def _declared_handler_costs(path: Path) -> dict[str, int]:
    module = ast.parse(path.read_text(encoding="utf-8"))
    costs = {}
    for node in module.body:
        if not isinstance(node, ast.ClassDef) or not any(
            isinstance(base, ast.Subscript)
            and isinstance(base.value, ast.Name)
            and base.value.id == "RequestHandler"
            for base in node.bases
        ):
            continue
        assignments = [
            statement.value.value
            for statement in node.body
            if isinstance(statement, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id == "rate_limit_cost"
                for target in statement.targets
            )
            and isinstance(statement.value, ast.Constant)
            and isinstance(statement.value.value, int)
        ]
        assert len(assignments) == 1, node.name
        costs[node.name] = assignments[0]
    return costs


def test_core_action_costs_match_business_contract(monkeypatch):
    from include.transport.request_handler import validate_request_handler_models
    from include.transport.router import available_functions

    validate_request_handler_models(available_functions)
    actual = {
        action: handler_type.rate_limit_cost
        for action, handler_type in available_functions.items()
    }

    assert actual == EXPECTED_CORE_ACTION_COSTS


def test_extra_handler_costs_match_business_contract():
    source_files = (
        PROJECT_ROOT / "src/include/extensions/builtin/_extension.py",
        PROJECT_ROOT / "src/include/extensions/oidc_sso/_extension.py",
        PROJECT_ROOT / "src/include/domains/security/handlers/debugging.py",
    )
    actual = {}
    for source_file in source_files:
        actual.update(_declared_handler_costs(source_file))

    assert actual == EXPECTED_EXTRA_HANDLER_COSTS


def test_all_known_costs_fit_default_request_buckets():
    from include.config.validation import RequestRateControlPolicy

    policy = RequestRateControlPolicy()
    capacity = min(policy.account_capacity, policy.ip_capacity)
    all_costs = (
        *EXPECTED_CORE_ACTION_COSTS.values(),
        *EXPECTED_EXTRA_HANDLER_COSTS.values(),
    )

    assert len(all_costs) == 92
    assert set(all_costs) == {1, 2, 3, 5, 10, 20}
    assert all(0 < cost <= capacity for cost in all_costs)


@pytest.mark.parametrize("declared_cost", [True, 0, -1, 1.5, 121])
def test_handler_cost_validation_rejects_invalid_declared_cost_even_when_overridden(
    monkeypatch, declared_cost
):
    from include.config.validation import RequestRateControlPolicy
    from include.domains.security.guards import request_rate_control

    policy = RequestRateControlPolicy(action_costs=(("custom_action", 1),))
    monkeypatch.setattr(
        request_rate_control.RequestRateControlPolicy,
        "from_config",
        classmethod(lambda cls: policy),
    )
    handler = type("CustomHandler", (), {"rate_limit_cost": declared_cost})

    with pytest.raises(ValueError, match="custom_action.*rate_limit_cost"):
        request_rate_control.validate_handler_rate_limit_costs(
            {"custom_action": handler}
        )


def test_handler_cost_validation_reports_configured_unknown_actions(monkeypatch):
    from include.config.validation import RequestRateControlPolicy
    from include.domains.security.guards import request_rate_control

    policy = RequestRateControlPolicy(
        action_costs=(("known_action", 2), ("unknown_action", 3))
    )
    monkeypatch.setattr(
        request_rate_control.RequestRateControlPolicy,
        "from_config",
        classmethod(lambda cls: policy),
    )
    handler = type("CustomHandler", (), {"rate_limit_cost": 1})

    assert request_rate_control.validate_handler_rate_limit_costs(
        {"known_action": handler}
    ) == ("unknown_action",)


def test_legacy_cost_override_does_not_configure_namespaced_action(monkeypatch):
    from include.config.validation import RequestRateControlPolicy
    from include.domains.security.guards import request_rate_control
    from include.transport.router import available_functions

    policy = RequestRateControlPolicy(action_costs=(("search", 9),))
    monkeypatch.setattr(
        request_rate_control.RequestRateControlPolicy,
        "from_config",
        classmethod(lambda cls: policy),
    )
    assert request_rate_control.validate_handler_rate_limit_costs(
        available_functions
    ) == ("search",)
    handler_cost = available_functions["core.search.query"].rate_limit_cost
    assert policy.cost_for("core.search.query", handler_cost) == handler_cost == 3
