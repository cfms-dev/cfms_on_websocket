import ast
from pathlib import Path

import pytest

from include.config.validation import RequestRateControlPolicy
from include.domains.security.guards import request_rate_control
from include.transport.request_handler import validate_request_handler_models
from include.transport.router import available_functions

pytestmark = pytest.mark.unit

PROJECT_ROOT = Path(__file__).resolve().parents[2]

EXTRA_HANDLER_FILES = (
    PROJECT_ROOT / "src/include/extensions/builtin/_extension.py",
    PROJECT_ROOT / "src/include/extensions/oidc_sso/_extension.py",
    PROJECT_ROOT / "src/include/domains/security/handlers/debugging.py",
)


def _declared_handler_costs(path: Path) -> dict[str, int]:
    module = ast.parse(path.read_text(encoding="utf-8"))
    costs: dict[str, int] = {}

    for node in module.body:
        if not isinstance(node, ast.ClassDef) or not any(
            isinstance(base, ast.Subscript)
            and isinstance(base.value, ast.Name)
            and base.value.id == "RequestHandler"
            for base in node.bases
        ):
            continue

        assignments: list[int] = []
        for stmt in node.body:
            if (
                isinstance(stmt, ast.Assign)
                and any(
                    isinstance(target, ast.Name) and target.id == "rate_limit_cost"
                    for target in stmt.targets
                )
                or (
                    isinstance(stmt, ast.AnnAssign)
                    and isinstance(stmt.target, ast.Name)
                    and stmt.target.id == "rate_limit_cost"
                )
            ):
                value_node = stmt.value
            else:
                continue

            if (
                isinstance(value_node, ast.Constant)
                and isinstance(value_node.value, int)
                and not isinstance(value_node.value, bool)
            ):
                assignments.append(value_node.value)

        assert len(assignments) == 1, (
            f"{node.name} must declare a valid int rate_limit_cost"
        )
        costs[node.name] = assignments[0]

    return costs


def _collect_all_live_costs() -> dict[str, int]:
    costs = {
        action: handler_type.rate_limit_cost
        for action, handler_type in available_functions.items()
    }
    for source_file in EXTRA_HANDLER_FILES:
        file_costs = _declared_handler_costs(source_file)
        assert file_costs, f"No RequestHandler subclasses found in {source_file}"
        costs.update(file_costs)
    return costs


def test_all_registered_handlers_have_valid_rate_limit_costs(monkeypatch):
    validate_request_handler_models(available_functions)

    default_policy = RequestRateControlPolicy()
    monkeypatch.setattr(
        request_rate_control.RequestRateControlPolicy,
        "from_options",
        classmethod(lambda cls, _session: default_policy),
    )

    unknown_actions = request_rate_control.validate_handler_rate_limit_costs(
        available_functions
    )
    assert unknown_actions == ()


def test_all_live_costs_fit_default_request_buckets():
    policy = RequestRateControlPolicy()
    capacity = min(policy.account_capacity, policy.ip_capacity)
    all_costs = _collect_all_live_costs()

    out_of_bounds = {
        name: cost for name, cost in all_costs.items() if not (0 < cost <= capacity)
    }
    assert not out_of_bounds, (
        f"Handlers with cost outside (0, {capacity}]: {out_of_bounds}"
    )


@pytest.mark.parametrize("declared_cost", [True, 0, -1, 1.5, 121])
def test_handler_cost_validation_rejects_invalid_declared_cost_even_when_overridden(
    monkeypatch, declared_cost
):
    policy = RequestRateControlPolicy(action_costs=(("custom_action", 1),))
    monkeypatch.setattr(
        request_rate_control.RequestRateControlPolicy,
        "from_options",
        classmethod(lambda cls, _session: policy),
    )
    handler = type("CustomHandler", (), {"rate_limit_cost": declared_cost})

    with pytest.raises(ValueError, match="custom_action.*rate_limit_cost"):
        request_rate_control.validate_handler_rate_limit_costs(
            {"custom_action": handler}
        )


def test_handler_cost_validation_reports_configured_unknown_actions(monkeypatch):
    policy = RequestRateControlPolicy(
        action_costs=(("known_action", 2), ("unknown_action", 3))
    )
    monkeypatch.setattr(
        request_rate_control.RequestRateControlPolicy,
        "from_options",
        classmethod(lambda cls, _session: policy),
    )
    handler = type("CustomHandler", (), {"rate_limit_cost": 1})

    assert request_rate_control.validate_handler_rate_limit_costs(
        {"known_action": handler}
    ) == ("unknown_action",)


def test_legacy_cost_override_does_not_configure_namespaced_action(monkeypatch):
    policy = RequestRateControlPolicy(action_costs=(("search", 9),))
    monkeypatch.setattr(
        request_rate_control.RequestRateControlPolicy,
        "from_options",
        classmethod(lambda cls, _session: policy),
    )
    assert request_rate_control.validate_handler_rate_limit_costs(
        available_functions
    ) == ("search",)
    handler_cost = available_functions["core.search.query"].rate_limit_cost
    assert policy.cost_for("core.search.query", handler_cost) == handler_cost == 3
