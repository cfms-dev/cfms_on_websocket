import ast
import subprocess
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from maintenance.cli import app

COMMANDS = {
    "user": ("reset-password", "clear-totp"),
    "config": ("fill-pepper", "sync-template"),
    "backup": ("export", "info", "import"),
    "audit": ("export", "purge"),
    "permission": ("purge-expired",),
    "database": ("upgrade", "migrate"),
    "deployment": (
        "upgrade",
        "status",
        "check",
        "update",
        "prune",
        "downgrade",
        "resume",
    ),
    "extension": (
        "list",
        "info",
        "install",
        "upgrade",
        "enable",
        "disable",
        "uninstall",
    ),
}


def test_cli_registration_matches_the_public_command_tree() -> None:
    registered = {
        group.name: tuple(
            command.name for command in group.typer_instance.registered_commands
        )
        for group in app.registered_groups
    }

    assert registered == COMMANDS


@pytest.mark.parametrize("group", [None, *COMMANDS])
def test_every_cli_group_has_a_help_entry(group: str | None) -> None:
    arguments = ["--help"] if group is None else [group, "--help"]

    result = CliRunner().invoke(app, arguments)

    assert result.exit_code == 0
    assert "Usage:" in result.stdout


def test_cli_import_does_not_eagerly_load_backup_providers_or_models() -> None:
    code = """
import sys
from maintenance.cli import app
assert app is not None
assert "maintenance.backup" not in sys.modules
assert "include.providers.manager" not in sys.modules
assert not any(name.startswith("include.database.models.") for name in sys.modules)
"""

    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        check=False,
        text=True,
    )

    assert result.returncode == 0, result.stderr


def test_maintenance_import_graph_is_acyclic_and_operations_is_not_a_barrel() -> None:
    source_root = Path(__file__).resolve().parents[2] / "src"
    maintenance_root = source_root / "maintenance"
    graph: dict[str, set[str]] = {}

    for path in maintenance_root.rglob("*.py"):
        module = ".".join(path.relative_to(source_root).with_suffix("").parts)
        if module.endswith(".__init__"):
            module = module.removesuffix(".__init__")
        imports: set[str] = set()
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(
                    alias.name
                    for alias in node.names
                    if alias.name.startswith("maintenance.")
                )
            elif isinstance(node, ast.ImportFrom) and (node.module or "").startswith(
                "maintenance."
            ):
                for alias in node.names:
                    candidate = f"{node.module}.{alias.name}"
                    candidate_path = source_root.joinpath(*candidate.split("."))
                    imports.add(
                        candidate
                        if candidate_path.with_suffix(".py").is_file()
                        or (candidate_path / "__init__.py").is_file()
                        else node.module
                    )
        graph[module] = imports

    operations_tree = ast.parse(
        (maintenance_root / "operations" / "__init__.py").read_text(encoding="utf-8")
    )
    assert not any(
        isinstance(node, (ast.Import, ast.ImportFrom)) for node in operations_tree.body
    )

    visited: set[str] = set()
    active: list[str] = []

    def visit(module: str) -> None:
        if module in active:
            cycle = " -> ".join([*active[active.index(module) :], module])
            pytest.fail(f"maintenance import cycle: {cycle}")
        if module in visited:
            return
        active.append(module)
        for dependency in graph.get(module, ()):
            candidate = dependency
            while candidate not in graph and "." in candidate:
                candidate = candidate.rsplit(".", 1)[0]
            if candidate in graph:
                visit(candidate)
        active.pop()
        visited.add(module)

    for module in graph:
        visit(module)
