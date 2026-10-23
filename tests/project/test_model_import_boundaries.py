import ast
from pathlib import Path

import pytest

pytestmark = pytest.mark.component


def test_document_models_do_not_import_domain_modules() -> None:
    project_root = Path(__file__).resolve().parents[2]
    model_path = project_root / "src/include/database/models/documents.py"
    tree = ast.parse(model_path.read_text(encoding="utf-8"))

    domain_imports = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            domain_imports.extend(
                alias.name
                for alias in node.names
                if alias.name.startswith("include.domains")
            )
        elif isinstance(node, ast.ImportFrom) and (node.module or "").startswith(
            "include.domains"
        ):
            domain_imports.append(node.module)

    assert domain_imports == []


def test_oidc_persistence_is_owned_exclusively_by_the_extension() -> None:
    source = Path(__file__).resolve().parents[2] / "src"
    extension_packages = tuple(
        manifest.parent
        for manifest in (source / "include/extensions").glob("*/manifest.toml")
    )
    violations = []
    for path in source.rglob("*.py"):
        if any(
            path.is_relative_to(package) for package in extension_packages
        ) or path.is_relative_to(source / "alembic/versions"):
            continue
        text = path.read_text(encoding="utf-8")
        if any(
            name in text
            for name in (
                "UserOidcCredential",
                "user_oidc_credentials",
                "bind_oidc_identity",
                "find_oidc_credential",
                "include.extensions.oidc_sso",
            )
        ):
            violations.append(str(path.relative_to(source)))
    assert violations == []
