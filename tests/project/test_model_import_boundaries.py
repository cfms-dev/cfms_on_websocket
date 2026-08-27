import ast
from pathlib import Path


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
