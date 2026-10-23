import ast
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

SOURCE_ROOT = Path(__file__).resolve().parents[2] / "src/include"
HANDLER_PATHS = sorted(
    path
    for path in SOURCE_ROOT.rglob("*.py")
    if "RequestHandler" in path.read_text(encoding="utf-8")
)


@pytest.mark.parametrize(
    "path", HANDLER_PATHS, ids=lambda path: path.relative_to(SOURCE_ROOT).as_posix()
)
def test_handlers_bind_their_declared_request_model(path):
    module = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(module):
        if not isinstance(node, ast.ClassDef):
            continue
        for base in node.bases:
            origin = base.value if isinstance(base, ast.Subscript) else base
            if not isinstance(origin, ast.Name) or origin.id != "RequestHandler":
                continue

            assert isinstance(base, ast.Subscript), node.name
            models = [
                statement.value
                for statement in node.body
                if isinstance(statement, ast.Assign)
                and any(
                    isinstance(target, ast.Name) and target.id == "request_model"
                    for target in statement.targets
                )
            ]
            assert len(models) == 1, node.name
            assert ast.dump(base.slice) == ast.dump(models[0]), node.name
