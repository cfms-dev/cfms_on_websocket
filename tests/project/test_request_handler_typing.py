import ast
import json
import subprocess
import sys
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
    handler_base_names = {"RequestHandler"}
    for node in ast.walk(module):
        if not isinstance(node, ast.ClassDef):
            continue
        for base in node.bases:
            origin = base.value if isinstance(base, ast.Subscript) else base
            if not isinstance(origin, ast.Name) or origin.id not in handler_base_names:
                continue

            handler_base_names.add(node.name)
            assert isinstance(base, ast.Subscript), node.name
            if isinstance(base.slice, ast.Name) and base.slice.id in {
                parameter.name for parameter in node.type_params
            }:
                continue
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


def test_pyright_infers_unannotated_request_parameters(tmp_path):
    sample = tmp_path / "handler_inference.py"
    sample.write_text(
        """from typing import Literal, assert_type

from include.domains.identity.handlers.auth import (
    _ExchangeTokenRequest,
)
from include.domains.identity.tokens import TokenPurpose
from include.transport.connection import ConnectionHandler
from include.transport.request_handler import RequestDataModel, RequestHandler, Result


class DirectHandler(RequestHandler[_ExchangeTokenRequest]):
    request_model = _ExchangeTokenRequest

    def handle(self, handler: ConnectionHandler, request) -> Result:
        assert_type(request, _ExchangeTokenRequest)
        assert_type(
            request.target_purpose,
            Literal[TokenPurpose.GENERAL, TokenPurpose.GENERAL_WITH_ESCALATION],
        )
        return Result(code=200)


class GenericHandler[RequestT: RequestDataModel](RequestHandler[RequestT]):
    def handle(self, handler: ConnectionHandler, request: RequestT) -> Result:
        assert_type(request, RequestT)
        return Result(code=200)


class IndirectHandler(GenericHandler[_ExchangeTokenRequest]):
    request_model = _ExchangeTokenRequest

    def handle(self, handler: ConnectionHandler, request) -> Result:
        assert_type(request, _ExchangeTokenRequest)
        return Result(code=200)
""",
        encoding="utf-8",
    )
    project_root = Path(__file__).resolve().parents[2]
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pyright",
            "--project",
            str(project_root / "pyproject.toml"),
            "--outputjson",
            str(sample),
        ],
        cwd=project_root,
        capture_output=True,
        check=False,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    diagnostics = json.loads(result.stdout)
    assert diagnostics["summary"]["errorCount"] == 0, diagnostics["generalDiagnostics"]
