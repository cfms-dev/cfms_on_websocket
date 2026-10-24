import json
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit


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
