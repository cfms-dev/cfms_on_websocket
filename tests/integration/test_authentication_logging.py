import subprocess
import sys

import pytest

pytestmark = pytest.mark.integration


def test_server_logs_exclude_authentication_values(tmp_path, protected_test_config):
    script = tmp_path / "log_auth_failure.py"
    script.write_text(
        """
from pathlib import Path
from types import SimpleNamespace
import sys

sys.path.insert(0, str(Path.cwd()))

from include.config import paths

assert paths.EXECUTABLE_ABSPATH == Path.cwd()

import main
from include.transport.connection import send_conclusion

main.EXECUTABLE_ABSPATH = Path(sys.argv[1])
main.prepare_logger()

def fail():
    password = "authentication-sensitive-password-marker"
    assert password == "expected"

try:
    fail()
except AssertionError:
    main.logger.opt(exception=True).error("authentication failure logged")

send_conclusion(SimpleNamespace(send=lambda *a, **k: None), 200,
                {"token": "authentication-sensitive-token-marker"})
main.logger.complete()
""",
        encoding="utf-8",
    )
    completed = subprocess.run(
        [sys.executable, str(script), str(tmp_path)],
        cwd=protected_test_config.src_dir,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=15,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    file_log = (tmp_path / "content" / "logs" / "server.log").read_text(
        encoding="utf-8"
    )
    for content in (completed.stderr, file_log):
        assert "authentication failure logged" in content
        assert "AssertionError" in content
        assert "authentication-sensitive-password-marker" not in content
        assert "authentication-sensitive-token-marker" not in content
