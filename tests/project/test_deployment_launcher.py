import importlib.util
import json
import os
import subprocess
from pathlib import Path
from types import ModuleType

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _load_launcher(deployment_root: Path) -> ModuleType:
    launcher_path = deployment_root / "main.py"
    launcher_path.write_bytes(
        (PROJECT_ROOT / "src/deployment_launcher.py").read_bytes()
    )
    spec = importlib.util.spec_from_file_location("deployment_launcher", launcher_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _prepare_deployment(tmp_path: Path) -> tuple[ModuleType, Path, Path]:
    deployment_root = tmp_path / "deployment"
    shared_root = deployment_root / "shared"
    shared_root.mkdir(parents=True)
    release_root = deployment_root / "releases" / "1.2.3"
    python = (
        release_root / ".venv" / "Scripts" / "python.exe"
        if os.name == "nt"
        else release_root / ".venv" / "bin" / "python"
    )
    python.parent.mkdir(parents=True)
    python.write_bytes(b"")
    (release_root / "src").mkdir()
    (deployment_root / "deployment.json").write_text(
        json.dumps({"active_version": "1.2.3"}),
        encoding="utf-8",
    )
    return _load_launcher(deployment_root), release_root, python


@pytest.mark.parametrize(
    ("arguments", "expected_tail"),
    [
        ([], ("src/main.py",)),
        (
            ["maintain", "deployment", "status"],
            ("-m", "maintenance.cli", "deployment", "status"),
        ),
    ],
)
def test_launcher_dispatches_active_release(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    arguments: list[str],
    expected_tail: tuple[str, ...],
) -> None:
    launcher, release_root, python = _prepare_deployment(tmp_path)
    captured = {}

    if os.name == "nt":

        def run(command, *, env, check):
            captured.update(command=command, env=env, check=check)
            return subprocess.CompletedProcess(command, 17)

        monkeypatch.setattr(launcher.subprocess, "run", run)
    else:

        def execve(executable, command, environment):
            captured.update(
                executable=executable,
                command=command,
                env=environment,
            )
            raise SystemExit(17)

        monkeypatch.setattr(launcher.os, "execve", execve)

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(launcher.sys, "argv", ["main.py", *arguments])

    with pytest.raises(SystemExit) as exc_info:
        launcher.main()

    assert exc_info.value.code == 17
    assert captured["command"][0] == str(python)
    assert (
        tuple(
            str(Path(item).relative_to(release_root)).replace("\\", "/")
            if item.startswith(str(release_root)) and item != str(python)
            else item
            for item in captured["command"][1:]
        )
        == expected_tail
    )
    assert captured["env"]["CFMS_SERVER_ROOT"] == str(
        tmp_path / "deployment" / "shared"
    )
    assert Path.cwd() == tmp_path / "deployment" / "shared"


@pytest.mark.parametrize(
    ("contents", "message"),
    [
        ("{", "Unable to read"),
        ("[]", "Unable to read"),
        (json.dumps({}), "Unable to read"),
        (json.dumps({"active_version": "1.2"}), "invalid active version"),
    ],
)
def test_launcher_rejects_invalid_deployment_state(
    tmp_path: Path,
    contents: str,
    message: str,
) -> None:
    deployment_root = tmp_path / "deployment"
    deployment_root.mkdir()
    launcher = _load_launcher(deployment_root)
    (deployment_root / "deployment.json").write_text(contents, encoding="utf-8")

    with pytest.raises(SystemExit, match=message):
        launcher.main()


def test_launcher_rejects_missing_active_interpreter(tmp_path: Path) -> None:
    deployment_root = tmp_path / "deployment"
    deployment_root.mkdir()
    launcher = _load_launcher(deployment_root)
    (deployment_root / "deployment.json").write_text(
        json.dumps({"active_version": "1.2.3"}),
        encoding="utf-8",
    )

    with pytest.raises(SystemExit, match="Active release interpreter not found"):
        launcher.main()


def test_launcher_rejects_unknown_action(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    launcher, _, _ = _prepare_deployment(tmp_path)
    monkeypatch.setattr(launcher.sys, "argv", ["main.py", "unknown"])

    with pytest.raises(SystemExit, match="Usage: python main.py"):
        launcher.main()


def test_launcher_completes_pending_cleanup_before_dispatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    launcher, _, _ = _prepare_deployment(tmp_path)
    deployment_root = tmp_path / "deployment"
    retired = deployment_root / "releases" / "1.2.2"
    retired.mkdir()
    transaction_path = deployment_root / "shared" / "run" / "upgrade-transaction.json"
    transaction_path.parent.mkdir()
    transaction_path.write_text(
        json.dumps(
            {
                "action": "upgrade",
                "from_version": "1.2.2",
                "phase": "cleanup-required",
                "to_version": "1.2.3",
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(launcher.sys, "argv", ["main.py", "unknown"])

    with pytest.raises(SystemExit, match="Usage: python main.py"):
        launcher.main()

    assert not retired.exists()
    assert not transaction_path.exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows launcher owns post-exit cleanup")
def test_windows_launcher_cleans_release_after_upgrade_process_exits(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    launcher, retired, _ = _prepare_deployment(tmp_path)
    deployment_root = tmp_path / "deployment"
    transaction_path = deployment_root / "shared" / "run" / "upgrade-transaction.json"

    def run(command, *, env, check):
        (deployment_root / "deployment.json").write_text(
            json.dumps({"active_version": "1.2.4"}),
            encoding="utf-8",
        )
        transaction_path.parent.mkdir(exist_ok=True)
        transaction_path.write_text(
            json.dumps(
                {
                    "action": "upgrade",
                    "from_version": "1.2.3",
                    "phase": "cleanup-required",
                    "to_version": "1.2.4",
                }
            ),
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(launcher.subprocess, "run", run)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        launcher.sys,
        "argv",
        ["main.py", "maintain", "deployment", "upgrade", "release.zip"],
    )

    with pytest.raises(SystemExit) as exc_info:
        launcher.main()

    assert exc_info.value.code == 0
    assert not retired.exists()
    assert not transaction_path.exists()
