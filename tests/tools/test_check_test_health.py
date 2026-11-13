import json
from types import SimpleNamespace

import pytest
lazy from botocore.exceptions import ClientError

from tools import check_test_health as health

pytestmark = pytest.mark.component


@pytest.mark.parametrize(
    ("contents", "no_skips", "valid"),
    [
        ("<testcase/>", True, True),
        ("<testcase/><testcase><skipped/></testcase>", False, True),
        ("", False, False),
        ("<testcase><skipped/></testcase>", False, False),
        ("<testcase/><testcase><skipped/></testcase>", True, False),
        ("<testcase><failure/></testcase>", False, False),
        ("<testcase><error/></testcase>", False, False),
    ],
)
def test_junit_requires_executed_successes_and_checks_backend_skips(
    tmp_path, contents, no_skips, valid
):
    report = tmp_path / "result.xml"
    report.write_text(
        f"<testsuites><testsuite>{contents}</testsuite></testsuites>", encoding="utf-8"
    )
    if valid:
        counts = health.validate_junit(report, require_no_skips=no_skips)
        assert counts["executed"] == 1
        assert counts["failure"] == counts["error"] == 0
    else:
        with pytest.raises(ValueError, match="JUnit"):
            health.validate_junit(report, require_no_skips=no_skips)


@pytest.mark.parametrize("code", [0, 2, 5])
def test_run_preserves_pytest_exit_status_and_records_elapsed_time(
    tmp_path, monkeypatch, code
):
    report = tmp_path / "result.xml"
    report.write_text("stale report", encoding="utf-8")

    def run(command, *, cwd, env, check):
        assert not report.exists()
        assert cwd == tmp_path
        assert env["PYTHONHASHSEED"] == "17"
        assert env["PYTHONPATH"].split(health.os.pathsep) == [
            str(tmp_path / "src"),
            str(tmp_path),
        ]
        assert "--randomly-seed=17" in command
        assert check is False
        report.write_text(
            "<testsuites><testsuite><testcase/></testsuite></testsuites>",
            encoding="utf-8",
        )
        return SimpleNamespace(returncode=code)

    ticks = iter([10.0, 12.5])
    monkeypatch.setattr(health.subprocess, "run", run)
    monkeypatch.setattr(health.time, "perf_counter", lambda: next(ticks))
    assert health.run_pytest(tmp_path, ["tests/"], report, 17) == (code, 2.5)


@pytest.mark.parametrize(
    ("profile", "elapsed", "exit_code"),
    [
        ("unit", 29, 0),
        ("unit", 30, 0),
        ("unit", 31, 1),
        ("component", 420, 0),
        ("component", 421, 1),
        ("integration", 420, 0),
        ("integration", 421, 1),
        ("all", 900, 0),
        ("all", 901, 1),
        ("redis", 60, 0),
        ("redis", 61, 1),
        ("mysql-8.4", 300, 0),
        ("mysql-8.4", 301, 1),
        ("mysql-9.7", 300, 0),
        ("mysql-9.7", 301, 1),
        ("postgresql", 120, 0),
        ("postgresql", 121, 1),
        ("s3", 60, 0),
        ("s3", 61, 1),
    ],
)
def test_main_enforces_the_profile_time_limit(
    tmp_path, monkeypatch, profile, elapsed, exit_code
):
    report = tmp_path / "result.xml"
    for name in health.BACKEND_ENVIRONMENT.get(profile, ()):
        monkeypatch.setenv(name, "1" if name == "CFMS_TEST_S3_WRITE" else "configured")

    def run(_root, _arguments, path, _seed):
        path.write_text(
            "<testsuites><testsuite><testcase/></testsuite></testsuites>",
            encoding="utf-8",
        )
        return 0, elapsed

    monkeypatch.setattr(health, "run_pytest", run)
    assert (
        health.main(["run", "--profile", profile, "--report", str(report)]) == exit_code
    )
    summary = json.loads(report.with_suffix(".json").read_text())
    assert summary["elapsed_seconds"] == elapsed
    assert summary["returncode"] == exit_code
    assert summary["pytest_returncode"] == 0


def test_configured_backend_requires_environment_before_running(tmp_path, monkeypatch):
    monkeypatch.delenv("CFMS_TEST_REDIS_URL", raising=False)
    assert (
        health.main(
            ["run", "--profile", "redis", "--report", str(tmp_path / "result.xml")]
        )
        == 1
    )
    assert not (tmp_path / "result.xml").exists()


@pytest.mark.parametrize("ready", [True, False])
def test_s3_readiness_checks_the_bucket_and_closes_the_client(monkeypatch, ready):
    pytest.importorskip("botocore")
    closed = []

    def head_bucket(*, Bucket):
        assert Bucket == "dedicated"
        if not ready:
            raise ClientError({"Error": {"Code": "NoSuchBucket"}}, "HeadBucket")

    client = SimpleNamespace(head_bucket=head_bucket, close=lambda: closed.append(True))
    monkeypatch.setenv("CFMS_TEST_S3_BUCKET", "dedicated")
    monkeypatch.setenv("CFMS_TEST_S3_ENDPOINT_URL", "http://127.0.0.1:8333")
    monkeypatch.setattr(
        health, "boto3", SimpleNamespace(client=lambda *_args, **_kwargs: client)
    )
    if ready:
        health.wait_for_s3(timeout_seconds=0)
    else:
        with pytest.raises(TimeoutError, match="Dedicated S3 bucket") as caught:
            health.wait_for_s3(timeout_seconds=0)
        assert isinstance(caught.value.__cause__, ClientError)
    assert closed == [True]


@pytest.mark.parametrize("exit_code", [1, 2, 5])
def test_main_does_not_retry_or_hide_pytest_failures(tmp_path, monkeypatch, exit_code):
    calls = []

    def run(*_args):
        calls.append(True)
        return exit_code, 1.0

    monkeypatch.setattr(health, "run_pytest", run)
    assert health.main(["run", "--report", str(tmp_path / "result.xml")]) == exit_code
    assert calls == [True]
