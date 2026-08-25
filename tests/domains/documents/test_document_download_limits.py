import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from shutil import copyfile
from threading import Event

import pytest
from sqlalchemy import create_engine, event, func, select
from sqlalchemy.orm import sessionmaker

PROJECT_ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture
def download_limit_context(monkeypatch, tmp_path):
    copyfile(PROJECT_ROOT / "src" / "config.toml.sample", tmp_path / "config.toml")
    copyfile(PROJECT_ROOT / "src" / "init", tmp_path / "init")
    monkeypatch.chdir(tmp_path)
    src_path = str(PROJECT_ROOT / "src")
    if src_path not in sys.path:
        sys.path.insert(0, src_path)

    from include.config.validation import DocumentDownloadRiskPolicy
    from include.database import models
    from include.database.session import Base
    from include.domains.documents import download_limits

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine)
    policy = DocumentDownloadRiskPolicy(
        mode="enforce",
        refill_period_seconds=60,
        issue_account_capacity=6,
        issue_account_refill_tokens=6,
        issue_ip_capacity=20,
        issue_ip_refill_tokens=20,
        transfer_account_capacity=20,
        transfer_account_refill_tokens=20,
        transfer_ip_capacity=20,
        transfer_ip_refill_tokens=20,
        task_capacity=2,
        task_refill_tokens=2,
        task_refill_period_seconds=60,
        new_account_seconds=100,
        ip_account_window_seconds=60,
        ip_accounts_elevated=2,
        ip_accounts_high=3,
        denial_window_seconds=60,
        denials_elevated=1,
        denials_high=3,
        elevated_cost=2,
        high_cost=3,
        state_retention_seconds=120,
    )
    monkeypatch.setattr(
        download_limits.DocumentDownloadRiskPolicy,
        "from_config",
        classmethod(lambda _cls: policy),
    )
    monkeypatch.setattr(
        download_limits,
        "_last_cleanup_monotonic",
        {"download_issue": 0.0, "download_transfer": 0.0},
    )
    yield download_limits, models, session_factory, policy
    engine.dispose()


def _issue(download_limits, session, username="alice", ip="203.0.113.1", **kwargs):
    return download_limits.check_download_issue_limits(
        session,
        username,
        ip,
        account_created_at=0.0,
        now=1000.0,
        bypass_rate_limit=False,
        **kwargs,
    )


def test_download_issue_uses_independent_account_and_ip_buckets(
    download_limit_context,
):
    download_limits, models, session_factory, _policy = download_limit_context

    with session_factory.begin() as session:
        decisions = [_issue(download_limits, session) for _ in range(7)]

    assert all(decision.allowed for decision in decisions[:6])
    assert decisions[-1].allowed is False
    assert decisions[-1].scope == "account"
    with session_factory() as session:
        assert (
            session.get(
                models.RateLimitBucket,
                ("download_issue", "account", "alice"),
            )
            is not None
        )
        assert (
            session.get(
                models.RateLimitBucket,
                ("document_creation", "account", "alice"),
            )
            is None
        )


def test_download_ip_account_fanout_escalates_risk(download_limit_context):
    download_limits, _models, session_factory, _policy = download_limit_context

    with session_factory.begin() as session:
        levels = [
            _issue(download_limits, session, username=username).risk_level
            for username in ("alice", "bob", "charlie")
        ]

    assert levels == [
        download_limits.DownloadRiskLevel.NORMAL,
        download_limits.DownloadRiskLevel.ELEVATED,
        download_limits.DownloadRiskLevel.HIGH,
    ]


def test_download_transfer_limits_each_bearer_task(download_limit_context):
    download_limits, models, session_factory, _policy = download_limit_context
    with session_factory.begin() as session:
        file = models.File(id="file", path="file.bin")
        task = models.FileTask(
            id="task",
            file=file,
            mode=models.TransferMode.DOWNLOAD,
            status=models.FileTaskStatus.IN_PROGRESS,
            start_time=900.0,
            end_time=1100.0,
        )
        session.add_all([file, task])

    with session_factory.begin() as session:
        decisions = [
            download_limits.check_download_transfer_limits(
                session,
                None,
                "203.0.113.1",
                "task",
                account_created_at=None,
                bypass_rate_limit=False,
                now=1000.0,
            )
            for _ in range(3)
        ]

    assert decisions[0].active_downloads == 1
    assert decisions[0].allowed is True
    assert decisions[1].allowed is True
    assert decisions[2].allowed is False
    assert decisions[2].scope == "task"
    assert decisions[2].limit == 2


def test_download_observe_mode_records_shadow_denial(
    download_limit_context, monkeypatch
):
    download_limits, _models, session_factory, policy = download_limit_context
    observe_policy = type(policy)(**{**policy.__dict__, "mode": "observe"})
    monkeypatch.setattr(
        download_limits.DocumentDownloadRiskPolicy,
        "from_config",
        classmethod(lambda _cls: observe_policy),
    )

    with session_factory.begin() as session:
        decisions = [_issue(download_limits, session) for _ in range(7)]

    assert all(decision.allowed for decision in decisions)
    assert decisions[-1].would_block is True


def test_download_bypass_does_not_create_shadow_state(download_limit_context):
    download_limits, models, session_factory, _policy = download_limit_context

    with session_factory.begin() as session:
        decision = download_limits.check_download_issue_limits(
            session,
            "sysop",
            "203.0.113.1",
            account_created_at=1000.0,
            bypass_rate_limit=True,
            now=1000.0,
        )

    assert decision.allowed is True
    with session_factory() as session:
        assert session.scalar(select(func.count(models.RateLimitBucket.namespace))) == 0
        assert session.scalar(select(func.count(models.RiskIPAccount.namespace))) == 0


def test_sqlite_issue_and_transfer_claim_share_one_lock_order(
    download_limit_context, tmp_path
):
    from include.domains.documents.commands.file_tasks import (
        ClaimedFileTask,
        claim_file_task,
    )
    from include.domains.security.guards.rate_limits import (
        rate_limit_lock,
        risk_control_transaction,
    )

    download_limits, models, _session_factory, policy = download_limit_context
    engine = create_engine(
        f"sqlite:///{tmp_path / 'download-concurrency.db'}",
        connect_args={"timeout": 0.2},
    )

    @event.listens_for(engine, "connect")
    def _configure_sqlite(dbapi_connection, _connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA busy_timeout=200")
        cursor.close()

    models.User.metadata.create_all(engine)
    concurrent_sessions = sessionmaker(bind=engine)
    with concurrent_sessions.begin() as session:
        download_file = models.File(id="download-file", path="download.bin")
        download_file.size = 1
        session.add_all(
            [
                models.User(username="alice", pass_hash="unused", created_time=0.0),
                download_file,
                models.File(id="issued-file", path="issued.bin"),
                models.FileTask(
                    id="download-task",
                    file=download_file,
                    issued_by_username="alice",
                    mode=models.TransferMode.DOWNLOAD,
                    status=models.FileTaskStatus.PENDING,
                    start_time=900.0,
                    end_time=1100.0,
                ),
            ]
        )

    claim_has_write_lock = Event()
    issue_is_waiting_for_risk_lock = Event()

    @event.listens_for(engine, "after_cursor_execute")
    def _pause_after_claim_update(
        _connection,
        _cursor,
        statement,
        _parameters,
        _context,
        _executemany,
    ):
        normalized = " ".join(statement.upper().split())
        if not normalized.startswith("UPDATE FILE_TASKS SET STATUS="):
            return
        assert rate_limit_lock.locked()
        claim_has_write_lock.set()
        assert issue_is_waiting_for_risk_lock.wait(timeout=1)

    def transfer_claim():
        with concurrent_sessions() as session, risk_control_transaction(session):
            claimed = claim_file_task(
                session,
                "download-task",
                models.TransferMode.DOWNLOAD,
                now=1000.0,
            )
            assert isinstance(claimed, ClaimedFileTask)
            decision = download_limits.check_download_transfer_limits(
                session,
                "alice",
                "203.0.113.1",
                "download-task",
                account_created_at=0.0,
                bypass_rate_limit=False,
                now=1000.0,
            )
            assert decision.allowed

    def issue_task():
        issue_is_waiting_for_risk_lock.set()
        with concurrent_sessions() as session, risk_control_transaction(session):
            decision = _issue(download_limits, session)
            assert decision.allowed
            session.add(
                models.FileTask(
                    id="issued-task",
                    file_id="issued-file",
                    issued_by_username="alice",
                    mode=models.TransferMode.DOWNLOAD,
                    status=models.FileTaskStatus.PENDING,
                    start_time=1000.0,
                    end_time=1100.0,
                )
            )

    with ThreadPoolExecutor(max_workers=2) as executor:
        transfer_future = executor.submit(transfer_claim)
        assert claim_has_write_lock.wait(timeout=1)
        issue_future = executor.submit(issue_task)
        transfer_future.result(timeout=2)
        issue_future.result(timeout=2)

    with concurrent_sessions() as session:
        task = session.get(models.FileTask, "download-task")
        issued_task = session.get(models.FileTask, "issued-task")
        issue_bucket = session.get(
            models.RateLimitBucket,
            ("download_issue", "account", "alice"),
        )
        transfer_bucket = session.get(
            models.RateLimitBucket,
            ("download_transfer", "account", "alice"),
        )
        assert task.status == models.FileTaskStatus.IN_PROGRESS
        assert issued_task.status == models.FileTaskStatus.PENDING
        assert issue_bucket.tokens == policy.issue_account_capacity - 1
        assert transfer_bucket.tokens == policy.transfer_account_capacity - 1

    engine.dispose()
