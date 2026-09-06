import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from shutil import copyfile

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

PROJECT_ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture
def creation_limit_context(monkeypatch, tmp_path):
    copyfile(PROJECT_ROOT / "src" / "config.toml.sample", tmp_path / "config.toml")
    (tmp_path / "init").touch()
    monkeypatch.chdir(tmp_path)
    src_path = str(PROJECT_ROOT / "src")
    if src_path not in sys.path:
        sys.path.insert(0, src_path)

    from include.config.validation import (
        DocumentCreationRiskPolicy,
        DocumentUploadPolicy,
    )
    from include.database import models
    from include.database.session import Base
    from include.domains.documents import creation_limits

    engine = create_engine("sqlite:///:memory:")

    @event.listens_for(engine, "connect")
    def _enable_sqlite_foreign_keys(dbapi_connection, _connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine)
    upload_policy = DocumentUploadPolicy(max_pending_documents_per_creator=2)
    risk_policy = DocumentCreationRiskPolicy(
        mode="enforce",
        refill_period_seconds=60,
        account_capacity=6,
        account_refill_tokens=6,
        ip_capacity=20,
        ip_refill_tokens=20,
        new_account_seconds=100,
        pending_elevated_ratio=0.5,
        pending_high_ratio=0.75,
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
        creation_limits.DocumentUploadPolicy,
        "from_config",
        classmethod(lambda _cls: upload_policy),
    )
    monkeypatch.setattr(
        creation_limits.DocumentCreationRiskPolicy,
        "from_config",
        classmethod(lambda _cls: risk_policy),
    )
    yield creation_limits, models, session_factory, upload_policy, risk_policy
    engine.dispose()


def _check(
    creation_limits,
    session,
    username="alice",
    ip_address="203.0.113.1",
    now=1000.0,
    **kwargs,
):
    return creation_limits.check_document_creation_limits(
        session,
        username,
        ip_address,
        account_created_at=0.0,
        now=now,
        **kwargs,
    )


def test_normal_risk_uses_continuously_refilled_token_bucket(
    creation_limit_context,
):
    creation_limits, _models, session_factory, _upload, _risk = creation_limit_context

    with session_factory.begin() as session:
        for _ in range(6):
            assert _check(creation_limits, session).allowed
    with session_factory.begin() as session:
        decision = _check(creation_limits, session)

    assert decision.allowed is False
    assert decision.scope == "account"
    assert decision.limit == 6
    assert decision.retry_after_seconds == 10

    with session_factory.begin() as session:
        recovered = _check(creation_limits, session, now=1061.0)
    assert recovered.allowed is True
    assert recovered.risk_level == creation_limits.CreationRiskLevel.NORMAL


def test_new_account_uses_elevated_request_cost(creation_limit_context):
    creation_limits, _models, session_factory, _upload, _risk = creation_limit_context

    with session_factory.begin() as session:
        for _ in range(3):
            decision = creation_limits.check_document_creation_limits(
                session,
                "alice",
                "203.0.113.1",
                account_created_at=950.0,
                now=1000.0,
            )
            assert decision.allowed
            assert decision.risk_level == creation_limits.CreationRiskLevel.ELEVATED
    with session_factory.begin() as session:
        decision = creation_limits.check_document_creation_limits(
            session,
            "alice",
            "203.0.113.1",
            account_created_at=950.0,
            now=1000.0,
        )
    assert decision.allowed is False
    assert decision.limit == 3


def test_ip_account_fanout_escalates_risk(creation_limit_context):
    creation_limits, _models, session_factory, _upload, _risk = creation_limit_context

    levels = []
    with session_factory.begin() as session:
        for username in ("alice", "bob", "charlie"):
            levels.append(
                _check(creation_limits, session, username=username).risk_level
            )

    assert levels == [
        creation_limits.CreationRiskLevel.NORMAL,
        creation_limits.CreationRiskLevel.ELEVATED,
        creation_limits.CreationRiskLevel.HIGH,
    ]


def test_repeated_denials_escalate_and_decay(creation_limit_context):
    creation_limits, _models, session_factory, _upload, _risk = creation_limit_context

    with session_factory.begin() as session:
        for _ in range(6):
            assert _check(creation_limits, session).allowed
        for _ in range(3):
            assert not _check(creation_limits, session).allowed
        high = _check(creation_limits, session)
    assert high.risk_level == creation_limits.CreationRiskLevel.HIGH

    with session_factory.begin() as session:
        decayed = _check(creation_limits, session, now=1061.0)
    assert decayed.allowed is True
    assert decayed.risk_level == creation_limits.CreationRiskLevel.NORMAL


def test_observe_mode_records_would_block_without_rate_denial(
    creation_limit_context, monkeypatch
):
    creation_limits, _models, session_factory, _upload, risk_policy = (
        creation_limit_context
    )
    observe_policy = type(risk_policy)(**{**risk_policy.__dict__, "mode": "observe"})
    monkeypatch.setattr(
        creation_limits.DocumentCreationRiskPolicy,
        "from_config",
        classmethod(lambda _cls: observe_policy),
    )

    with session_factory.begin() as session:
        decisions = [_check(creation_limits, session) for _ in range(7)]

    assert all(decision.allowed for decision in decisions)
    assert decisions[-1].would_block is True


def _seed_pending_documents(models, session, count=2):
    user = models.User(username="alice", pass_hash="unused", created_time=1.0)
    root = models.Folder(id="/", name="/", inherit=False)
    session.add_all([user, root])
    for number in range(count):
        document = models.Document(
            id=f"document-{number}", title=f"reserved-{number}", folder=root
        )
        document.metadata_record = models.DocumentMetadata(
            creator_username=user.username,
            last_modified_by_username=user.username,
        )
        file = models.File(id=f"file-{number}", path=f"pending-{number}")
        revision = models.DocumentRevision(
            id=f"revision-{number}", document=document, file=file
        )
        document.current_revision = revision
        task = models.FileTask(
            id=f"task-{number}",
            file=file,
            mode=models.TransferMode.UPLOAD,
            status=models.FileTaskStatus.PENDING,
            start_time=1.0,
            end_time=2000.0,
        )
        session.add_all([document, file, revision, task])


def test_pending_ratio_affects_risk_and_hard_limit_remains(
    creation_limit_context,
):
    creation_limits, models, session_factory, _upload, _risk = creation_limit_context

    with session_factory.begin() as session:
        _seed_pending_documents(models, session, count=1)
    with session_factory.begin() as session:
        decision = _check(creation_limits, session)
    assert decision.allowed is True
    assert decision.risk_level == creation_limits.CreationRiskLevel.ELEVATED


def test_rate_limit_bypass_preserves_pending_hard_limit(
    creation_limit_context,
):
    creation_limits, models, session_factory, _upload, _risk = creation_limit_context

    with session_factory.begin() as session:
        _seed_pending_documents(models, session)
    with session_factory.begin() as session:
        decision = _check(
            creation_limits,
            session,
            bypass_rate_limit=True,
        )

    assert decision.allowed is False
    assert decision.scope == "pending_documents"
    with session_factory() as session:
        account_bucket = session.get(
            models.RateLimitBucket, ("document_creation", "account", "alice")
        )
        assert account_bucket.tokens == 6
        assert (
            session.get(
                models.RiskIPAccount,
                ("document_creation", "203.0.113.1", "alice"),
            )
            is None
        )


def test_cleanup_removes_stale_risk_state(creation_limit_context):
    creation_limits, models, session_factory, _upload, _risk = creation_limit_context

    with session_factory.begin() as session:
        session.add_all(
            [
                models.RateLimitBucket(
                    namespace="document_creation",
                    scope="account",
                    identity="stale",
                    tokens=1.0,
                    last_refill_at=1.0,
                    denial_count=0,
                    last_attempt=1.0,
                ),
                models.RiskIPAccount(
                    namespace="document_creation",
                    ip_address="198.51.100.1",
                    username="stale",
                    last_attempt=1.0,
                ),
            ]
        )
    with session_factory.begin() as session:
        result = creation_limits.cleanup_document_creation_risk_state(
            session, now=1000.0
        )
    with session_factory() as session:
        assert (
            session.get(
                models.RateLimitBucket,
                ("document_creation", "account", "stale"),
            )
            is None
        )
        assert (
            session.get(
                models.RiskIPAccount,
                ("document_creation", "198.51.100.1", "stale"),
            )
            is None
        )
    assert result.buckets == 1
    assert result.ip_accounts == 1


def test_reduced_capacity_caps_existing_balance(creation_limit_context, monkeypatch):
    creation_limits, models, session_factory, _upload, risk_policy = (
        creation_limit_context
    )
    smaller_policy = type(risk_policy)(
        **{
            **risk_policy.__dict__,
            "account_capacity": 3,
            "ip_capacity": 10,
        }
    )
    monkeypatch.setattr(
        creation_limits.DocumentCreationRiskPolicy,
        "from_config",
        classmethod(lambda _cls: smaller_policy),
    )

    with session_factory.begin() as session:
        assert _check(creation_limits, session).allowed
    with session_factory() as session:
        bucket = session.get(
            models.RateLimitBucket, ("document_creation", "account", "alice")
        )
        assert bucket.tokens == 2


def test_concurrent_bypass_requests_do_not_cross_pending_limit(
    creation_limit_context, tmp_path
):
    from include.domains.security.guards.rate_limits import (
        risk_control_transaction,
    )

    creation_limits, models, _session_factory, upload_policy, _risk = (
        creation_limit_context
    )
    engine = create_engine(
        f"sqlite:///{tmp_path / 'concurrency.db'}",
        connect_args={"timeout": 30},
    )
    models.User.metadata.create_all(engine)
    concurrent_sessions = sessionmaker(bind=engine)
    with concurrent_sessions.begin() as session:
        session.add_all(
            [
                models.User(username="alice", pass_hash="unused", created_time=1.0),
                models.Folder(id="/", name="/", inherit=False),
            ]
        )

    def create_pending(number):
        with concurrent_sessions() as session, risk_control_transaction(session):
            decision = _check(
                creation_limits,
                session,
                now=1000.0 + number,
                bypass_rate_limit=True,
            )
            if not decision.allowed:
                return False
            document = models.Document(
                id=f"concurrent-document-{number}",
                title=f"concurrent-{number}",
                folder_id="/",
            )
            document.metadata_record = models.DocumentMetadata(
                creator_username="alice",
                last_modified_by_username="alice",
            )
            file = models.File(
                id=f"concurrent-file-{number}", path=f"concurrent-{number}"
            )
            revision = models.DocumentRevision(
                id=f"concurrent-revision-{number}", document=document, file=file
            )
            document.current_revision = revision
            task = models.FileTask(
                id=f"concurrent-task-{number}",
                file=file,
                mode=models.TransferMode.UPLOAD,
                status=models.FileTaskStatus.PENDING,
                start_time=1.0,
                end_time=2000.0,
            )
            session.add_all([document, file, revision, task])
            return True

    with ThreadPoolExecutor(max_workers=4) as executor:
        allowed = list(executor.map(create_pending, range(4)))

    assert sum(allowed) == upload_policy.max_pending_documents_per_creator
    with concurrent_sessions() as session:
        assert creation_limits.count_pending_documents(session, "alice", 1004.0) == 2
    engine.dispose()
