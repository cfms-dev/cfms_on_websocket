import sys
from pathlib import Path
from shutil import copyfile

import pytest
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import sessionmaker

PROJECT_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def creation_limit_context(monkeypatch, tmp_path):
    copyfile(PROJECT_ROOT / "src" / "config.toml.sample", tmp_path / "config.toml")
    monkeypatch.chdir(tmp_path)
    src_path = str(PROJECT_ROOT / "src")
    if src_path not in sys.path:
        sys.path.insert(0, src_path)

    from include.config.validation import DocumentUploadPolicy
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
    policy = DocumentUploadPolicy(
        max_pending_documents_per_creator=2,
        creation_rate_window_seconds=600,
        creation_rate_per_user=2,
        creation_rate_per_ip=10,
    )
    monkeypatch.setattr(
        creation_limits.DocumentUploadPolicy,
        "from_config",
        classmethod(lambda _cls: policy),
    )
    yield creation_limits, models, session_factory, policy
    engine.dispose()


def test_account_creation_rate_uses_fixed_window(creation_limit_context):
    creation_limits, models, session_factory, _policy = creation_limit_context

    with session_factory.begin() as session:
        assert creation_limits.check_document_creation_limits(
            session, "alice", "203.0.113.1", now=100.0
        ).allowed
    with session_factory.begin() as session:
        assert creation_limits.check_document_creation_limits(
            session, "alice", "203.0.113.1", now=101.0
        ).allowed
    with session_factory.begin() as session:
        decision = creation_limits.check_document_creation_limits(
            session, "alice", "203.0.113.1", now=102.0
        )

    assert decision.allowed is False
    assert decision.scope == "account"
    assert decision.limit == 2
    assert decision.retry_after_seconds == 598

    with session_factory.begin() as session:
        assert creation_limits.check_document_creation_limits(
            session, "alice", "203.0.113.1", now=700.0
        ).allowed
        row = session.scalar(
            select(models.DocumentCreationThrottle).where(
                models.DocumentCreationThrottle.scope == "account",
                models.DocumentCreationThrottle.identity == "alice",
            )
        )
        assert row.attempts == 1


def test_pending_document_limit_uses_creator_and_live_uploads(
    creation_limit_context, monkeypatch
):
    creation_limits, models, session_factory, policy = creation_limit_context
    monkeypatch.setattr(
        creation_limits.DocumentUploadPolicy,
        "from_config",
        classmethod(
            lambda _cls: type(policy)(
                max_pending_documents_per_creator=2,
                creation_rate_window_seconds=600,
                creation_rate_per_user=100,
                creation_rate_per_ip=100,
            )
        ),
    )

    with session_factory.begin() as session:
        user = models.User(
            username="alice",
            pass_hash="unused",
            created_time=1.0,
        )
        root = models.Folder(id="/", name="/", inherit=False)
        session.add_all([user, root])
        for number in range(2):
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
                end_time=1000.0,
            )
            session.add_all([document, file, revision, task])

    with session_factory.begin() as session:
        decision = creation_limits.check_document_creation_limits(
            session, "alice", "203.0.113.1", now=100.0
        )
    assert decision.allowed is False
    assert decision.scope == "pending_documents"
    assert decision.limit == 2
    assert decision.retry_after_seconds == 900

    with session_factory.begin() as session:
        session.get(models.FileTask, "task-0").status = models.FileTaskStatus.COMPLETED
    with session_factory.begin() as session:
        assert creation_limits.check_document_creation_limits(
            session, "alice", "203.0.113.1", now=101.0
        ).allowed
