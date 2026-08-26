import os
import shutil
import sys
from pathlib import Path

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

PROJECT_ROOT = Path(__file__).resolve().parents[3]

pytestmark = pytest.mark.skipif(
    "CFMS_TEST_MYSQL_URL" not in os.environ,
    reason="CFMS_TEST_MYSQL_URL is required for MySQL rate limit tests",
)


def test_record_ip_account_refreshes_row_created_after_snapshot(monkeypatch, tmp_path):
    shutil.copy(PROJECT_ROOT / "src" / "config.toml.sample", tmp_path / "config.toml")
    (tmp_path / "init").write_text("", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    src_path = str(PROJECT_ROOT / "src")
    if src_path not in sys.path:
        sys.path.insert(0, src_path)

    from include.database.models.operations import RiskIPAccount
    from include.database.session import global_config
    from include.domains.security.guards.rate_limits import record_ip_account

    engine = create_engine(
        os.environ["CFMS_TEST_MYSQL_URL"], isolation_level="REPEATABLE READ"
    )
    RiskIPAccount.__table__.drop(engine, checkfirst=True)
    RiskIPAccount.__table__.create(engine)
    session_factory = sessionmaker(bind=engine)
    identity = ("download_transfer", "117.173.139.116", "HUMANITY")

    try:
        with session_factory() as stale_session, stale_session.begin():
            assert stale_session.get(RiskIPAccount, identity) is None
            with session_factory.begin() as concurrent_session:
                concurrent_session.add(
                    RiskIPAccount(
                        namespace=identity[0],
                        ip_address=identity[1],
                        username=identity[2],
                        last_attempt=1.0,
                    )
                )

            record_ip_account(stale_session, *identity, now=2.0)

        with session_factory() as session:
            rows = session.scalars(select(RiskIPAccount)).all()
            assert len(rows) == 1
            assert rows[0].last_attempt == 2.0
    finally:
        global_config.stop()
        RiskIPAccount.__table__.drop(engine, checkfirst=True)
        engine.dispose()
