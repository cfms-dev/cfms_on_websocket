import os
from pathlib import Path

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

PROJECT_ROOT = Path(__file__).resolve().parents[3]

pytestmark = pytest.mark.skipif(
    "CFMS_TEST_MYSQL_URL" not in os.environ,
    reason="CFMS_TEST_MYSQL_URL is required for MySQL rate limit tests",
)


@pytest.mark.integration
def test_record_ip_account_refreshes_row_created_after_snapshot():
    from include.database.models.operations import RiskIPAccount
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
        RiskIPAccount.__table__.drop(engine, checkfirst=True)
        engine.dispose()
