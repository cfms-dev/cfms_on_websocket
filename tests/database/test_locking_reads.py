import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
from sqlalchemy import event, select, update
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

from include.database.models.documents import Document, EntityStatus, Folder
from include.database.session import Base, Session

pytestmark = pytest.mark.component


class _LockingBase(DeclarativeBase):
    pass


class _Item(_LockingBase):
    __tablename__ = "locking_items"

    id: Mapped[int] = mapped_column(primary_key=True)
    value: Mapped[int]


@pytest.fixture
def locking_database(sqlite_engine_factory, tmp_path):
    database = sqlite_engine_factory(tmp_path / "locking.db", timeout_seconds=5)
    _LockingBase.metadata.create_all(database)
    factory = sessionmaker(bind=database)
    with factory.begin() as session:
        session.add(_Item(id=1, value=0))
    return database, factory


@pytest.mark.parametrize("query", ["get", "select"])
@pytest.mark.parametrize("release", ["commit", "rollback", "close"])
def test_locking_read_excludes_writers_until_transaction_ends(
    locking_database, query, release
):
    database, factory = locking_database
    with factory() as session, database.connect() as competitor:
        if query == "get":
            item = session.get(_Item, 1, with_for_update=True)
        else:
            item = session.scalar(select(_Item).where(_Item.id == 1).with_for_update())
        assert item is not None
        competitor.exec_driver_sql("PRAGMA busy_timeout=0")
        with pytest.raises(OperationalError) as failure:
            competitor.execute(update(_Item).where(_Item.id == 1).values(value=2))
        assert failure.value.orig.sqlite_errorcode == sqlite3.SQLITE_BUSY
        competitor.rollback()

        item.value = 1
        session.flush()
        assert competitor.scalar(select(_Item.value).where(_Item.id == 1)) == 0
        competitor.rollback()
        if release == "commit":
            session.commit()
        elif release == "rollback":
            session.rollback()
        else:
            session.close()

        assert competitor.scalar(select(_Item.value).where(_Item.id == 1)) == (
            1 if release == "commit" else 0
        )
        competitor.execute(update(_Item).where(_Item.id == 1).values(value=2))
        competitor.commit()
    with factory() as session:
        assert session.get(_Item, 1).value == 2


def test_plain_read_transaction_does_not_reserve_sqlite_writer(locking_database):
    _database, factory = locking_database
    with factory.begin() as reader, factory.begin() as writer:
        original = reader.get(_Item, 1)
        writer.get(_Item, 1).value = 1
        writer.flush()
        assert original.value == 0
        assert not reader.connection().connection.driver_connection.in_transaction
    with factory() as session:
        assert session.get(_Item, 1).value == 1


@pytest.mark.parametrize("query", ["get", "select"])
def test_locking_read_refreshes_previously_loaded_state(locking_database, query):
    _database, factory = locking_database
    with factory.begin() as reader:
        original = reader.get(_Item, 1)
        with factory.begin() as writer:
            writer.get(_Item, 1).value = 1
        if query == "get":
            locked = reader.get(_Item, 1, with_for_update=True, populate_existing=True)
        else:
            locked = reader.scalar(
                select(_Item)
                .where(_Item.id == 1)
                .with_for_update()
                .execution_options(populate_existing=True)
            )
        assert locked is original
        assert locked.value == 1
        assert reader.connection().connection.driver_connection.in_transaction


@pytest.mark.parametrize("flushed", [False, True])
def test_locking_read_reuses_write_transaction_and_autoflushes(
    locking_database, flushed
):
    _database, factory = locking_database
    with factory.begin() as session:
        original = session.get(_Item, 1)
        original.value = 1
        if flushed:
            session.flush()
        locked = session.scalar(select(_Item).where(_Item.id == 1).with_for_update())
        assert locked is original
        assert locked.value == 1
        assert session.scalar(select(_Item.value).where(_Item.id == 1)) == 1
        assert session.get(_Item, 1, with_for_update=True) is original
    with factory() as session:
        assert session.get(_Item, 1).value == 1


@pytest.mark.parametrize("rollback_outer", [False, True])
def test_locking_read_inside_savepoint_respects_outer_transaction(
    locking_database, rollback_outer
):
    _database, factory = locking_database
    with factory() as session:
        session.begin()
        with session.begin_nested():
            item = session.get(_Item, 1, with_for_update=True)
            item.value = 1
        if rollback_outer:
            session.rollback()
        else:
            session.commit()
    with factory() as session:
        assert session.get(_Item, 1).value == (0 if rollback_outer else 1)


def test_exception_after_savepoint_release_rolls_back_changes(locking_database):
    _database, factory = locking_database

    def change_then_abort():
        with factory.begin() as session:
            with session.begin_nested():
                session.get(_Item, 1, with_for_update=True).value = 1
            raise ValueError("Abort outer transaction")

    with pytest.raises(ValueError, match="Abort outer transaction"):
        change_then_abort()
    with factory() as session:
        assert session.get(_Item, 1).value == 0


def test_waiting_locking_read_observes_committed_state(locking_database):
    database, factory = locking_database
    waiting = threading.Event()

    @event.listens_for(database, "before_cursor_execute")
    def observe_lock(_conn, _cursor, statement, _params, _context, _many):
        if (
            threading.current_thread() is not threading.main_thread()
            and statement == "BEGIN IMMEDIATE"
        ):
            waiting.set()

    def read_locked_value():
        with factory.begin() as session:
            return session.get(_Item, 1, with_for_update=True).value

    try:
        with factory() as holder, ThreadPoolExecutor(max_workers=1) as workers:
            item = holder.get(_Item, 1, with_for_update=True)
            item.value = 1
            holder.flush()
            result = workers.submit(read_locked_value)
            try:
                assert waiting.wait(3)
            finally:
                holder.commit()
            assert result.result(timeout=5) == 1
    finally:
        event.remove(database, "before_cursor_execute", observe_lock)


def test_reused_connection_does_not_keep_transaction_or_lock(
    sqlite_engine_factory, tmp_path
):
    database = sqlite_engine_factory(tmp_path / "reuse.db")
    _LockingBase.metadata.create_all(database)
    factory = sessionmaker(bind=database)
    with factory.begin() as session:
        session.add(_Item(id=1, value=0))
    with factory() as session:
        original_connection = session.connection().connection.driver_connection
        session.get(_Item, 1, with_for_update=True).value = 1
        session.flush()
    with factory.begin() as session:
        reused_connection = session.connection().connection.driver_connection
        assert reused_connection is original_connection
        assert not reused_connection.in_transaction
        assert session.get(_Item, 1).value == 0
        session.get(_Item, 1, with_for_update=True).value = 2
    with factory() as session:
        assert session.get(_Item, 1).value == 2


def test_locking_reads_preserve_soft_delete_filter(sqlite_engine_factory, tmp_path):
    database = sqlite_engine_factory(tmp_path / "filtered.db")
    Base.metadata.create_all(database)
    with Session(bind=database) as session, session.begin():
        root = Folder(id="/", name="/")
        session.add_all(
            [
                root,
                Document(id="live", title="Live", folder=root),
                Document(
                    id="deleted",
                    title="Deleted",
                    folder=root,
                    status=EntityStatus.DELETED,
                ),
            ]
        )
    with Session(bind=database) as session:
        visible = session.scalars(select(Document).with_for_update()).all()
        assert [document.id for document in visible] == ["live"]
        all_documents = session.scalars(
            select(Document).with_for_update().execution_options(include_deleted=True)
        ).all()
        assert {document.id for document in all_documents} == {"live", "deleted"}
