from types import SimpleNamespace
from typing import Any, cast

import pytest
from sqlalchemy import Integer, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

from include.database.cursors import (
    DEFAULT_KEYSET_WINDOW_SIZES,
    StreamingCursorBatchStrategy,
    WindowedKeysetBatchStrategy,
    default_keyset_batch_strategy,
)


class _CursorBase(DeclarativeBase):
    pass


class _CursorRow(_CursorBase):
    __tablename__ = "cursor_test_rows"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)


@pytest.mark.unit
@pytest.mark.parametrize(
    ("dialect_name", "expected_cls"),
    [
        ("sqlite", StreamingCursorBatchStrategy),
        ("postgresql", WindowedKeysetBatchStrategy),
        ("mysql", WindowedKeysetBatchStrategy),
        (None, WindowedKeysetBatchStrategy),
    ],
)
def test_default_keyset_batch_strategy_selects_by_dialect(
    dialect_name: str | None,
    expected_cls: type[StreamingCursorBatchStrategy | WindowedKeysetBatchStrategy],
):
    bind = (
        SimpleNamespace(dialect=SimpleNamespace(name=dialect_name))
        if dialect_name is not None
        else None
    )
    fake_session = cast(Session, SimpleNamespace(get_bind=lambda: bind))

    strategy = default_keyset_batch_strategy(fake_session)
    assert isinstance(strategy, expected_cls)
    if isinstance(strategy, WindowedKeysetBatchStrategy):
        assert strategy.window_sizes == DEFAULT_KEYSET_WINDOW_SIZES


@pytest.mark.unit
def test_windowed_keyset_batch_strategy_rejects_empty_window_sizes():
    strategy = WindowedKeysetBatchStrategy(window_sizes=())
    fake_session = cast(Session, SimpleNamespace())

    with pytest.raises(ValueError, match="window_sizes"):
        next(
            strategy.iter_batches(
                fake_session,
                build_select=lambda _key, _limit: select(_CursorRow.id),
                cursor_key_of=lambda row: [row["id"]],
                initial_last_key=None,
            )
        )


@pytest.mark.component
@pytest.mark.parametrize(
    ("row_count", "expected_batches", "expected_limits"),
    [
        (7, [[1, 2], [3, 4, 5], [6, 7]], [2, 3, 3]),
        (5, [[1, 2], [3, 4, 5]], [2, 3, 3]),
        (0, [], [2]),
    ],
)
def test_windowed_keyset_batch_strategy_escalates_windows_and_advances_key(
    sqlite_engine_factory,
    row_count: int,
    expected_batches: list[list[int]],
    expected_limits: list[int],
):
    engine = sqlite_engine_factory(":memory:")
    _CursorBase.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    with factory.begin() as session:
        session.add_all([_CursorRow(id=i) for i in range(1, row_count + 1)])

    requested_limits: list[int | None] = []
    strategy = WindowedKeysetBatchStrategy(window_sizes=(2, 3))

    def _build_select(last_key: list[Any] | None, limit: int | None):
        requested_limits.append(limit)
        stmt = select(_CursorRow.id).order_by(_CursorRow.id.asc())
        if last_key is not None:
            stmt = stmt.where(_CursorRow.id > last_key[0])
        if limit is not None:
            stmt = stmt.limit(limit)
        return stmt

    with factory() as session:
        batches = [
            [row["id"] for row in batch]
            for batch in strategy.iter_batches(
                session,
                build_select=_build_select,
                cursor_key_of=lambda row: [row["id"]],
                initial_last_key=None,
            )
        ]

    assert batches == expected_batches
    assert requested_limits == expected_limits
