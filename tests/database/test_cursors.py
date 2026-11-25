from contextlib import closing
from types import SimpleNamespace
from typing import Any, cast

import pytest
from pydantic import ValidationError
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
@pytest.mark.parametrize(
    ("window_sizes", "expected_error_type"),
    [
        ((), "too_short"),
        ((0,), "greater_than"),
        ((-1,), "greater_than"),
        ((2, 0), "greater_than"),
        ((True,), "int_type"),
    ],
)
def test_windowed_keyset_batch_strategy_rejects_invalid_window_sizes(
    window_sizes: tuple[Any, ...],
    expected_error_type: str,
):
    with pytest.raises(ValidationError) as exc:
        WindowedKeysetBatchStrategy(window_sizes=window_sizes)

    assert exc.value.errors()[0]["type"] == expected_error_type


@pytest.mark.unit
@pytest.mark.parametrize(
    ("chunk_size", "expected_error_type"),
    [
        (0, "greater_than"),
        (-1, "greater_than"),
        (True, "int_type"),
    ],
)
def test_streaming_cursor_batch_strategy_rejects_non_positive_chunk_size(
    chunk_size: Any,
    expected_error_type: str,
):
    with pytest.raises(ValidationError) as exc:
        StreamingCursorBatchStrategy(chunk_size=chunk_size)

    assert exc.value.errors()[0]["type"] == expected_error_type


def _seed_cursor_rows(sqlite_engine_factory, row_count: int):
    engine = sqlite_engine_factory(":memory:")
    _CursorBase.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    with factory.begin() as session:
        session.add_all([_CursorRow(id=i) for i in range(1, row_count + 1)])
    return factory


@pytest.mark.component
@pytest.mark.parametrize(
    ("row_count", "initial_last_key", "expected_batches", "expected_limits"),
    [
        (7, None, [[1, 2], [3, 4, 5], [6, 7]], [2, 3, 3]),
        (5, None, [[1, 2], [3, 4, 5]], [2, 3, 3]),
        (7, [3], [[4, 5], [6, 7]], [2, 3]),
        (0, None, [], [2]),
    ],
)
def test_windowed_keyset_batch_strategy_escalates_windows_and_advances_key(
    sqlite_engine_factory,
    row_count: int,
    initial_last_key: list[Any] | None,
    expected_batches: list[list[int]],
    expected_limits: list[int],
):
    factory = _seed_cursor_rows(sqlite_engine_factory, row_count)
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

    with (
        factory() as session,
        closing(
            strategy.iter_batches(
                session,
                build_select=_build_select,
                cursor_key_of=lambda row: [row["id"]],
                initial_last_key=initial_last_key,
            )
        ) as gen,
    ):
        batches = [[row["id"] for row in batch] for batch in gen]

    assert batches == expected_batches
    assert requested_limits == expected_limits


@pytest.mark.component
@pytest.mark.parametrize(
    ("row_count", "chunk_size", "initial_last_key", "expected_batches"),
    [
        (0, 2, None, []),
        (4, 2, None, [[1, 2], [3, 4]]),
        (5, 2, None, [[1, 2], [3, 4], [5]]),
        (6, 2, [2], [[3, 4], [5, 6]]),
    ],
)
def test_streaming_cursor_batch_strategy_fetches_chunks_and_supports_early_close(
    sqlite_engine_factory,
    row_count: int,
    chunk_size: int,
    initial_last_key: list[Any] | None,
    expected_batches: list[list[int]],
):
    factory = _seed_cursor_rows(sqlite_engine_factory, row_count)
    strategy = StreamingCursorBatchStrategy(chunk_size=chunk_size)

    def _build_select(last_key: list[Any] | None, limit: int | None):
        assert limit is None
        stmt = select(_CursorRow.id).order_by(_CursorRow.id.asc())
        if last_key is not None:
            stmt = stmt.where(_CursorRow.id > last_key[0])
        return stmt

    with (
        factory() as session,
        closing(
            strategy.iter_batches(
                session,
                build_select=_build_select,
                cursor_key_of=lambda row: [row["id"]],
                initial_last_key=initial_last_key,
            )
        ) as gen,
    ):
        batches = [[row["id"] for row in batch] for batch in gen]

    assert batches == expected_batches

    # Verify early closing() on both strategies does not raise or leave active cursors.
    with factory() as session:
        if row_count > 0:
            for strat in (
                StreamingCursorBatchStrategy(chunk_size=1),
                WindowedKeysetBatchStrategy(window_sizes=(1,)),
            ):
                with closing(
                    strat.iter_batches(
                        session,
                        build_select=lambda key, lim: (
                            select(_CursorRow.id)
                            .where(_CursorRow.id > key[0] if key is not None else True)
                            .order_by(_CursorRow.id.asc())
                            .limit(lim)
                            if lim is not None
                            else select(_CursorRow.id).order_by(_CursorRow.id.asc())
                        ),
                        cursor_key_of=lambda row: [row["id"]],
                        initial_last_key=None,
                    )
                ) as early_gen:
                    first_batch = next(early_gen)
                    assert len(first_batch) == 1
