from typing import TYPE_CHECKING

from maintenance.operations.database.tables import APPLICATION_TABLE_NAMES

if TYPE_CHECKING:
    from rich.progress import Progress, TaskID


def add_progress_task(progress: Progress | None) -> TaskID | None:
    if progress is None:
        return None
    return progress.add_task(
        "Migrating database tables",
        total=len(APPLICATION_TABLE_NAMES) * 2,
    )


def update_progress(
    progress: Progress | None,
    task_id: TaskID | None,
    description: str,
) -> None:
    if progress is not None and task_id is not None:
        progress.update(task_id, description=description)


def advance_progress(
    progress: Progress | None,
    task_id: TaskID | None,
) -> None:
    if progress is not None and task_id is not None:
        progress.advance(task_id)
