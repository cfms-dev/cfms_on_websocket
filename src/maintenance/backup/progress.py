from dataclasses import dataclass, field

from rich.progress import Progress, TaskID

EXPORT_PROGRESS_STEPS = 6


IMPORT_PROGRESS_STEPS = 9


@dataclass
class _BackupProgressReporter:
    progress: Progress | None
    show_details: bool = False
    overall_task_id: TaskID | None = None
    detail_task_ids: dict[str, TaskID] = field(default_factory=dict)

    def update_overall(
        self,
        *,
        message: str,
        current_step: int,
        total_steps: int,
        detail: str | None = None,
    ) -> None:
        if self.progress is None:
            return

        description = _format_progress_description(message, detail)
        if self.overall_task_id is None:
            self.overall_task_id = self.progress.add_task(
                description,
                total=total_steps,
                completed=0,
            )
        self.progress.update(
            self.overall_task_id,
            total=total_steps,
            completed=current_step,
            description=description,
            refresh=True,
        )

    def update_detail(
        self,
        *,
        phase: str,
        message: str,
        detail: str | None = None,
        completed_units: int | None = None,
        total_units: int | None = None,
    ) -> None:
        if self.progress is None or not self.show_details:
            return

        description = _format_progress_description(message, detail)
        task_id = self.detail_task_ids.get(phase)
        if task_id is None:
            task_id = self.progress.add_task(
                description,
                total=total_units,
                completed=0,
            )
            self.detail_task_ids[phase] = task_id

        self.progress.update(
            task_id,
            total=total_units,
            completed=completed_units,
            description=description,
            refresh=True,
        )


def _emit_progress(
    progress_reporter: _BackupProgressReporter | None,
    *,
    phase: str,
    message: str,
    current_step: int,
    total_steps: int,
    detail: str | None = None,
    completed_units: int | None = None,
    total_units: int | None = None,
    verbose_only: bool = False,
) -> None:
    if progress_reporter is None:
        return
    if verbose_only:
        progress_reporter.update_detail(
            phase=phase,
            message=message,
            detail=detail,
            completed_units=completed_units,
            total_units=total_units,
        )
        return
    progress_reporter.update_overall(
        message=message,
        current_step=current_step,
        total_steps=total_steps,
        detail=detail,
    )


def _format_progress_description(message: str, detail: str | None = None) -> str:
    if detail:
        return f"{message}: {detail}"
    return message
