from typing import Any, Self

from sqlalchemy import event
from sqlalchemy.orm import (
    DeclarativeBase,
    ORMExecuteState,
    sessionmaker,
    with_loader_criteria,
)
from sqlalchemy.orm import (
    Session as _Session,
)

from include.config.settings import global_config
from include.database.engine import create_database_engine

__all__ = ["Base", "Session", "engine"]

debug_enabled = global_config["debug"]
engine = create_database_engine(global_config["database"], echo=debug_enabled)

Session = sessionmaker(bind=engine)


@event.listens_for(Session, "do_orm_execute")
def _add_filtering_criteria(execute_state: ORMExecuteState) -> None:
    if (
        execute_state.is_select
        and not execute_state.is_column_load
        and not execute_state.execution_options.get("include_deleted", False)
    ):
        from include.database.models.documents import Document, EntityStatus, Folder

        execute_state.statement = execute_state.statement.options(
            with_loader_criteria(Folder, Folder.status != EntityStatus.DELETED),
            with_loader_criteria(Document, Document.status != EntityStatus.DELETED),
        )


class Base(DeclarativeBase):
    @classmethod
    def get_existing(cls, session: _Session, ident: Any) -> Self:
        obj = session.get(cls, ident)
        if obj is None:
            raise LookupError(f"{cls.__name__} with ID {ident} not found")
        return obj


Base.metadata.naming_convention = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(column_0_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}
