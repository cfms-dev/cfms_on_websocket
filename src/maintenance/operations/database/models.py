from dataclasses import dataclass


class DatabaseMigrationError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class TableMigrationResult:
    name: str
    rows: int
    sha256: str


@dataclass(frozen=True, slots=True)
class DatabaseMigrationResult:
    source_dialect: str
    target_dialect: str
    tables: tuple[TableMigrationResult, ...]
    elapsed_seconds: float

    @property
    def row_count(self) -> int:
        return sum(table.rows for table in self.tables)
