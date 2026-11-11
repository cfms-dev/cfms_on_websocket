import re

from sqlalchemy.exc import IntegrityError


def is_unique_constraint_violation(
    exc: IntegrityError,
    *,
    constraint_name: str,
    sqlite_column_sets: tuple[tuple[str, ...], ...],
) -> bool:
    """Identify a specific unique constraint without managing the transaction."""
    original = exc.orig
    sqlstate = getattr(original, "sqlstate", None) or getattr(original, "pgcode", None)
    if sqlstate == "23505":
        diagnostic = getattr(original, "diag", None)
        return getattr(diagnostic, "constraint_name", None) == constraint_name

    error_args = getattr(original, "args", ())
    error_number = getattr(original, "errno", None)
    if error_number is None:
        error_number = error_args[0] if error_args else None
    if error_number == 1062:
        message = getattr(original, "msg", None) or (
            error_args[1] if len(error_args) > 1 else str(original)
        )
        key_match = re.search(
            r"\bfor key (?P<quote>['\"`])(?P<key>.+?)(?P=quote)\s*$", message
        )
        return (
            key_match is not None
            and key_match["key"].rsplit(".", 1)[-1] == constraint_name
        )

    sqlite_error_name = getattr(original, "sqlite_errorname", None)
    if sqlite_error_name not in {"SQLITE_CONSTRAINT", "SQLITE_CONSTRAINT_UNIQUE"}:
        return False
    message = str(original)
    prefix = "UNIQUE constraint failed:"
    if not message.startswith(prefix):
        return False
    columns = sorted(column.strip() for column in message[len(prefix) :].split(","))
    return any(columns == sorted(candidate) for candidate in sqlite_column_sets)
