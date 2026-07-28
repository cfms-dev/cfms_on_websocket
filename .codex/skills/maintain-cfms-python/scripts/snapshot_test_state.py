#!/usr/bin/env python3
"""Create a non-destructive snapshot of CFMS runtime state before pytest."""

import argparse
import contextlib
import datetime as dt
import os
import shutil
import sqlite3
import tempfile
import uuid
from pathlib import Path


def find_project_root(explicit_root: Path | None) -> Path:
    candidates = [explicit_root.resolve()] if explicit_root is not None else []
    candidates.extend((Path.cwd().resolve(), *Path(__file__).resolve().parents))
    for candidate in candidates:
        if (candidate / "pyproject.toml").is_file() and (candidate / "src").is_dir():
            return candidate
    raise SystemExit("Could not find the CFMS project root; pass --project-root.")


def snapshot_database(source_path: Path, destination_path: Path) -> None:
    source_uri = f"{source_path.resolve().as_uri()}?mode=ro"
    with (
        contextlib.closing(sqlite3.connect(source_uri, uri=True, timeout=30)) as source,
        contextlib.closing(sqlite3.connect(destination_path)) as destination,
    ):
        source.backup(destination)
        result = destination.execute("PRAGMA quick_check").fetchone()
        if result != ("ok",):
            raise RuntimeError(f"SQLite snapshot failed quick_check: {result!r}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Snapshot app.db and test-deleted runtime files without modifying the project."
        )
    )
    parser.add_argument("--project-root", type=Path)
    parser.add_argument(
        "--output-root",
        type=Path,
        default=Path(tempfile.gettempdir()) / "cfms-test-snapshots",
        help="Parent directory for the new unique snapshot directory.",
    )
    args = parser.parse_args()

    project_root = find_project_root(args.project_root)
    source_dir = project_root / "src"
    timestamp = dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%S.%fZ")
    snapshot_dir = args.output_root.resolve() / f"{timestamp}-{uuid.uuid4().hex[:8]}"
    snapshot_dir.mkdir(parents=True, mode=0o700)

    copied: list[str] = []
    database_path = source_dir / "app.db"
    if database_path.is_file():
        snapshot_database(database_path, snapshot_dir / "app.db")
        copied.append("app.db (consistent SQLite backup, including committed WAL data)")

    for filename in ("config.toml", "init", "admin_password.txt"):
        source_path = source_dir / filename
        if source_path.is_file():
            destination_path = snapshot_dir / filename
            shutil.copy2(source_path, destination_path)
            try:
                os.chmod(destination_path, 0o600)
            except OSError:
                pass
            copied.append(filename)

    if not copied:
        print(f"Created empty snapshot directory: {snapshot_dir}")
        print("No current CFMS runtime files were present.")
        return

    print(f"Snapshot created: {snapshot_dir}")
    for item in copied:
        print(f"- {item}")
    print("Treat this directory as sensitive; restoration is intentionally manual.")


if __name__ == "__main__":
    main()
