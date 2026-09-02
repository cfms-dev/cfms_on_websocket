Create and stamp an empty database during first server initialization without
blocking normal startup on an Alembic revision check. Keep SQLite/MySQL upgrades
and rejection of non-empty unversioned databases in the maintenance tool.
