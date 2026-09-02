"""Absolute paths for the flat CFMS server tree."""

from pathlib import Path

__all__ = ["EXECUTEABLE_ABSPATH", "EXTENSION_ROOT", "PROJECT_ABSPATH"]

EXECUTEABLE_ABSPATH = Path(__file__).resolve().parents[2]
"""Executable absolute path, i.e. the root of the CFMS server tree."""

PROJECT_ABSPATH = EXECUTEABLE_ABSPATH.parent
EXTENSION_ROOT = EXECUTEABLE_ABSPATH / "include" / "extensions"
