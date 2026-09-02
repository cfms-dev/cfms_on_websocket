"""Absolute paths for the flat CFMS server tree."""

from pathlib import Path

__all__ = ["EXECUTABLE_ABSPATH", "EXTENSION_ROOT", "PROJECT_ABSPATH"]

EXECUTABLE_ABSPATH = Path(__file__).resolve().parents[2]
"""Executable absolute path, i.e. the root of the CFMS server tree."""

PROJECT_ABSPATH = EXECUTABLE_ABSPATH.parent
EXTENSION_ROOT = EXECUTABLE_ABSPATH / "include" / "extensions"
