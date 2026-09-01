"""Absolute paths for the flat CFMS server tree."""

from pathlib import Path

__all__ = ["APPLICATION_ABSPATH", "EXTENSION_ROOT", "PROJECT_ABSPATH"]

APPLICATION_ABSPATH = Path(__file__).resolve().parents[2]
PROJECT_ABSPATH = APPLICATION_ABSPATH.parent
EXTENSION_ROOT = APPLICATION_ABSPATH / "include" / "extensions"
