import sys
from types import ModuleType

import pytest
from sqlalchemy import Column, ForeignKey, Integer, LargeBinary, MetaData, Table

from include.config import paths
from include.extensions.data import ExtensionDataTable


def encode_example(row):
    return {**row, "value": row["value"].hex()}


def decode_example(row):
    return {**row, "value": bytes.fromhex(row["value"])}


def validate_example(row):
    if not row["value"]:
        raise ValueError("Example data cannot be empty")


@pytest.fixture
def example_data(monkeypatch, tmp_path):
    root = tmp_path / "extensions"
    directory = root / "example"
    directory.mkdir(parents=True)
    (directory / "_extension.py").write_text(
        'raise AssertionError("Runtime entrypoint must not be loaded")',
        encoding="utf-8",
    )
    manifest = directory / "manifest.toml"
    manifest.write_text(
        """manifest_version = 2
[extension]
identifier = "example"
name = "Example"
version = "1.0.0"
authors = ["Tests"]
license = "MIT"
[data]
module = "example_extension_data"
""",
        encoding="utf-8",
    )
    metadata = MetaData()
    parent = Table("example_parent", metadata, Column("id", Integer, primary_key=True))
    child = Table(
        "example_child",
        metadata,
        Column("id", Integer, primary_key=True),
        Column("parent_id", ForeignKey(parent.c.id), nullable=False),
        Column("value", LargeBinary(32), nullable=False),
    )
    declarations = [
        ExtensionDataTable(
            "example",
            child,
            "accounts",
            encode_example,
            decode_example,
            validate_example,
        ),
        ExtensionDataTable("example", parent, "accounts"),
    ]
    module = ModuleType("example_extension_data")
    module.register_data = lambda: tuple(declarations)
    monkeypatch.setitem(sys.modules, module.__name__, module)
    monkeypatch.setattr(paths, "EXTENSION_ROOT", root)
    return declarations, manifest
