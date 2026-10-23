import subprocess
import sys
from pathlib import Path

import pytest
from sqlalchemy import Column, Integer, MetaData, Table, inspect
from sqlalchemy.engine.reflection import Inspector

from include.database.session import Base
from include.extensions.data import (
    ExtensionDataError,
    ExtensionDataTable,
    extension_metadata,
    load_extension_data,
    prepare_extension_tables,
)
from include.extensions.manager import ExtensionManifestError, parse_extension_manifest
from tests.support.extension_data import example_data

pytestmark = pytest.mark.component

__all__ = ["example_data"]


def test_data_entrypoint_is_independent_and_orders_foreign_keys(example_data):
    declarations = load_extension_data(Base.metadata)
    assert tuple(declarations) == ("example_parent", "example_child")
    assert "example_parent" not in Base.metadata.tables
    assert "example_child" not in Base.metadata.tables


@pytest.mark.parametrize("conflict", ["owner", "duplicate", "core"])
def test_data_ownership_conflicts_are_rejected(example_data, conflict):
    declarations, _manifest = example_data
    if conflict == "owner":
        declarations[:] = [ExtensionDataTable("another", declarations[0].table)]
    elif conflict == "duplicate":
        declarations.append(declarations[0])
    else:
        declarations[:] = [ExtensionDataTable("example", Base.metadata.tables["users"])]
    with pytest.raises(ExtensionDataError, match="ownership"):
        load_extension_data(Base.metadata)


def test_invalid_data_entrypoint_is_rejected(example_data):
    _declarations, manifest = example_data
    manifest.write_text(
        manifest.read_text(encoding="utf-8").replace(
            'module = "example_extension_data"', 'module = "../runtime.py"'
        ),
        encoding="utf-8",
    )
    with pytest.raises(ExtensionManifestError, match="data.module"):
        parse_extension_manifest(manifest)


def test_schema_preparation_creates_only_extension_tables(
    example_data, sqlite_engine_factory
):
    engine = sqlite_engine_factory()
    declarations = load_extension_data(Base.metadata)
    metadata = extension_metadata(Base.metadata, declarations)
    with engine.begin() as connection:
        prepare_extension_tables(connection, metadata, set(declarations))
        connection.execute(metadata.tables["example_parent"].insert(), {"id": 1})
        prepare_extension_tables(connection, metadata, set(declarations))
        assert connection.execute(metadata.tables["example_parent"].select()).all() == [
            (1,)
        ]
    assert set(inspect(engine).get_table_names()) == set(declarations)


def test_incompatible_existing_extension_table_is_rejected(
    example_data, sqlite_engine_factory
):
    engine = sqlite_engine_factory()
    Table(
        "example_parent", MetaData(), Column("wrong", Integer, primary_key=True)
    ).create(engine)
    declarations = load_extension_data(Base.metadata)
    with (
        engine.begin() as connection,
        pytest.raises(ExtensionDataError, match="Incompatible"),
    ):
        prepare_extension_tables(
            connection,
            extension_metadata(Base.metadata, declarations),
            set(declarations),
        )
    assert inspect(engine).get_table_names() == ["example_parent"]


def test_schema_preparation_accepts_foreign_keys_without_optional_options(
    example_data, sqlite_engine_factory, monkeypatch
):
    engine = sqlite_engine_factory()
    declarations = load_extension_data(Base.metadata)
    metadata = extension_metadata(Base.metadata, declarations)
    get_foreign_keys = Inspector.get_foreign_keys

    def reflect_without_options(self, table_name, *args, **kwargs):
        return [
            {key: value for key, value in foreign_key.items() if key != "options"}
            for foreign_key in get_foreign_keys(self, table_name, *args, **kwargs)
        ]

    with engine.begin() as connection:
        prepare_extension_tables(connection, metadata, set(declarations))
        connection.execute(metadata.tables["example_parent"].insert(), {"id": 1})
        connection.execute(
            metadata.tables["example_child"].insert(),
            {"id": 2, "parent_id": 1, "value": b"preserved"},
        )
        monkeypatch.setattr(Inspector, "get_foreign_keys", reflect_without_options)

        prepare_extension_tables(connection, metadata, set(declarations), create=False)

        assert connection.execute(metadata.tables["example_child"].select()).all() == [
            (2, 1, b"preserved")
        ]


def test_oidc_data_import_does_not_require_network_dependencies(protected_test_config):
    source = Path(__file__).resolve().parents[2] / "src"
    script = """
import sys
import importlib.abc

class BlockNetworkImports(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split(".")[0] in {"authlib", "requests"}:
            raise AssertionError(fullname)

sys.meta_path.insert(0, BlockNetworkImports())
import include.database.models
from include.database.session import Base
from include.extensions.data import load_extension_data
declarations = load_extension_data(Base.metadata)
assert "user_oidc_credentials" in declarations
assert "user_oidc_credentials" not in Base.metadata.tables
assert "include.extensions.oidc_sso._extension" not in sys.modules
assert "oidc_sso" not in sys.modules
"""
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            f"import sys; sys.path.insert(0, {str(source)!r})\n" + script,
        ],
        cwd=protected_test_config.src_dir,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
