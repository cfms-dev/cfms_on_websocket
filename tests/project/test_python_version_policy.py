import ast
import pathlib
import tomllib

PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[2]
PYTHON_SOURCE_ROOTS = (
    PROJECT_ROOT / "src",
    PROJECT_ROOT / "tests",
    PROJECT_ROOT / "tools",
)


def test_project_requires_python_3_14_or_newer():
    with (PROJECT_ROOT / "pyproject.toml").open("rb") as pyproject_file:
        pyproject = tomllib.load(pyproject_file)

    assert pyproject["project"]["requires-python"] == ">=3.14"


def test_python_sources_do_not_enable_postponed_annotations():
    future_annotation_imports = []

    for source_root in PYTHON_SOURCE_ROOTS:
        for source_path in source_root.rglob("*.py"):
            if ".venv" in source_path.parts or source_path.is_relative_to(
                PROJECT_ROOT / "src" / "certtools"
            ):
                continue

            module = ast.parse(source_path.read_text(encoding="utf-8"))
            for node in module.body:
                if not isinstance(node, ast.ImportFrom) or node.module != "__future__":
                    continue
                if any(alias.name == "annotations" for alias in node.names):
                    future_annotation_imports.append(
                        source_path.relative_to(PROJECT_ROOT)
                    )

    assert future_annotation_imports == []
