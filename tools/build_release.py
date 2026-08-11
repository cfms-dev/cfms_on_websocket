import argparse
import datetime as dt
import gzip
import hashlib
import io
import re
import tarfile
import tomllib
import zipfile
from pathlib import Path, PurePosixPath

VERSION_PATTERN = re.compile(r"\d+\.\d+\.\d+")
ROOT_FILES = (
    "CHANGELOG.md",
    "README.md",
    "SECURITY.md",
    "pyproject.toml",
    "uv.lock",
)
RUNTIME_FILES = (
    "src/LICENSE",
    "src/alembic.ini",
    "src/config.toml.sample",
    "src/content/hello",
    "src/main.py",
)
RUNTIME_TREES = (
    "src/alembic",
    "src/include",
    "src/maintenance",
    "src/content/ssl/client",
)
FORBIDDEN_PREFIXES = (
    ".codex/",
    ".git/",
    ".github/",
    ".idea/",
    ".venv/",
    ".vscode/",
    "docs/",
    "src/certtools/",
    "tests/",
    "tools/",
)
FORBIDDEN_NAMES = {
    "admin_password.txt",
    "app.db",
    "config.toml",
    "init",
}
CA_CERTIFICATE_PATTERN = re.compile(r"[0-9a-fA-F]{8}\.[0-9]+").fullmatch


def _validate_version(project_root: Path, version: str) -> None:
    if VERSION_PATTERN.fullmatch(version) is None:
        raise ValueError(f"Release version must use X.Y.Z format: {version!r}")

    with (project_root / "pyproject.toml").open("rb") as pyproject_file:
        project_version = tomllib.load(pyproject_file)["project"]["version"]
    if project_version != version:
        raise ValueError(
            f"Release version {version!r} does not match project version "
            f"{project_version!r}"
        )


def _is_ignored_tree_file(relative_path: PurePosixPath) -> bool:
    return any(
        part == ".git" or part == "__pycache__" for part in relative_path.parts
    ) or (
        relative_path.name == ".gitignore" or relative_path.suffix in {".pyc", ".pyo"}
    )


def _collect_release_files(
    project_root: Path,
) -> tuple[tuple[PurePosixPath, Path], ...]:
    files: dict[PurePosixPath, Path] = {}

    for relative_name in (*ROOT_FILES, *RUNTIME_FILES):
        source_path = project_root / relative_name
        if not source_path.is_file():
            raise ValueError(f"Required release file is missing: {relative_name}")
        if source_path.is_symlink():
            raise ValueError(
                f"Release files must not be symbolic links: {relative_name}"
            )
        files[PurePosixPath(relative_name)] = source_path

    for relative_name in RUNTIME_TREES:
        source_root = project_root / relative_name
        if not source_root.is_dir():
            raise ValueError(f"Required release directory is missing: {relative_name}")
        for source_path in sorted(source_root.rglob("*")):
            if not source_path.is_file():
                continue
            relative_path = PurePosixPath(
                source_path.relative_to(project_root).as_posix()
            )
            if _is_ignored_tree_file(relative_path):
                continue
            if source_path.is_symlink():
                raise ValueError(
                    f"Release files must not be symbolic links: {relative_path}"
                )
            files[relative_path] = source_path

    ca_root = PurePosixPath("src/content/ssl/client")
    if not any(
        path.parent == ca_root and CA_CERTIFICATE_PATTERN(path.name) for path in files
    ):
        raise ValueError(
            "The client CA submodule is missing its hashed certificates; "
            "check it out recursively before building a release"
        )

    for relative_path in files:
        path_text = relative_path.as_posix()
        if path_text.startswith(FORBIDDEN_PREFIXES):
            raise ValueError(f"Forbidden path selected for release: {relative_path}")
        if relative_path.name in FORBIDDEN_NAMES or relative_path.suffix in {
            ".db",
            ".key",
            ".log",
        }:
            raise ValueError(
                f"Mutable or sensitive path selected for release: {relative_path}"
            )

    return tuple(sorted(files.items(), key=lambda item: item[0].as_posix()))


def _zip_timestamp(source_date_epoch: int) -> tuple[int, int, int, int, int, int]:
    timestamp = dt.datetime.fromtimestamp(source_date_epoch, dt.UTC)
    if timestamp.year < 1980:
        timestamp = dt.datetime(1980, 1, 1, tzinfo=dt.UTC)
    return (
        timestamp.year,
        timestamp.month,
        timestamp.day,
        timestamp.hour,
        timestamp.minute,
        timestamp.second,
    )


def _write_zip(
    output_path: Path,
    top_level: str,
    files: tuple[tuple[PurePosixPath, Path], ...],
    source_date_epoch: int,
) -> None:
    timestamp = _zip_timestamp(source_date_epoch)
    with zipfile.ZipFile(
        output_path,
        mode="w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
    ) as archive:
        for relative_path, source_path in files:
            archive_path = PurePosixPath(top_level, relative_path).as_posix()
            info = zipfile.ZipInfo(archive_path, date_time=timestamp)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            archive.writestr(info, source_path.read_bytes(), compresslevel=9)


def _write_tar_gz(
    output_path: Path,
    top_level: str,
    files: tuple[tuple[PurePosixPath, Path], ...],
    source_date_epoch: int,
) -> None:
    with (
        output_path.open("wb") as output_file,
        gzip.GzipFile(
            filename="",
            mode="wb",
            compresslevel=9,
            fileobj=output_file,
            mtime=source_date_epoch,
        ) as compressed_file,
        tarfile.open(
            fileobj=compressed_file,
            mode="w",
            format=tarfile.PAX_FORMAT,
        ) as archive,
    ):
        for relative_path, source_path in files:
            contents = source_path.read_bytes()
            archive_path = PurePosixPath(top_level, relative_path).as_posix()
            info = tarfile.TarInfo(archive_path)
            info.size = len(contents)
            info.mtime = source_date_epoch
            info.mode = 0o644
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            archive.addfile(info, io.BytesIO(contents))


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as artifact:
        for chunk in iter(lambda: artifact.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_release(
    project_root: Path,
    output_dir: Path,
    version: str,
    source_date_epoch: int,
) -> tuple[Path, Path, Path]:
    project_root = project_root.resolve()
    output_dir = output_dir.resolve()
    if source_date_epoch < 0:
        raise ValueError("Source date epoch must not be negative")

    _validate_version(project_root, version)
    files = _collect_release_files(project_root)
    output_dir.mkdir(parents=True, exist_ok=True)

    archive_stem = f"cfms-on-websocket-{version}"
    zip_path = output_dir / f"{archive_stem}.zip"
    tar_path = output_dir / f"{archive_stem}.tar.gz"
    checksums_path = output_dir / "SHA256SUMS.txt"

    _write_zip(zip_path, archive_stem, files, source_date_epoch)
    _write_tar_gz(tar_path, archive_stem, files, source_date_epoch)
    checksums_path.write_text(
        "".join(
            f"{_sha256(path)}  {path.name}\n"
            for path in sorted((tar_path, zip_path), key=lambda path: path.name)
        ),
        encoding="utf-8",
        newline="\n",
    )
    return zip_path, tar_path, checksums_path


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build reproducible CFMS source deployment archives."
    )
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-date-epoch", required=True, type=int)
    parser.add_argument("--output-dir", type=Path, default=Path("dist"))
    args = parser.parse_args()

    try:
        artifacts = build_release(
            Path(__file__).resolve().parents[1],
            args.output_dir,
            args.version,
            args.source_date_epoch,
        )
    except (KeyError, OSError, ValueError, tomllib.TOMLDecodeError) as exc:
        parser.error(str(exc))

    for artifact in artifacts:
        print(artifact)


if __name__ == "__main__":
    main()
