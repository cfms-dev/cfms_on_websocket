import argparse
import datetime as dt
import re
import subprocess
import tomllib
from pathlib import Path

VERSION_PATTERN = re.compile(r"\d+\.\d+\.\d+")
CORE_VERSION_PATTERN = re.compile(r'(?m)^(CORE_VERSION\s*=\s*Version\(")[^"]+("\))')
PROJECT_VERSION_PATTERN = re.compile(r'(?m)^(version\s*=\s*")[^"]+(".*)')
MINIMUM_SERVER_VERSION_PATTERN = re.compile(
    r'(?m)^(minimum_server_version\s*=\s*")[^"]+(".*)'
)
RELEASE_HEADING_PATTERN = re.compile(
    r"^## \[v(?P<version>\d+\.\d+\.\d+)\]"
    r"\(https://github\.com/cfms-dev/cfms_on_websocket/releases/tag/"
    r"v(?P=version)\) - (?P<date>\d{4}-\d{2}-\d{2})$",
    re.MULTILINE,
)
LATEST_COMPARE_PATTERN = re.compile(
    r"^<small>\[Compare with latest\]"
    r"\(https://github\.com/cfms-dev/cfms_on_websocket/compare/"
    r"v(?P<version>\d+\.\d+\.\d+)\.\.\.HEAD\)</small>$",
    re.MULTILINE,
)

TOWNCRIER_MARKER = "<!-- towncrier release notes start -->"
IGNORED_FRAGMENT_NAMES = {
    ".gitignore",
    ".gitkeep",
    ".keep",
    "readme",
    "readme.md",
    "readme.rst",
}
MANAGED_PATHS = (
    Path("pyproject.toml"),
    Path("uv.lock"),
    Path("CHANGELOG.md"),
    Path("src/include/config/constants.py"),
    Path("src/include/extensions/builtin/manifest.toml"),
)


class ReleaseError(RuntimeError):
    pass


def _read_text(path: Path) -> str:
    return path.read_bytes().decode("utf-8").replace("\r\n", "\n")


def _write_text(path: Path, content: str) -> None:
    original = path.read_bytes()
    newline = "\r\n" if b"\r\n" in original else "\n"
    path.write_bytes(content.replace("\n", newline).encode("utf-8"))


def _replace_once(text: str, pattern: re.Pattern[str], replacement: str) -> str:
    updated, count = pattern.subn(replacement, text, count=1)
    if count != 1:
        raise ReleaseError(f"Expected exactly one match for {pattern.pattern!r}")
    return updated


def _parse_version(version: str) -> tuple[int, int, int]:
    if VERSION_PATTERN.fullmatch(version) is None:
        raise ReleaseError(f"Version must use stable X.Y.Z format: {version!r}")
    return tuple(int(part) for part in version.split("."))


def _core_version(project_root: Path) -> str:
    constants = _read_text(project_root / "src/include/config/constants.py")
    match = re.search(r'(?m)^CORE_VERSION\s*=\s*Version\("([^"]+)"\)', constants)
    if match is None:
        raise ReleaseError("Unable to find CORE_VERSION")
    return match.group(1)


def _locked_project_version(project_root: Path) -> str:
    lock_data = tomllib.loads(_read_text(project_root / "uv.lock"))
    matches = [
        package["version"]
        for package in lock_data["package"]
        if package.get("name") == "cfms-on-websocket"
        and package.get("source") == {"editable": "."}
    ]
    if len(matches) != 1:
        raise ReleaseError(
            "uv.lock must contain exactly one editable cfms-on-websocket package"
        )
    return matches[0]


def _synchronized_versions(project_root: Path) -> dict[str, str]:
    pyproject = tomllib.loads(_read_text(project_root / "pyproject.toml"))
    manifest = tomllib.loads(
        _read_text(project_root / "src/include/extensions/builtin/manifest.toml")
    )
    return {
        "CORE_VERSION": _core_version(project_root),
        "project.version": pyproject["project"]["version"],
        "builtin.version": manifest["extension"]["version"],
        "builtin.minimum_server_version": manifest["compatibility"][
            "minimum_server_version"
        ],
        "uv.lock": _locked_project_version(project_root),
    }


def _validate_synchronized_versions(project_root: Path, expected: str) -> None:
    versions = _synchronized_versions(project_root)
    mismatches = {name: value for name, value in versions.items() if value != expected}
    if mismatches:
        details = ", ".join(f"{name}={value!r}" for name, value in mismatches.items())
        raise ReleaseError(
            f"Release versions are not synchronized to {expected!r}: {details}"
        )


def _fragment_paths(project_root: Path) -> tuple[Path, ...]:
    fragment_root = project_root / "changelog.d"
    if not fragment_root.is_dir():
        return ()
    return tuple(
        path
        for path in sorted(fragment_root.rglob("*"))
        if path.is_file() and path.name.casefold() not in IGNORED_FRAGMENT_NAMES
    )


def _release_matches(changelog: str) -> list[re.Match[str]]:
    return list(RELEASE_HEADING_PATTERN.finditer(changelog))


def _validate_current_changelog(project_root: Path, current_version: str) -> None:
    changelog = _read_text(project_root / "CHANGELOG.md")
    if changelog.count(TOWNCRIER_MARKER) != 1:
        raise ReleaseError("CHANGELOG.md must contain exactly one Towncrier marker")
    latest_compare = LATEST_COMPARE_PATTERN.search(changelog)
    if latest_compare is None or latest_compare.group("version") != current_version:
        raise ReleaseError("The Unreleased comparison link does not match CORE_VERSION")
    releases = _release_matches(changelog)
    if not releases or releases[0].group("version") != current_version:
        raise ReleaseError("The latest CHANGELOG release does not match CORE_VERSION")


def _run_command(
    project_root: Path, command: list[str]
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        command,
        cwd=project_root,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        output = "\n".join(
            part.strip() for part in (result.stdout, result.stderr) if part
        )
        raise ReleaseError(
            f"Command failed with exit code {result.returncode}: {' '.join(command)}"
            + (f"\n{output}" if output else "")
        )
    return result


def _require_clean_worktree(project_root: Path) -> None:
    result = _run_command(project_root, ["git", "status", "--porcelain"])
    if result.stdout.strip():
        raise ReleaseError("Release preparation requires a clean Git worktree")


def _target_version(current: str, version: str | None, bump: str | None) -> str:
    current_parts = _parse_version(current)
    if (version is None) == (bump is None):
        raise ReleaseError("Specify either a target version or --bump")
    if version is not None:
        target = version
    else:
        major, minor, patch = current_parts
        if bump == "major":
            target = f"{major + 1}.0.0"
        elif bump == "minor":
            target = f"{major}.{minor + 1}.0"
        elif bump == "patch":
            target = f"{major}.{minor}.{patch + 1}"
        else:
            raise ReleaseError(f"Unsupported semantic increment: {bump!r}")
    if _parse_version(target) <= current_parts:
        raise ReleaseError(
            f"Target version {target!r} must be newer than CORE_VERSION {current!r}"
        )
    return target


def _update_versions(project_root: Path, target: str) -> None:
    constants_path = project_root / "src/include/config/constants.py"
    constants = _replace_once(
        _read_text(constants_path),
        CORE_VERSION_PATTERN,
        rf"\g<1>{target}\g<2>",
    )
    _write_text(constants_path, constants)

    pyproject_path = project_root / "pyproject.toml"
    pyproject = _replace_once(
        _read_text(pyproject_path),
        PROJECT_VERSION_PATTERN,
        rf"\g<1>{target}\g<2>",
    )
    _write_text(pyproject_path, pyproject)

    manifest_path = project_root / "src/include/extensions/builtin/manifest.toml"
    manifest = _replace_once(
        _read_text(manifest_path),
        PROJECT_VERSION_PATTERN,
        rf"\g<1>{target}\g<2>",
    )
    manifest = _replace_once(
        manifest,
        MINIMUM_SERVER_VERSION_PATTERN,
        rf"\g<1>{target}\g<2>",
    )
    _write_text(manifest_path, manifest)


def _update_changelog_links(
    project_root: Path,
    previous_version: str,
    target_version: str,
    release_date: str,
) -> None:
    changelog_path = project_root / "CHANGELOG.md"
    changelog = _read_text(changelog_path)
    changelog = _replace_once(
        changelog,
        LATEST_COMPARE_PATTERN,
        "<small>[Compare with latest]"
        "(https://github.com/cfms-dev/cfms_on_websocket/compare/"
        f"v{target_version}...HEAD)</small>",
    )
    heading = (
        f"## [v{target_version}]"
        "(https://github.com/cfms-dev/cfms_on_websocket/releases/tag/"
        f"v{target_version}) - {release_date}"
    )
    if changelog.count(heading) != 1:
        raise ReleaseError("Towncrier did not generate the expected release heading")
    comparison = (
        "<small>[Compare with previous release]"
        "(https://github.com/cfms-dev/cfms_on_websocket/compare/"
        f"v{previous_version}...v{target_version})</small>"
    )
    changelog = changelog.replace(heading, f"{heading}\n\n{comparison}", 1)
    _write_text(changelog_path, changelog)


def extract_release_notes(project_root: Path, version: str) -> str:
    _parse_version(version)
    changelog = _read_text(project_root / "CHANGELOG.md")
    releases = _release_matches(changelog)
    release_index = next(
        (
            index
            for index, match in enumerate(releases)
            if match.group("version") == version
        ),
        None,
    )
    if release_index is None:
        raise ReleaseError(f"CHANGELOG.md has no release section for v{version}")
    match = releases[release_index]
    end = (
        releases[release_index + 1].start()
        if release_index + 1 < len(releases)
        else len(changelog)
    )
    lines = changelog[match.end() : end].splitlines()
    while lines and not lines[0].strip():
        lines.pop(0)
    if lines and lines[0].startswith("<small>[Compare with previous release]"):
        lines.pop(0)
    while lines and not lines[0].strip():
        lines.pop(0)
    notes = "\n".join(lines).strip()
    if not notes:
        raise ReleaseError(f"Release v{version} has no notes")
    return f"{notes}\n"


def check_release(
    project_root: Path,
    version: str,
    notes_output: Path | None = None,
) -> None:
    _parse_version(version)
    _validate_synchronized_versions(project_root, version)
    if _fragment_paths(project_root):
        raise ReleaseError("Release contains unconsumed Towncrier fragments")
    _validate_current_changelog(project_root, version)
    changelog = _read_text(project_root / "CHANGELOG.md")
    releases = _release_matches(changelog)
    if len(releases) > 1:
        previous = releases[1].group("version")
        expected = (
            "<small>[Compare with previous release]"
            "(https://github.com/cfms-dev/cfms_on_websocket/compare/"
            f"v{previous}...v{version})</small>"
        )
        section_end = releases[1].start()
        if expected not in changelog[releases[0].end() : section_end]:
            raise ReleaseError("The release comparison link is missing or incorrect")
    notes = extract_release_notes(project_root, version)
    if notes_output is not None:
        notes_output.parent.mkdir(parents=True, exist_ok=True)
        notes_output.write_text(notes, encoding="utf-8", newline="\n")


def prepare_release(
    project_root: Path,
    version: str | None = None,
    bump: str | None = None,
    release_date: str | None = None,
) -> str:
    project_root = project_root.resolve()
    _require_clean_worktree(project_root)
    current = _core_version(project_root)
    _validate_synchronized_versions(project_root, current)
    _validate_current_changelog(project_root, current)
    target = _target_version(current, version, bump)
    if release_date is None:
        release_date = dt.datetime.now(dt.UTC).date().isoformat()
    else:
        try:
            release_date = dt.date.fromisoformat(release_date).isoformat()
        except ValueError as exc:
            raise ReleaseError(
                f"Release date must use YYYY-MM-DD format: {release_date!r}"
            ) from exc

    fragments = _fragment_paths(project_root)
    if not fragments:
        raise ReleaseError("At least one Towncrier fragment is required")
    draft = _run_command(
        project_root,
        [
            "towncrier",
            "build",
            "--draft",
            "--version",
            target,
            "--date",
            release_date,
        ],
    )
    if not draft.stdout.strip():
        raise ReleaseError("Towncrier generated an empty release draft")
    print(draft.stdout.rstrip())

    snapshots = {path: (project_root / path).read_bytes() for path in MANAGED_PATHS}
    fragment_snapshots = {path: path.read_bytes() for path in fragments}
    try:
        _update_versions(project_root, target)
        _run_command(project_root, ["uv", "lock"])
        _run_command(
            project_root,
            [
                "towncrier",
                "build",
                "--keep",
                "--version",
                target,
                "--date",
                release_date,
            ],
        )
        _update_changelog_links(project_root, current, target, release_date)
        for fragment in fragments:
            fragment.unlink()
        check_release(project_root, target)
    except BaseException:
        for path, contents in snapshots.items():
            (project_root / path).write_bytes(contents)
        for path, contents in fragment_snapshots.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(contents)
        raise
    return target


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Prepare and validate synchronized CFMS releases."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    prepare_parser = subparsers.add_parser(
        "prepare", help="bump synchronized versions and build the changelog"
    )
    prepare_parser.add_argument("version", nargs="?")
    prepare_parser.add_argument("--bump", choices=("major", "minor", "patch"))
    prepare_parser.add_argument("--date")

    check_parser = subparsers.add_parser(
        "check", help="validate a prepared release and optionally export its notes"
    )
    check_parser.add_argument("version")
    check_parser.add_argument("--notes-output", type=Path)

    args = parser.parse_args()
    project_root = Path(__file__).resolve().parents[1]
    try:
        if args.command == "prepare":
            target = prepare_release(
                project_root,
                version=args.version,
                bump=args.bump,
                release_date=args.date,
            )
            print(f"Prepared release v{target}")
        else:
            check_release(project_root, args.version, args.notes_output)
            print(f"Release v{args.version} is synchronized")
    except (KeyError, OSError, ReleaseError, tomllib.TOMLDecodeError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
