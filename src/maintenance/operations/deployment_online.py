import datetime as dt
import hashlib
import json
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from packaging.version import Version

from maintenance.operations import deployment
from maintenance.operations.exceptions import MaintenanceOperationError

GITHUB_LATEST_RELEASE_URL = (
    "https://api.github.com/repos/cfms-dev/cfms_on_websocket/releases/latest"
)
GITHUB_API_VERSION = "2026-03-10"
MAX_METADATA_BYTES = 1024 * 1024
MAX_CHECKSUM_BYTES = 64 * 1024
METADATA_TIMEOUT_SECONDS = 10
DOWNLOAD_TIMEOUT_SECONDS = 60

_TAG_PATTERN = re.compile(r"v(\d+\.\d+\.\d+)").fullmatch
_ASSET_DIGEST_PATTERN = re.compile(r"sha256:([0-9a-fA-F]{64})").fullmatch
_CHECKSUM_PATTERN = re.compile(r"[0-9a-fA-F]{64}").fullmatch


@dataclass(frozen=True, slots=True)
class OnlineDeploymentStatus:
    deployment_root: Path
    current_version: str
    latest_version: str
    update_available: bool
    published_at: dt.datetime
    release_url: str


@dataclass(frozen=True, slots=True)
class OnlineDeploymentUpdateResult:
    status: OnlineDeploymentStatus
    deployment: deployment.DeploymentResult | None


@dataclass(frozen=True, slots=True)
class _ReleaseAsset:
    name: str
    url: str
    size: int
    digest: str


@dataclass(frozen=True, slots=True)
class _OnlineRelease:
    version: str
    published_at: dt.datetime
    release_url: str
    package: _ReleaseAsset
    checksums: _ReleaseAsset


class _HTTPSOnlyRedirectHandler(HTTPRedirectHandler):
    def redirect_request(
        self,
        req,
        fp,
        code,
        msg,
        headers,
        newurl,
    ):
        if urlsplit(newurl).scheme != "https":
            raise HTTPError(
                req.full_url,
                code,
                "GitHub redirected an asset download away from HTTPS",
                headers,
                fp,
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_URL_OPENER = build_opener(_HTTPSOnlyRedirectHandler())


def _request(url: str, *, api: bool) -> Request:
    headers = {
        "Accept": "application/vnd.github+json" if api else "application/octet-stream",
        "User-Agent": "cfms-on-websocket-maintain",
    }
    if api:
        headers["X-GitHub-Api-Version"] = GITHUB_API_VERSION
    return Request(url, headers=headers)


def _open(request: Request, *, timeout: int):
    try:
        return _URL_OPENER.open(request, timeout=timeout)
    except HTTPError as exc:
        if exc.code in {403, 429}:
            retry_after = exc.headers.get("Retry-After")
            reset = exc.headers.get("X-RateLimit-Reset")
            if retry_after:
                suffix = f"; retry after {retry_after} seconds"
            elif reset:
                try:
                    reset_at = dt.datetime.fromtimestamp(int(reset), dt.UTC)
                except OverflowError, ValueError:
                    suffix = ""
                else:
                    suffix = f"; limit resets at {reset_at.isoformat()}"
            else:
                suffix = ""
            raise MaintenanceOperationError(
                f"GitHub API rate limit exceeded{suffix}"
            ) from exc
        raise MaintenanceOperationError(
            f"GitHub request failed with HTTP status {exc.code}"
        ) from exc
    except (TimeoutError, URLError, OSError) as exc:
        raise MaintenanceOperationError(f"Unable to reach GitHub: {exc}") from exc


def _declared_length(response, *, maximum: int, label: str) -> int | None:
    value = response.headers.get("Content-Length")
    if value is None:
        return None
    try:
        length = int(value)
    except ValueError as exc:
        raise MaintenanceOperationError(
            f"GitHub returned an invalid Content-Length for {label}"
        ) from exc
    if length < 0 or length > maximum:
        raise MaintenanceOperationError(f"GitHub {label} exceeds the size limit")
    return length


def _read_response(response, *, maximum: int, label: str) -> bytes:
    declared = _declared_length(response, maximum=maximum, label=label)
    contents = bytearray()
    while chunk := response.read(min(1024 * 1024, maximum + 1 - len(contents))):
        contents.extend(chunk)
        if len(contents) > maximum:
            raise MaintenanceOperationError(f"GitHub {label} exceeds the size limit")
    if declared is not None and len(contents) != declared:
        raise MaintenanceOperationError(f"GitHub {label} download was truncated")
    return bytes(contents)


def _read_url(
    url: str,
    *,
    maximum: int,
    timeout: int,
    label: str,
    api: bool = False,
) -> bytes:
    request = _request(url, api=api)
    try:
        with _open(request, timeout=timeout) as response:
            if urlsplit(response.geturl()).scheme != "https":
                raise MaintenanceOperationError(f"GitHub {label} did not use HTTPS")
            return _read_response(response, maximum=maximum, label=label)
    except (TimeoutError, URLError, OSError) as exc:
        raise MaintenanceOperationError(
            f"Unable to download GitHub {label}: {exc}"
        ) from exc


def _parse_published_at(value: Any) -> dt.datetime:
    if not isinstance(value, str):
        raise MaintenanceOperationError("GitHub release metadata is invalid")
    try:
        published_at = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise MaintenanceOperationError("GitHub release metadata is invalid") from exc
    if published_at.tzinfo is None:
        raise MaintenanceOperationError("GitHub release metadata is invalid")
    return published_at


def _asset(
    assets: list[Any],
    *,
    name: str,
    version: str,
    maximum: int,
) -> _ReleaseAsset:
    matches = [
        item for item in assets if isinstance(item, dict) and item.get("name") == name
    ]
    if len(matches) != 1:
        raise MaintenanceOperationError(
            f"GitHub release must contain exactly one uploaded {name} asset"
        )
    item = matches[0]
    url = item.get("browser_download_url")
    size = item.get("size")
    digest_match = (
        _ASSET_DIGEST_PATTERN(item.get("digest"))
        if isinstance(item.get("digest"), str)
        else None
    )
    expected_path = f"/cfms-dev/cfms_on_websocket/releases/download/v{version}/{name}"
    parsed_url = urlsplit(url) if isinstance(url, str) else None
    if (
        item.get("state") != "uploaded"
        or isinstance(size, bool)
        or not isinstance(size, int)
        or size < 0
        or size > maximum
        or digest_match is None
        or parsed_url is None
        or parsed_url.scheme != "https"
        or parsed_url.netloc != "github.com"
        or parsed_url.path != expected_path
        or parsed_url.query
        or parsed_url.fragment
    ):
        raise MaintenanceOperationError(f"GitHub release asset {name} is invalid")
    return _ReleaseAsset(name, url, size, digest_match[1].lower())


def _fetch_latest_release() -> _OnlineRelease:
    contents = _read_url(
        GITHUB_LATEST_RELEASE_URL,
        maximum=MAX_METADATA_BYTES,
        timeout=METADATA_TIMEOUT_SECONDS,
        label="release metadata",
        api=True,
    )
    try:
        metadata = json.loads(contents)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise MaintenanceOperationError("GitHub release metadata is invalid") from exc
    if not isinstance(metadata, dict):
        raise MaintenanceOperationError("GitHub release metadata is invalid")
    tag = metadata.get("tag_name")
    tag_match = _TAG_PATTERN(tag) if isinstance(tag, str) else None
    if (
        tag_match is None
        or metadata.get("draft") is not False
        or metadata.get("prerelease") is not False
    ):
        raise MaintenanceOperationError("GitHub release metadata is invalid")
    version = tag_match[1]
    release_url = metadata.get("html_url")
    expected_release_url = (
        f"https://github.com/cfms-dev/cfms_on_websocket/releases/tag/v{version}"
    )
    assets = metadata.get("assets")
    if release_url != expected_release_url or not isinstance(assets, list):
        raise MaintenanceOperationError("GitHub release metadata is invalid")
    package_name = f"cfms-on-websocket-{version}.zip"
    return _OnlineRelease(
        version,
        _parse_published_at(metadata.get("published_at")),
        release_url,
        _asset(
            assets,
            name=package_name,
            version=version,
            maximum=deployment.MAX_PACKAGE_BYTES,
        ),
        _asset(
            assets,
            name="SHA256SUMS.txt",
            version=version,
            maximum=MAX_CHECKSUM_BYTES,
        ),
    )


def _status(
    project_root: Path, current_version: str, release: _OnlineRelease
) -> OnlineDeploymentStatus:
    return OnlineDeploymentStatus(
        project_root,
        current_version,
        release.version,
        Version(release.version) > Version(current_version),
        release.published_at,
        release.release_url,
    )


def inspect_online_deployment(deployment_root: str | Path) -> OnlineDeploymentStatus:
    project_root = deployment._project_root(deployment_root)
    active = deployment._active_release(project_root)
    return _status(project_root, active.version, _fetch_latest_release())


def _download_asset(asset: _ReleaseAsset, target: Path, *, maximum: int) -> str:
    request = _request(asset.url, api=False)
    digest = hashlib.sha256()
    try:
        with _open(request, timeout=DOWNLOAD_TIMEOUT_SECONDS) as response:
            if urlsplit(response.geturl()).scheme != "https":
                raise MaintenanceOperationError(
                    f"GitHub {asset.name} download did not use HTTPS"
                )
            declared = _declared_length(response, maximum=maximum, label=asset.name)
            if declared is not None and declared != asset.size:
                raise MaintenanceOperationError(
                    f"GitHub {asset.name} size does not match release metadata"
                )
            downloaded = 0
            with target.open("xb") as output:
                while chunk := response.read(1024 * 1024):
                    downloaded += len(chunk)
                    if downloaded > maximum:
                        raise MaintenanceOperationError(
                            f"GitHub {asset.name} exceeds the size limit"
                        )
                    output.write(chunk)
                    digest.update(chunk)
            if downloaded != asset.size or (
                declared is not None and downloaded != declared
            ):
                raise MaintenanceOperationError(
                    f"GitHub {asset.name} download was truncated"
                )
    except (TimeoutError, URLError, OSError) as exc:
        raise MaintenanceOperationError(
            f"Unable to download GitHub {asset.name}: {exc}"
        ) from exc
    actual = digest.hexdigest()
    if actual != asset.digest:
        raise MaintenanceOperationError(
            f"GitHub {asset.name} digest does not match release metadata"
        )
    return actual


def _checksum_for(contents: bytes, package_name: str) -> str:
    try:
        lines = contents.decode("utf-8").splitlines()
    except UnicodeError as exc:
        raise MaintenanceOperationError("GitHub checksum asset is invalid") from exc
    matches = []
    for line in lines:
        parts = line.split(maxsplit=1)
        if len(parts) == 2 and parts[1].lstrip("* ") == package_name:
            matches.append(parts[0])
    if len(matches) != 1 or _CHECKSUM_PATTERN(matches[0]) is None:
        raise MaintenanceOperationError(
            f"GitHub checksum asset must contain exactly one valid entry for {package_name}"
        )
    return matches[0].lower()


def update_online_deployment(
    deployment_root: str | Path,
    *,
    extras: tuple[str, ...] | None = None,
    requirements_lock: str | Path | None = None,
) -> OnlineDeploymentUpdateResult:
    project_root = deployment._project_root(deployment_root)
    active = deployment._active_release(project_root)
    release = _fetch_latest_release()
    status = _status(project_root, active.version, release)
    if not status.update_available:
        return OnlineDeploymentUpdateResult(status, None)

    staging_root = deployment._maintenance_root(project_root) / "staging"
    staging_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="online-", dir=staging_root) as temporary:
        temporary_root = Path(temporary)
        checksum_path = temporary_root / release.checksums.name
        package_path = temporary_root / release.package.name
        _download_asset(
            release.checksums,
            checksum_path,
            maximum=MAX_CHECKSUM_BYTES,
        )
        package_digest = _download_asset(
            release.package,
            package_path,
            maximum=deployment.MAX_PACKAGE_BYTES,
        )
        expected_digest = _checksum_for(
            checksum_path.read_bytes(), release.package.name
        )
        if package_digest != expected_digest:
            raise MaintenanceOperationError(
                "GitHub release package digest does not match SHA256SUMS.txt"
            )
        result = deployment.upgrade_deployment(
            package_path,
            project_root,
            expected_sha256=expected_digest,
            extras=extras,
            requirements_lock=requirements_lock,
        )
    return OnlineDeploymentUpdateResult(status, result)
