import base64
import importlib
import sys
from pathlib import Path

import pytest
from cryptography import fernet as fernet_module
from tomlkit import dumps, parse

_CONFIG_SAMPLE = Path(__file__).resolve().parents[2] / "src" / "config.toml.sample"


def _load_pagination(monkeypatch, tmp_path):
    module_names = ("include.domains.pagination", "include.config.settings")
    previous_modules = {name: sys.modules.get(name) for name in module_names}
    config = parse(_CONFIG_SAMPLE.read_text(encoding="utf-8"))
    config["server"]["secret_key"] = "pagination-test-secret"
    config["security"]["pepper"] = "pagination-test-pepper"
    (tmp_path / "config.toml").write_text(
        dumps(config),
        encoding="utf-8",
    )
    (tmp_path / "init").write_text("", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    for name in module_names:
        sys.modules.pop(name, None)
    return importlib.import_module("include.domains.pagination"), previous_modules


def _restore_modules(pagination, previous_modules):
    pagination.global_config.stop()
    for name, module in previous_modules.items():
        if module is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = module


def _tamper_token(token: str) -> str:
    raw_token = bytearray(base64.urlsafe_b64decode(token))
    raw_token[-1] ^= 1
    return base64.urlsafe_b64encode(raw_token).decode()


def _encode_cursor(
    pagination,
    *,
    action: str,
    sort: str,
    filters: dict,
    last: list,
) -> str:
    return pagination.PaginationCursor(
        action=action,
        sort=sort,
        filters=filters,
        last=last,
    ).encode()


def test_encrypted_cursor_binding_and_validation(monkeypatch, tmp_path):
    pagination, previous_modules = _load_pagination(monkeypatch, tmp_path)
    try:
        token = _encode_cursor(
            pagination,
            action="list_directory",
            sort="type_name_id:asc",
            filters={"folder_id": "root"},
            last=[0, "alpha", "id-1"],
        )
        raw_token = base64.urlsafe_b64decode(token)
        assert "list_directory" not in token
        assert "alpha" not in token
        assert b"list_directory" not in raw_token
        assert b"alpha" not in raw_token
        raw_payload = pagination._cursor_fernet().decrypt(token)
        assert "t" not in pagination.json.loads(raw_payload)

        decoded_cursor = pagination.PaginationCursor.decode(
            token,
            action="list_directory",
            sort="type_name_id:asc",
            filters={"folder_id": "root"},
            value_types=[int, str, str],
        )
        assert decoded_cursor is not None
        assert decoded_cursor.last == [0, "alpha", "id-1"]
        assert "maximum" in pagination.OFFSET_PAGINATION_SCHEMA["offset"]

        with pytest.raises(
            pagination.CursorError, match="Cursor does not match this request"
        ):
            pagination.PaginationCursor.decode(
                token,
                action="list_directory",
                sort="type_name_id:asc",
                filters={"folder_id": "other"},
            )

        with pytest.raises(pagination.CursorError):
            pagination.PaginationCursor.decode(
                _tamper_token(token),
                action="list_directory",
                sort="type_name_id:asc",
                filters={"folder_id": "root"},
            )

        with pytest.raises(pagination.CursorError):
            pagination.PaginationCursor.decode(
                base64.urlsafe_b64encode(
                    b'{"v":2,"a":"list_directory","k":[0,"alpha","id-1"]}'
                ).decode(),
                action="list_directory",
                sort="type_name_id:asc",
                filters={"folder_id": "root"},
            )

        typed_token = _encode_cursor(
            pagination,
            action="view_access_entries",
            sort="id:asc",
            filters={"object_type": "user", "object_identifier": "alice"},
            last=["1"],
        )
        with pytest.raises(pagination.CursorError):
            pagination.PaginationCursor.decode(
                typed_token,
                action="view_access_entries",
                sort="id:asc",
                filters={"object_type": "user", "object_identifier": "alice"},
                value_types=[int],
            )

        with pytest.raises(pagination.CursorError):
            pagination.PaginationCursor.decode(
                "x" * (pagination.PAGINATION_CURSOR_MAX_LENGTH + 1),
                action="list_directory",
                sort="type_name_id:asc",
                filters={"folder_id": "root"},
            )

        assert (
            pagination.PaginationCursor.decode(
                None,
                action="list_directory",
                sort="type_name_id:asc",
                filters={"folder_id": "root"},
            )
            is None
        )

        response = pagination.make_cursor_response(
            [
                {"id": "id-1", "_cursor_key": [0, "alpha", "id-1"]},
                {"id": "id-2", "_cursor_key": [0, "bravo", "id-2"]},
            ],
            page_size=1,
            action="list_directory",
            sort="type_name_id:asc",
            filters={"folder_id": "root"},
            cursor_key=lambda item: item["_cursor_key"],
        )
        assert response["items"] == [{"id": "id-1"}]
        assert response["next_cursor"] is not None
    finally:
        _restore_modules(pagination, previous_modules)


def test_cursor_ttl_defaults_to_no_expiration(monkeypatch, tmp_path):
    pagination, previous_modules = _load_pagination(monkeypatch, tmp_path)
    try:
        now = 2_000_000_000
        monkeypatch.setattr(fernet_module.time, "time", lambda: now)
        token = _encode_cursor(
            pagination,
            action="search",
            sort="name:asc",
            filters={"query": "alpha"},
            last=["alpha", 0, "id-1"],
        )

        monkeypatch.setattr(fernet_module.time, "time", lambda: now + 10_000)
        decoded_cursor = pagination.PaginationCursor.decode(
            token,
            action="search",
            sort="name:asc",
            filters={"query": "alpha"},
            value_types=[str, int, str],
        )
        assert decoded_cursor is not None
        assert decoded_cursor.last == ["alpha", 0, "id-1"]
    finally:
        _restore_modules(pagination, previous_modules)


def test_cursor_ttl_rejects_expired_tokens(monkeypatch, tmp_path):
    pagination, previous_modules = _load_pagination(monkeypatch, tmp_path)
    try:
        now = 2_000_000_000
        monkeypatch.setattr(fernet_module.time, "time", lambda: now)
        token = _encode_cursor(
            pagination,
            action="view_audit_logs",
            sort="logged_time_id:desc",
            filters={"filters": []},
            last=[1000.0, "audit-1"],
        )

        monkeypatch.setattr(fernet_module.time, "time", lambda: now + 3601)
        with pytest.raises(pagination.CursorError):
            pagination.PaginationCursor.decode(
                token,
                action="view_audit_logs",
                sort="logged_time_id:desc",
                filters={"filters": []},
                ttl=3600,
                value_types=[(int, float), str],
            )

        decoded_cursor = pagination.PaginationCursor.decode(
            token,
            action="view_audit_logs",
            sort="logged_time_id:desc",
            filters={"filters": []},
            value_types=[(int, float), str],
        )
        assert decoded_cursor is not None
        assert decoded_cursor.last == [1000.0, "audit-1"]
    finally:
        _restore_modules(pagination, previous_modules)


@pytest.mark.parametrize("aad", [None, "wrong-aad"])
def test_cursor_rejects_missing_or_wrong_payload_aad(monkeypatch, tmp_path, aad):
    pagination, previous_modules = _load_pagination(monkeypatch, tmp_path)
    try:
        payload = {
            "a": "list_directory",
            "s": "type_name_id:asc",
            "f": pagination._filters_hash({"folder_id": "root"}),
            "k": [0, "alpha", "id-1"],
        }
        if aad is not None:
            payload["aad"] = aad

        token = (
            pagination._cursor_fernet()
            .encrypt(pagination._canonical_json(payload))
            .decode()
        )
        with pytest.raises(pagination.CursorError):
            pagination.PaginationCursor.decode(
                token,
                action="list_directory",
                sort="type_name_id:asc",
                filters={"folder_id": "root"},
                value_types=[int, str, str],
            )
    finally:
        _restore_modules(pagination, previous_modules)


def test_cursor_response_token_expiration_is_controlled_by_decode_ttl(
    monkeypatch, tmp_path
):
    pagination, previous_modules = _load_pagination(monkeypatch, tmp_path)
    try:
        now = 2_000_000_000
        monkeypatch.setattr(fernet_module.time, "time", lambda: now)
        response = pagination.make_cursor_response(
            [
                {"id": "audit-1", "logged_time": 2.0},
                {"id": "audit-2", "logged_time": 1.0},
            ],
            page_size=1,
            action="view_audit_logs",
            sort="logged_time_id:desc",
            filters={"filters": []},
            cursor_key=lambda item: [item["logged_time"], item["id"]],
        )

        assert response["next_cursor"] is not None
        monkeypatch.setattr(fernet_module.time, "time", lambda: now + 3601)
        with pytest.raises(pagination.CursorError):
            pagination.PaginationCursor.decode(
                response["next_cursor"],
                action="view_audit_logs",
                sort="logged_time_id:desc",
                filters={"filters": []},
                ttl=3600,
                value_types=[(int, float), str],
            )
    finally:
        _restore_modules(pagination, previous_modules)
