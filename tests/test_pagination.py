import base64
import importlib
import json
import sys

import pytest


def _load_pagination(monkeypatch, tmp_path):
    module_names = ("include.domains.pagination", "include.config.settings")
    previous_modules = {name: sys.modules.get(name) for name in module_names}
    (tmp_path / "config.toml").write_text(
        """
[server]
secret_key = "pagination-test-secret"
""".strip(),
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


def _decode_token(token: str) -> dict:
    padding = "=" * (-len(token) % 4)
    raw = base64.urlsafe_b64decode((token + padding).encode())
    return json.loads(raw)


def _encode_token(payload: dict) -> str:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def test_cursor_signature_binding_and_validation(monkeypatch, tmp_path):
    pagination, previous_modules = _load_pagination(monkeypatch, tmp_path)
    try:
        token = pagination.encode_cursor(
            action="list_directory",
            sort="type_name_id:asc",
            filters={"folder_id": "root"},
            last=[0, "alpha", "id-1"],
        )

        assert pagination.decode_cursor(
            token,
            action="list_directory",
            sort="type_name_id:asc",
            filters={"folder_id": "root"},
            value_types=[int, str, str],
        ) == [0, "alpha", "id-1"]
        assert "maximum" in pagination.OFFSET_PAGINATION_SCHEMA["offset"]

        with pytest.raises(pagination.CursorError):
            pagination.decode_cursor(
                token,
                action="list_directory",
                sort="type_name_id:asc",
                filters={"folder_id": "other"},
            )

        tampered_payload = _decode_token(token)
        tampered_payload["last"] = [1, "omega", "id-9"]
        with pytest.raises(pagination.CursorError):
            pagination.decode_cursor(
                _encode_token(tampered_payload),
                action="list_directory",
                sort="type_name_id:asc",
                filters={"folder_id": "root"},
            )

        typed_token = pagination.encode_cursor(
            action="view_access_entries",
            sort="id:asc",
            filters={"object_type": "user", "object_identifier": "alice"},
            last=["1"],
        )
        with pytest.raises(pagination.CursorError):
            pagination.decode_cursor(
                typed_token,
                action="view_access_entries",
                sort="id:asc",
                filters={"object_type": "user", "object_identifier": "alice"},
                value_types=[int],
            )

        with pytest.raises(pagination.CursorError):
            pagination.decode_cursor(
                "x" * (pagination.PAGINATION_CURSOR_MAX_LENGTH + 1),
                action="list_directory",
                sort="type_name_id:asc",
                filters={"folder_id": "root"},
            )
    finally:
        _restore_modules(pagination, previous_modules)
