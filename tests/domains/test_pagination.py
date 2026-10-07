import base64
from types import SimpleNamespace

import pytest
from cryptography import fernet as fernet_module

from include.domains import pagination as pagination_module

# Independently encrypted v2 fixtures use pagination-test-secret and timestamp
# 1700000000. The valid fixture shares the key and binding with every invalid one.
_VALID_CURSOR_V2 = (
    "gAAAAABlU_EA6h-0symSgMjQmvV5qFO8tyBePCfdL3H9N3UYDMD-bFWQZK8GsjbtVndlY2"
    "QgMQ_WdIPNRVhLes1nw8TLjfheDrKQDq1ru8h_DOAwyT4bT2v42Yr7GB4eG_vmjWpaeeJf"
    "uXQPKIwcdTMWWkFc_dnsgkOc6Dxf5H6LM4ryKxHE7UKMfu4fd9f7GhhjAGGPd959dCM3wf"
    "geD4zYDwTENq76pOgRSbKgeo4HHR_TXOz6Gn1c6dagRbsHKAS8NIfiK1IFL6xvXQIskQJH"
    "lSmydJAlm8ri9ldP4xsm3lK_FCUlTGk="
)
_INVALID_CURSOR_V2 = (
    pytest.param(
        (
            "gAAAAABlU_EArIaeLj9VxzHQ_2yt3xsZ56qTBi4mNVyYNozhp8pVeWcZt0aA4newN135VI"
            "B2QJsfTQWHlIipL8hkgjB3AjLFtqBe5FO4ysgY9l83Rv2sVVWyZvMeATtJ6OUQ0I0tD7DN"
            "jZ_Qw7XEkQ84Fhc2oEXPBO0TxOguIxYsZbfrqp4Ha1VqyryKoGRYlaFXz9KmkddbCGQD9f"
            "Y-VeVamJqra3-3929pblm67lzkdJ2jKIqmIrrvnwXlR9julTl2rj8t64q_"
        ),
        id="missing-aad",
    ),
    pytest.param(
        (
            "gAAAAABlU_EAfNu-uLqWWpCEvtY0hWD5_hqtFTmXTZ0yUyQsN17ssyGFtHKkNbhssLdNeT"
            "26sc6suieXJJ3BNp4amoY_DEXKyAjWHJOR73UKNVkSSiI_WWgZW0JbgjBgeHyvbKNlvPGY"
            "-JBRphffOfrmTGPjS47-ESn5IrRhxfgtc50nVrsdpkep5No989byyIWLoGx_Gn3bPrwICI"
            "PWGsJ85olKg3gdksNfo8vtuWqFrGIB1h7MuaicT-4VuRzG6mBIRYeiw8HrRVPRzRCmvcna"
            "6hvYgyyQ2w=="
        ),
        id="wrong-aad",
    ),
    pytest.param(
        (
            "gAAAAABlU_EAed8D-CBur7Guqo3oHfVEbqMcU-nvcHdbCJBSaAPsF_0setettPX8Fz25s2"
            "E1Qn9rLOz3wjlqkpfHXrIYYVUPGg=="
        ),
        id="invalid-root",
    ),
    pytest.param(
        (
            "gAAAAABlU_EAA1NTqp8IuA_lJsZhPx-pX1NqJJVeH_XS-VgX7GnmGBS8agN1R5njx4CdHF"
            "XVNpHwMkfVt4OeWwyidQYEXV8LlvItln6H7OhuOVLlo0qj3Dnf7oNmcBwMhAPFXqsLcjl_"
            "Bh3TY-32ASLltWwuyKcyleaxZfVL3m-hYNnhQA1ViHx2X1fkyyNvdvc77GOnIlzhv8ongA"
            "RfgHi_ZPKyicAlMBTxW0wTRgrmDnplvlt6svcZaff8J4MEhUB8tspVPMv4dy7tSrTV418L"
            "-C9r5pUuyg=="
        ),
        id="missing-last",
    ),
    pytest.param(
        (
            "gAAAAABlU_EA7DWMB2gYWIsldr-7E103mYHqlefefUod0bEPvyflS95reHR3RylxNH4vTU"
            "XtdQnBUom89pLvYwYMJLOFQCJozGnTJPVIpdbgynjxPRCPmuzdEg2yRHsYnkRyhxVZkGnl"
            "GO4-sPtdyh-zC32DXJGDse_1RR80GTLIaDXY1OuQ4F9vkykgy65Yx7cz7Lib2fBjvs43sH"
            "5gNd9RbU1oykzaOv0Wy8AMAKezhQ4HCvfq3qIjEcB8ovdwUZzY18F5JEPV8Q8L6lNn641P"
            "wsW57gWA9Q=="
        ),
        id="non-list-last",
    ),
    pytest.param(
        (
            "gAAAAABlU_EAbemazFuPVwOsDlqVYzOW7a-0OIIkXVsCqFG9xhJ19KJI8_vVvCno7hA9ze"
            "ClSnfsgJXoX-7BVyQmwOl03aC7bA=="
        ),
        id="invalid-json",
    ),
)


@pytest.fixture
def pagination(monkeypatch):
    monkeypatch.setattr(
        pagination_module,
        "global_config",
        {"server": {"secret_key": "pagination-test-secret"}},
    )
    return pagination_module


@pytest.fixture
def directory_cursor(pagination):
    return pagination.PaginationCursor(
        action="list_directory",
        sort="type_name_id:asc",
        filters={"folder_id": "root"},
        last=[0, "alpha", "id-1"],
    )


def test_encrypted_cursor_round_trip_hides_request_details(
    pagination, directory_cursor
):
    token = directory_cursor.encode()

    raw_token = base64.urlsafe_b64decode(token)
    assert b"list_directory" not in raw_token
    assert b"alpha" not in raw_token
    decoded = pagination.PaginationCursor.decode(
        token,
        action="list_directory",
        sort="type_name_id:asc",
        filters={"folder_id": "root"},
        value_types=[int, str, str],
    )
    assert decoded == directory_cursor


@pytest.mark.parametrize(
    ("action", "sort", "filters"),
    [
        pytest.param("search", "type_name_id:asc", {"folder_id": "root"}, id="action"),
        pytest.param("list_directory", "name:desc", {"folder_id": "root"}, id="sort"),
        pytest.param(
            "list_directory", "type_name_id:asc", {"folder_id": "other"}, id="filters"
        ),
    ],
)
def test_cursor_is_bound_to_request(
    pagination, directory_cursor, action, sort, filters
):
    token = directory_cursor.encode()

    with pytest.raises(
        pagination.CursorError, match="Cursor does not match this request"
    ):
        pagination.PaginationCursor.decode(
            token, action=action, sort=sort, filters=filters
        )


def test_cursor_filter_binding_is_independent_of_mapping_order(pagination):
    token = pagination.PaginationCursor(
        action="search",
        sort="name:asc",
        filters={"query": "alpha", "include_deleted": False},
        last=["alpha", 0, "id-1"],
    ).encode()

    decoded = pagination.PaginationCursor.decode(
        token,
        action="search",
        sort="name:asc",
        filters={"include_deleted": False, "query": "alpha"},
        value_types=[str, int, str],
    )

    assert decoded is not None
    assert decoded.last == ["alpha", 0, "id-1"]


def test_cursor_rejects_tampering(pagination, directory_cursor):
    raw_token = bytearray(base64.urlsafe_b64decode(directory_cursor.encode()))
    raw_token[-1] ^= 1
    token = base64.urlsafe_b64encode(raw_token).decode()

    with pytest.raises(pagination.CursorError, match="Invalid cursor"):
        pagination.PaginationCursor.decode(
            token,
            action="list_directory",
            sort="type_name_id:asc",
            filters={"folder_id": "root"},
        )


@pytest.mark.parametrize(
    "token",
    [
        pytest.param("not-a-fernet-token", id="malformed"),
        pytest.param(
            base64.urlsafe_b64encode(
                b'{"v":2,"a":"list_directory","k":[0,"alpha","id-1"]}'
            ).decode(),
            id="unencrypted",
        ),
        pytest.param(
            "x" * (pagination_module.PAGINATION_CURSOR_MAX_LENGTH + 1), id="oversized"
        ),
    ],
)
def test_cursor_rejects_invalid_tokens(pagination, token):
    with pytest.raises(pagination.CursorError, match="Invalid cursor"):
        pagination.PaginationCursor.decode(
            token,
            action="list_directory",
            sort="type_name_id:asc",
            filters={"folder_id": "root"},
        )


@pytest.mark.parametrize("token", _INVALID_CURSOR_V2)
def test_cursor_rejects_authenticated_invalid_payloads(pagination, token):
    valid = pagination.PaginationCursor.decode(
        _VALID_CURSOR_V2,
        action="list_directory",
        sort="type_name_id:asc",
        filters={"folder_id": "root"},
        value_types=[int, str, str],
    )
    assert valid is not None
    assert valid.last == [0, "alpha", "id-1"]

    with pytest.raises(pagination.CursorError, match="Invalid cursor"):
        pagination.PaginationCursor.decode(
            token,
            action="list_directory",
            sort="type_name_id:asc",
            filters={"folder_id": "root"},
            value_types=[int, str, str],
        )


@pytest.mark.parametrize(
    "last",
    [
        pytest.param(["1"], id="string"),
        pytest.param([True], id="boolean"),
        pytest.param([1.0], id="float"),
        pytest.param([], id="missing-key"),
        pytest.param([1, 2], id="extra-key"),
    ],
)
def test_cursor_rejects_incorrect_key_types_or_arity(pagination, last):
    token = pagination.PaginationCursor(
        action="view_access_entries",
        sort="id:asc",
        filters={"object_type": "user", "object_identifier": "alice"},
        last=last,
    ).encode()

    with pytest.raises(pagination.CursorError, match="Invalid cursor"):
        pagination.PaginationCursor.decode(
            token,
            action="view_access_entries",
            sort="id:asc",
            filters={"object_type": "user", "object_identifier": "alice"},
            value_types=[int],
        )


def test_cursor_is_invalid_after_secret_rotation(
    pagination, directory_cursor, monkeypatch
):
    token = directory_cursor.encode()
    monkeypatch.setattr(
        pagination,
        "global_config",
        {"server": {"secret_key": "rotated-pagination-secret"}},
    )

    with pytest.raises(pagination.CursorError, match="Invalid cursor"):
        pagination.PaginationCursor.decode(
            token,
            action="list_directory",
            sort="type_name_id:asc",
            filters={"folder_id": "root"},
        )


def test_missing_cursor_starts_a_new_page(pagination):
    assert (
        pagination.PaginationCursor.decode(
            None,
            action="list_directory",
            sort="type_name_id:asc",
            filters={"folder_id": "root"},
        )
        is None
    )


@pytest.mark.parametrize("item_count", [0, 1, 2])
def test_cursor_response_contains_page_and_continuation(pagination, item_count):
    items = [
        {"id": "id-1", "_cursor_key": [0, "alpha", "id-1"], "_internal": "hidden"},
        {"id": "id-2", "_cursor_key": [0, "bravo", "id-2"], "_internal": "hidden"},
    ][:item_count]

    response = pagination.make_cursor_response(
        items,
        page_size=1,
        action="list_directory",
        sort="type_name_id:asc",
        filters={"folder_id": "root"},
        cursor_key=lambda item: item["_cursor_key"],
    )

    assert response["items"] == ([{"id": "id-1"}] if item_count else [])
    assert response["page_size"] == 1
    assert response["has_more"] is (item_count > 1)
    decoded = pagination.PaginationCursor.decode(
        response["next_cursor"],
        action="list_directory",
        sort="type_name_id:asc",
        filters={"folder_id": "root"},
        value_types=[int, str, str],
    )
    if item_count > 1:
        assert decoded is not None
        assert decoded.last == [0, "alpha", "id-1"]
    else:
        assert decoded is None


def test_cursor_ttl_defaults_to_no_expiration(pagination, monkeypatch):
    now = 2_000_000_000
    monkeypatch.setattr(fernet_module, "time", SimpleNamespace(time=lambda: now))
    token = pagination.PaginationCursor(
        action="search",
        sort="name:asc",
        filters={"query": "alpha"},
        last=["alpha", 0, "id-1"],
    ).encode()

    monkeypatch.setattr(
        fernet_module, "time", SimpleNamespace(time=lambda: now + 10_000)
    )
    decoded_cursor = pagination.PaginationCursor.decode(
        token,
        action="search",
        sort="name:asc",
        filters={"query": "alpha"},
        value_types=[str, int, str],
    )
    assert decoded_cursor is not None
    assert decoded_cursor.last == ["alpha", 0, "id-1"]


def test_cursor_ttl_rejects_expired_tokens(pagination, monkeypatch):
    now = 2_000_000_000
    monkeypatch.setattr(fernet_module, "time", SimpleNamespace(time=lambda: now))
    token = pagination.PaginationCursor(
        action="view_audit_logs",
        sort="logged_time_id:desc",
        filters={"filters": []},
        last=[1000.0, "audit-1"],
    ).encode()

    monkeypatch.setattr(fernet_module, "time", SimpleNamespace(time=lambda: now + 3601))
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


def test_cursor_response_token_expiration_is_controlled_by_decode_ttl(
    pagination, monkeypatch
):
    now = 2_000_000_000
    monkeypatch.setattr(fernet_module, "time", SimpleNamespace(time=lambda: now))
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
    monkeypatch.setattr(fernet_module, "time", SimpleNamespace(time=lambda: now + 3601))
    with pytest.raises(pagination.CursorError):
        pagination.PaginationCursor.decode(
            response["next_cursor"],
            action="view_audit_logs",
            sort="logged_time_id:desc",
            filters={"filters": []},
            ttl=3600,
            value_types=[(int, float), str],
        )
