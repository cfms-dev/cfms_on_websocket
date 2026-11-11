import pytest

pytestmark = [pytest.mark.integration, pytest.mark.asyncio]


@pytest.mark.parametrize(
    ("action", "data"),
    [
        ("core.setting.list", {}),
        ("core.setting.get", {"namespace": "server"}),
        (
            "core.setting.update",
            {
                "namespace": "server",
                "changes": {"name": {"value": "new", "expected_revision": 0}},
            },
        ),
    ],
)
async def test_setting_actions_require_authentication(client, action, data):
    response = await client.send_request(action, data, include_auth=False)
    assert response["code"] == 401


async def test_setting_protocol_round_trip_and_validation(authenticated_client):
    client = authenticated_client
    listed = await client.send_request("core.setting.list", {"namespace": "server"})
    assert listed["code"] == 200
    assert listed["data"]["items"][0]["option_key"] == "name"
    original = await client.send_request(
        "core.setting.get", {"namespace": "server", "keys": ["name"]}
    )
    assert original["code"] == 200
    initial = original["data"]["settings"]["name"]
    changed = await client.send_request(
        "core.setting.update",
        {
            "namespace": "server",
            "changes": {
                "name": {
                    "value": "Setting API test",
                    "expected_revision": initial["revision"],
                }
            },
        },
    )
    assert changed["code"] == 200
    try:
        assert changed["data"]["settings"]["name"]["value"] == "Setting API test"
        assert (
            changed["data"]["settings"]["name"]["revision"] == initial["revision"] + 1
        )
        read = await client.send_request("core.setting.get", {"namespace": "server"})
        assert read["code"] == 200
        assert read["data"]["settings"]["name"]["value"] == "Setting API test"
        stale = await client.send_request(
            "core.setting.update",
            {
                "namespace": "server",
                "changes": {
                    "name": {"value": "stale", "expected_revision": initial["revision"]}
                },
            },
        )
        assert stale["code"] == 409
        invalid = await client.send_request(
            "core.setting.update",
            {
                "namespace": "server",
                "changes": {"name": {"value": "bad", "expected_revision": True}},
            },
        )
        assert invalid["code"] == 400
        assert invalid["data"]["errors"][0]["loc"] == [
            "changes",
            "name",
            "expected_revision",
        ]
    finally:
        restored = await client.send_request(
            "core.setting.update",
            {
                "namespace": "server",
                "changes": {
                    "name": {
                        "value": initial["value"],
                        "expected_revision": changed["data"]["settings"]["name"][
                            "revision"
                        ],
                    }
                },
            },
        )
        assert restored["code"] == 200
