from pathlib import Path

import pytest
import pytest_asyncio

from tests.support.client import CFMSTestClient
from tests.support.utils import assert_error, assert_success

pytestmark = pytest.mark.integration


@pytest_asyncio.fixture
async def revision_history(authenticated_client, document_factory, tmp_path: Path):
    document = await document_factory("Revision History")
    document_id = document["document_id"]
    initial = assert_success(await authenticated_client.list_revisions(document_id))
    original_revision_id = initial["items"][0]["id"]
    payload = tmp_path / "second-revision.bin"
    payload.write_bytes(b"second revision content")
    task = assert_success(await authenticated_client.upload_document(document_id))
    await authenticated_client.upload_file_to_server(
        task["task_data"]["task_id"], str(payload)
    )
    current = assert_success(await authenticated_client.list_revisions(document_id))
    current_revision_id = next(
        item["id"] for item in current["items"] if item["is_current"]
    )
    assert current_revision_id != original_revision_id
    return {
        "document_id": document_id,
        "original_revision_id": original_revision_id,
        "current_revision_id": current_revision_id,
    }


class TestRevisionOperations:
    @pytest.mark.asyncio
    async def test_created_document_has_one_current_revision(
        self,
        authenticated_client: CFMSTestClient,
        document_factory,
    ):
        document = await document_factory("Initial Revision")

        data = assert_success(
            await authenticated_client.list_revisions(document["document_id"])
        )

        assert len(data["items"]) == 1
        assert data["items"][0]["is_current"] is True

    @pytest.mark.asyncio
    async def test_upload_adds_one_revision_and_makes_it_current(
        self,
        authenticated_client: CFMSTestClient,
        document_factory,
        tmp_path: Path,
    ):
        document = await document_factory("New Revision")
        document_id = document["document_id"]
        original = assert_success(
            await authenticated_client.list_revisions(document_id)
        )["items"][0]["id"]
        payload = tmp_path / "new-revision.bin"
        payload.write_bytes(b"new revision content")
        task = assert_success(await authenticated_client.upload_document(document_id))

        await authenticated_client.upload_file_to_server(
            task["task_data"]["task_id"], str(payload)
        )

        items = assert_success(await authenticated_client.list_revisions(document_id))[
            "items"
        ]
        assert len(items) == 2
        original_revision = next(item for item in items if item["id"] == original)
        new_revision = next(item for item in items if item["id"] != original)
        assert original_revision["is_current"] is False
        assert new_revision["is_current"] is True

    @pytest.mark.asyncio
    async def test_list_revisions_cursor_returns_each_revision_once(
        self,
        authenticated_client: CFMSTestClient,
        revision_history,
    ):
        document_id = revision_history["document_id"]

        first = assert_success(
            await authenticated_client.list_revisions(document_id, page_size=1)
        )
        second = assert_success(
            await authenticated_client.list_revisions(
                document_id, page_size=1, cursor=first["next_cursor"]
            )
        )

        assert len(first["items"]) == len(second["items"]) == 1
        assert {item["id"] for item in first["items"] + second["items"]} == {
            revision_history["original_revision_id"],
            revision_history["current_revision_id"],
        }
        assert first["has_more"] is True
        assert second["has_more"] is False

    @pytest.mark.asyncio
    async def test_get_revision(
        self,
        authenticated_client: CFMSTestClient,
        revision_history,
    ):
        revision_id = revision_history["current_revision_id"]

        data = assert_success(await authenticated_client.get_revision(revision_id))

        assert data["task_data"]["task_id"]

    @pytest.mark.asyncio
    async def test_set_document_revision(
        self,
        authenticated_client: CFMSTestClient,
        revision_history,
    ):
        document_id = revision_history["document_id"]
        original_id = revision_history["original_revision_id"]

        response = await authenticated_client.set_document_revision(
            document_id, original_id
        )

        assert_success(response)
        items = assert_success(await authenticated_client.list_revisions(document_id))[
            "items"
        ]
        assert {item["id"]: item["is_current"] for item in items} == {
            original_id: True,
            revision_history["current_revision_id"]: False,
        }

    @pytest.mark.asyncio
    async def test_delete_revision(
        self,
        authenticated_client: CFMSTestClient,
        revision_history,
    ):
        document_id = revision_history["document_id"]
        original_id = revision_history["original_revision_id"]

        response = await authenticated_client.delete_revision(original_id)

        assert_success(response)
        items = assert_success(await authenticated_client.list_revisions(document_id))[
            "items"
        ]
        assert [(item["id"], item["is_current"]) for item in items] == [
            (revision_history["current_revision_id"], True)
        ]

    @pytest.mark.asyncio
    async def test_list_revisions_missing_doc(
        self, authenticated_client: CFMSTestClient
    ):
        response = await authenticated_client.list_revisions("invalid-doc-id-12345")

        assert_error(response, 404)
