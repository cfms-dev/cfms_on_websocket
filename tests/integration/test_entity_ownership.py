from types import SimpleNamespace

import pytest

from tests.support.entities import document_factory, owned_entities


class EntityClient:
    def __init__(self, fail_identifier=None):
        self.remaining = {
            "document-1",
            "document-2",
            "parent",
            "child",
            "group",
            "user",
        }
        self.fail_identifier = fail_identifier

    async def delete_document(self, identifier):
        return {"code": 200}

    async def purge_document(self, identifier):
        if identifier == self.fail_identifier:
            return {"code": 500}
        self.remaining.discard(identifier)
        return {"code": 200}

    async def delete_directory(self, identifier):
        return {"code": 200}

    async def purge_directory(self, identifier):
        if identifier == "parent":
            assert "child" not in self.remaining
        self.remaining.discard(identifier)
        return {"code": 200}

    async def send_request(self, _action, data):
        self.remaining.discard(data["group_name"])
        return {"code": 200}

    async def delete_user(self, identifier):
        self.remaining.discard(identifier)
        return {"code": 200}


@pytest.mark.unit
@pytest.mark.asyncio
@pytest.mark.parametrize("failure", [False, True])
@pytest.mark.parametrize("body_failure", [False, True])
async def test_owned_entities_release_every_resource_even_after_cleanup_failure(
    failure,
    body_failure,
):
    client = EntityClient("document-2" if failure else None)
    ownership = owned_entities.__wrapped__(client)
    entities = await anext(ownership)
    entities["documents"].extend(["document-1", "document-2"])
    entities["directories"].extend(["parent", "child"])
    entities["groups"].append("group")
    entities["users"].append("user")

    close = (
        ownership.athrow(RuntimeError("body failed"))
        if body_failure
        else ownership.aclose()
    )
    if failure:
        with pytest.raises(ExceptionGroup) as caught:
            await close
        assert len(caught.value.exceptions) == 1
        assert isinstance(caught.value.exceptions[0], AssertionError)
        assert client.remaining == {"document-2"}
    else:
        if body_failure:
            with pytest.raises(RuntimeError, match="body failed"):
                await close
        else:
            await close
        assert client.remaining == set()


@pytest.mark.unit
@pytest.mark.asyncio
async def test_failed_document_upload_is_registered_for_cleanup():
    async def create_document(_title, _folder_id):
        return {
            "code": 200,
            "data": {"document_id": "document-1", "task_data": {"task_id": "task"}},
        }

    async def upload_file(*_args):
        raise OSError("upload failed")

    client = SimpleNamespace(
        create_document=create_document, upload_file_to_server=upload_file
    )
    entities = {"documents": []}
    create = await document_factory.__wrapped__(client, entities)

    with pytest.raises(OSError, match="upload failed"):
        await create("document")

    assert entities["documents"] == ["document-1"]
