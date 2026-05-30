import os

import pytest

from tests.test_client import CFMSTestClient, calculate_sha256
from tests.utils import assert_success


class TestFileTransfer:
    @pytest.mark.asyncio
    async def test_upload_and_download_file(
        self, authenticated_client: CFMSTestClient, document_factory, tmp_path
    ):
        doc = await document_factory(
            "File Transfer Test Doc", upload_file=None
        )  # Don't upload automatically
        doc_id = doc["document_id"]

        # 1. Start an upload task
        upload_resp = await authenticated_client.upload_document(doc_id)
        task_data = assert_success(upload_resp)["task_data"]
        upload_task_id = task_data["task_id"]

        # We will upload pyproject.toml as a test file
        test_file_path = "./pyproject.toml"
        original_hash = calculate_sha256(test_file_path)

        # 2. Upload file chunks over the stream
        await authenticated_client.upload_file_to_server(upload_task_id, test_file_path)

        # 3. Get the latest revision ID
        list_resp = await authenticated_client.list_revisions(doc_id)
        revisions = assert_success(list_resp)["revisions"]
        current_rev = next((r for r in revisions if r["is_current"]), None)
        assert current_rev is not None

        # 4. Prepare download
        get_rev_resp = await authenticated_client.get_revision(current_rev["id"])
        dl_task_id = assert_success(get_rev_resp)["task_data"]["task_id"]

        # 5. Download the file utilizing the new client download stream mechanism
        download_dest = str(tmp_path / "downloaded_test_file.toml")
        await authenticated_client.download_file_from_server(dl_task_id, download_dest)

        # 6. Verify checksum matches
        downloaded_hash = calculate_sha256(download_dest)
        assert original_hash == downloaded_hash
        assert os.path.getsize(test_file_path) == os.path.getsize(download_dest)

    @pytest.mark.asyncio
    async def test_download_invalid_task_id_raises_runtime_error(
        self, authenticated_client: CFMSTestClient, tmp_path
    ):
        download_dest = str(tmp_path / "invalid_download.bin")

        with pytest.raises(
            RuntimeError, match="Download failed \(404\): Task not found"
        ):
            await authenticated_client.download_file_from_server(
                "missing-download-task-id", download_dest
            )

    @pytest.mark.asyncio
    async def test_download_aborted_by_server_hook(
        self, authenticated_client: CFMSTestClient, monkeypatch, tmp_path
    ):
        class FakeFrame:
            def __init__(self, data):
                self.data = data

        class FakeStream:
            def __init__(self):
                self.sent_payloads = []
                self.responses = [
                    FakeFrame(b'{"action":"transfer_file"}'),
                    FakeFrame(b'{"action":"abort"}'),
                ]

            async def send(self, data):
                self.sent_payloads.append(data)

            async def recv(self):
                return self.responses.pop(0)

        fake_stream = FakeStream()
        monkeypatch.setattr(
            authenticated_client.multiplexer, "create_stream", lambda: fake_stream
        )

        with pytest.raises(RuntimeError, match="Server aborted file transfer"):
            await authenticated_client.download_file_from_server(
                "fake-task-id", str(tmp_path / "aborted.bin")
            )

    @pytest.mark.asyncio
    async def test_upload_missing_source_file_raises_clear_error(
        self, authenticated_client: CFMSTestClient, document_factory
    ):
        doc = await document_factory("MissingUploadSourceDoc", upload_file=None)
        doc_id = doc["document_id"]

        upload_resp = await authenticated_client.upload_document(doc_id)
        upload_task_id = assert_success(upload_resp)["task_data"]["task_id"]

        with pytest.raises(FileNotFoundError, match="Upload source file not found"):
            await authenticated_client.upload_file_to_server(
                upload_task_id, "./does-not-exist-upload-source.bin"
            )
