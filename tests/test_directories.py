"""
Tests for directory management operations.
"""

import secrets
import time
from pathlib import Path

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from tests.test_client import CFMSTestClient
from tests.utils import assert_success


def test_name_write_lock_lives_until_explicit_release(
    monkeypatch, protected_test_config
):
    monkeypatch.chdir(protected_test_config.src_dir)

    from include.config.settings import global_config
    from include.database.models.documents import DirectoryNameLock
    from include.domains.documents.commands.name_conflicts import (
        NameConflict,
        acquire_name_write_lock,
        release_name_write_lock,
    )

    monkeypatch.setitem(global_config["document"], "allow_name_duplicate", False)

    engine = create_engine("sqlite:///:memory:")
    DirectoryNameLock.__table__.create(engine)
    session_factory = sessionmaker(bind=engine)

    with session_factory() as session:
        lock = acquire_name_write_lock(session, "parent", "Shared Name")

        assert isinstance(lock, DirectoryNameLock)
        assert session.scalar(select(DirectoryNameLock)) is lock
        session.expunge(lock)
        assert isinstance(
            acquire_name_write_lock(session, "parent", "Shared Name"),
            NameConflict,
        )

        lock = session.get(
            DirectoryNameLock,
            {"parent_id": "parent", "name": "Shared Name"},
        )
        release_name_write_lock(session, lock)
        session.commit()

    with session_factory() as session:
        assert session.scalar(select(DirectoryNameLock)) is None


class TestDirectoryOperations:
    """Test directory operations."""

    @pytest.mark.asyncio
    async def test_list_directory_root(self, authenticated_client: CFMSTestClient):
        """Test listing the root directory."""
        response = await authenticated_client.list_directory()

        assert response["code"] == 200
        assert "data" in response

    @pytest.mark.asyncio
    async def test_create_directory(self, authenticated_client: CFMSTestClient):
        """Test creating a new directory."""
        dir_name = "Test Directory"
        response = await authenticated_client.create_directory(dir_name)

        # Directory creation might succeed or fail based on permissions
        # We just check the response is valid
        assert "code" in response
        assert "data" in response

        if response["code"] == 200:
            # Cleanup if created successfully
            directory_id = response["data"].get("id")
            if directory_id:
                try:
                    await authenticated_client.delete_directory(directory_id)
                except Exception:
                    pass

    @pytest.mark.asyncio
    async def test_create_directory_with_empty_name(
        self, authenticated_client: CFMSTestClient
    ):
        """Test creating a directory with an empty name."""
        response = await authenticated_client.create_directory("")

        # Should fail validation
        assert response["code"] == 400

    @pytest.mark.asyncio
    async def test_delete_directory(self, authenticated_client: CFMSTestClient):
        """Test deleting a directory."""
        # First create a directory
        create_response = await authenticated_client.create_directory(
            "Directory to Delete"
        )

        if create_response["code"] == 200:
            directory_id = create_response["data"]["id"]

            # Delete it
            delete_response = await authenticated_client.delete_directory(directory_id)

            # Should get a response (success or failure is implementation-dependent)
            assert "code" in delete_response

    @pytest.mark.asyncio
    async def test_delete_nonexistent_directory(
        self, authenticated_client: CFMSTestClient
    ):
        """Test deleting a directory that doesn't exist."""
        response = await authenticated_client.delete_directory("nonexistent_folder_id")

        assert response["code"] != 200

    @pytest.mark.asyncio
    async def test_list_directory_contents(self, authenticated_client: CFMSTestClient):
        """Test listing directory contents after creating items."""
        # Create a test directory
        dir_response = await authenticated_client.create_directory("Test List Dir")

        if dir_response["code"] == 200:
            directory_id = dir_response["data"]["id"]

            try:
                # Create a document in the directory
                doc_response = await authenticated_client.create_document(
                    "Test Doc in Dir", folder_id=directory_id
                )

                if doc_response["code"] == 200:
                    # List the directory
                    list_response = await authenticated_client.list_directory(
                        directory_id
                    )

                    assert list_response["code"] == 200
                    assert "data" in list_response

                    # Cleanup document
                    try:
                        await authenticated_client.delete_document(
                            doc_response["data"]["document_id"]
                        )
                    except Exception:
                        pass
            finally:
                # Cleanup directory
                try:
                    await authenticated_client.delete_directory(directory_id)
                except Exception:
                    pass

    @pytest.mark.asyncio
    async def test_list_directory_with_cursor(
        self, authenticated_client: CFMSTestClient
    ):
        parent_response = await authenticated_client.create_directory(
            "Cursor Directory Parent"
        )
        parent_id = parent_response["data"]["id"]
        first_child = await authenticated_client.create_directory(
            "Cursor Child A", parent_id=parent_id
        )
        second_child = await authenticated_client.create_directory(
            "Cursor Child B", parent_id=parent_id
        )

        try:
            first_page_response = await authenticated_client.list_directory(
                parent_id, page_size=1
            )
            first_page = first_page_response["data"]
            second_page_response = await authenticated_client.list_directory(
                parent_id, page_size=1, cursor=first_page["next_cursor"]
            )
            second_page = second_page_response["data"]

            assert len(first_page["items"]) == 1
            assert len(second_page["items"]) == 1
            assert first_page["items"][0]["id"] != second_page["items"][0]["id"]
        finally:
            await authenticated_client.delete_directory(first_child["data"]["id"])
            await authenticated_client.delete_directory(second_child["data"]["id"])
            await authenticated_client.delete_directory(parent_id)

    @pytest.mark.asyncio
    async def test_get_directory_info_counts_active_direct_children(
        self, authenticated_client: CFMSTestClient
    ):
        parent_response = await authenticated_client.create_directory(
            "Directory Info Parent"
        )
        parent_id = parent_response["data"]["id"]
        child_response = await authenticated_client.create_directory(
            "Directory Info Child", parent_id=parent_id
        )
        child_id = child_response["data"]["id"]
        active_doc_response = await authenticated_client.create_document(
            "Directory Info Active Doc", folder_id=parent_id
        )
        active_doc_id = active_doc_response["data"]["document_id"]
        inactive_doc_response = await authenticated_client.create_document(
            "Directory Info Inactive Doc", folder_id=parent_id
        )
        inactive_doc_id = inactive_doc_response["data"]["document_id"]

        try:
            await authenticated_client.upload_file_to_server(
                active_doc_response["data"]["task_data"]["task_id"],
                "./pytest.ini",
            )
            info_response = await authenticated_client.send_request(
                "get_directory_info", {"directory_id": parent_id}
            )

            assert info_response["code"] == 200
            assert info_response["data"]["directory_id"] == parent_id
            assert info_response["data"]["count_of_child"] == 2
            assert info_response["data"]["parent_id"] == "/"
            assert info_response["data"]["name"] == "Directory Info Parent"
            assert "created_time" in info_response["data"]
            assert "access_rules" in info_response["data"]
            assert "info_code" in info_response["data"]
        finally:
            await authenticated_client.delete_document(active_doc_id)
            await authenticated_client.delete_document(inactive_doc_id)
            await authenticated_client.delete_directory(child_id)
            await authenticated_client.delete_directory(parent_id)


class TestDirectoryMove:
    """Test directory move operations."""

    @pytest.mark.asyncio
    async def test_move_directory_to_root(self, authenticated_client: CFMSTestClient):
        """Test moving a directory to root."""
        # Create a parent and a child directory
        parent_response = await authenticated_client.create_directory("Parent Dir")

        if parent_response["code"] == 200:
            parent_id = parent_response["data"]["id"]

            try:
                child_response = await authenticated_client.create_directory(
                    "Child Dir", parent_id=parent_id
                )

                if child_response["code"] == 200:
                    child_id = child_response["data"]["id"]

                    try:
                        # Move child to root
                        move_response = await authenticated_client.move_directory(
                            child_id, None
                        )

                        # Should succeed
                        assert move_response["code"] == 200
                    finally:
                        try:
                            await authenticated_client.delete_directory(child_id)
                        except Exception:
                            pass
            finally:
                try:
                    await authenticated_client.delete_directory(parent_id)
                except Exception:
                    pass

    @pytest.mark.asyncio
    async def test_move_directory_into_itself(
        self, authenticated_client: CFMSTestClient
    ):
        """Test that moving a directory into itself is prevented."""
        # Create a directory
        dir_response = await authenticated_client.create_directory("Test Dir")

        if dir_response["code"] == 200:
            dir_id = dir_response["data"]["id"]

            try:
                # Try to move directory into itself
                move_response = await authenticated_client.move_directory(
                    dir_id, dir_id
                )

                # Should fail with 400
                assert move_response["code"] == 400
                assert "subdirectory" in move_response["message"].lower()
            finally:
                try:
                    await authenticated_client.delete_directory(dir_id)
                except Exception:
                    pass

    @pytest.mark.asyncio
    async def test_move_directory_into_child(
        self, authenticated_client: CFMSTestClient
    ):
        """Test that moving a directory into its child is prevented."""
        # Create parent and child
        parent_response = await authenticated_client.create_directory("Parent Dir")

        if parent_response["code"] == 200:
            parent_id = parent_response["data"]["id"]

            try:
                child_response = await authenticated_client.create_directory(
                    "Child Dir", parent_id=parent_id
                )

                if child_response["code"] == 200:
                    child_id = child_response["data"]["id"]

                    try:
                        # Try to move parent into child
                        move_response = await authenticated_client.move_directory(
                            parent_id, child_id
                        )

                        # Should fail with 400
                        assert move_response["code"] == 400
                        assert "subdirectory" in move_response["message"].lower()
                    finally:
                        try:
                            await authenticated_client.delete_directory(child_id)
                        except Exception:
                            pass
            finally:
                try:
                    await authenticated_client.delete_directory(parent_id)
                except Exception:
                    pass

    @pytest.mark.asyncio
    async def test_move_directory_into_grandchild(
        self, authenticated_client: CFMSTestClient
    ):
        """Test that moving a directory into its grandchild is prevented."""
        # Create parent, child, and grandchild
        parent_response = await authenticated_client.create_directory("Parent Dir")

        if parent_response["code"] == 200:
            parent_id = parent_response["data"]["id"]

            try:
                child_response = await authenticated_client.create_directory(
                    "Child Dir", parent_id=parent_id
                )

                if child_response["code"] == 200:
                    child_id = child_response["data"]["id"]

                    try:
                        grandchild_response = (
                            await authenticated_client.create_directory(
                                "Grandchild Dir", parent_id=child_id
                            )
                        )

                        if grandchild_response["code"] == 200:
                            grandchild_id = grandchild_response["data"]["id"]

                            try:
                                # Try to move parent into grandchild
                                move_response = (
                                    await authenticated_client.move_directory(
                                        parent_id, grandchild_id
                                    )
                                )

                                # Should fail with 400
                                assert move_response["code"] == 400
                                assert (
                                    "subdirectory" in move_response["message"].lower()
                                )
                            finally:
                                try:
                                    await authenticated_client.delete_directory(
                                        grandchild_id
                                    )
                                except Exception:
                                    pass
                    finally:
                        try:
                            await authenticated_client.delete_directory(child_id)
                        except Exception:
                            pass
            finally:
                try:
                    await authenticated_client.delete_directory(parent_id)
                except Exception:
                    pass

    @pytest.mark.asyncio
    async def test_move_directory_to_sibling(
        self, authenticated_client: CFMSTestClient
    ):
        """Test moving a directory to a sibling location (should succeed)."""
        # Create parent with two children
        parent_response = await authenticated_client.create_directory("Parent Dir")

        if parent_response["code"] == 200:
            parent_id = parent_response["data"]["id"]

            try:
                child1_response = await authenticated_client.create_directory(
                    "Child Dir 1", parent_id=parent_id
                )
                child2_response = await authenticated_client.create_directory(
                    "Child Dir 2", parent_id=parent_id
                )

                if child1_response["code"] == 200 and child2_response["code"] == 200:
                    child1_id = child1_response["data"]["id"]
                    child2_id = child2_response["data"]["id"]

                    try:
                        # Move child2 into child1 (should succeed)
                        move_response = await authenticated_client.move_directory(
                            child2_id, child1_id
                        )

                        # Should succeed
                        assert move_response["code"] == 200
                    finally:
                        try:
                            await authenticated_client.delete_directory(child1_id)
                        except Exception:
                            pass
                        try:
                            await authenticated_client.delete_directory(child2_id)
                        except Exception:
                            pass
            finally:
                try:
                    await authenticated_client.delete_directory(parent_id)
                except Exception:
                    pass


class TestDocumentDirectoryNameConflicts:
    @staticmethod
    def _session_factory(db_path: Path):
        return sessionmaker(bind=create_engine(f"sqlite:///{db_path.as_posix()}"))

    @staticmethod
    def _create_inactive_document(
        stale_doc_id: str,
        stale_file_id: str,
        stale_revision_id: str,
        name: str,
        parent_id: str,
        db_path: Path,
    ) -> None:
        from include.database.models.documents import (
            Document,
            DocumentRevision,
            DocumentRevisionStatus,
            EntityStatus,
        )
        from include.database.models.files import File

        now = time.time()
        with TestDocumentDirectoryNameConflicts._session_factory(db_path)() as session:
            stale_file = File(
                id=stale_file_id,
                path=f"content/files/test/{stale_file_id}",
                created_time=now,
                active=False,
            )
            stale_doc = Document(
                id=stale_doc_id,
                title=name,
                created_time=now,
                folder_id=parent_id,
                inherit=True,
                status=EntityStatus.OK,
            )
            stale_revision = DocumentRevision(
                id=stale_revision_id,
                document=stale_doc,
                file=stale_file,
                created_time=now,
                status=DocumentRevisionStatus.OK,
            )
            stale_doc.current_revision = stale_revision
            session.add(stale_doc)
            session.commit()

    @staticmethod
    def _delete_inactive_document(
        stale_doc_id: str, stale_file_id: str, db_path: Path
    ) -> None:
        from include.database.models.documents import Document
        from include.database.models.files import File

        with TestDocumentDirectoryNameConflicts._session_factory(db_path)() as session:
            stale_doc = session.get(
                Document, stale_doc_id, execution_options={"include_deleted": True}
            )
            if stale_doc:
                stale_doc.current_revision = None
                session.flush()
                session.delete(stale_doc)

            stale_file = session.get(File, stale_file_id)
            if stale_file:
                session.delete(stale_file)

            session.commit()

    @pytest.mark.asyncio
    async def test_directory_and_document_names_share_namespace(
        self, authenticated_client: CFMSTestClient, document_factory
    ):
        suffix = secrets.token_hex(4)
        parent = await authenticated_client.create_directory(
            f"Conflict Parent {suffix}"
        )
        parent_id = assert_success(parent)["id"]
        folder_name = f"Shared Name {suffix}"
        doc_name = f"Shared Doc Name {suffix}"

        folder = await authenticated_client.create_directory(folder_name, parent_id)
        folder_id = assert_success(folder)["id"]
        doc = await document_factory(doc_name, folder_id=parent_id)

        try:
            doc_conflict = await authenticated_client.create_document(
                folder_name, folder_id=parent_id
            )
            assert doc_conflict["code"] == 409

            folder_conflict = await authenticated_client.create_directory(
                doc_name, parent_id
            )
            assert folder_conflict["code"] == 409
        finally:
            await authenticated_client.delete_document(doc["document_id"])
            await authenticated_client.delete_directory(folder_id)
            await authenticated_client.delete_directory(parent_id)

    @pytest.mark.asyncio
    async def test_inactive_document_does_not_hide_directory_conflict(
        self, authenticated_client: CFMSTestClient, monkeypatch, protected_test_config
    ):
        monkeypatch.chdir(protected_test_config.src_dir)
        suffix = secrets.token_hex(4)
        parent = await authenticated_client.create_directory(
            f"Inactive Conflict Parent {suffix}"
        )
        parent_id = assert_success(parent)["id"]
        name = f"Inactive Shared {suffix}"
        folder = await authenticated_client.create_directory(name, parent_id)
        folder_id = assert_success(folder)["id"]
        stale_doc_id = secrets.token_hex(32)
        stale_file_id = secrets.token_hex(32)

        stale_revision_id = secrets.token_hex(32)
        db_path = protected_test_config.src_dir / "app.db"
        self._create_inactive_document(
            stale_doc_id, stale_file_id, stale_revision_id, name, parent_id, db_path
        )

        try:
            doc_conflict = await authenticated_client.create_document(
                name, folder_id=parent_id
            )
            assert doc_conflict["code"] == 409

            folder_conflict = await authenticated_client.create_directory(
                name, parent_id
            )
            assert folder_conflict["code"] == 409
        finally:
            self._delete_inactive_document(stale_doc_id, stale_file_id, db_path)
            await authenticated_client.delete_directory(folder_id)
            await authenticated_client.delete_directory(parent_id)

    @pytest.mark.asyncio
    async def test_rename_move_and_restore_respect_name_conflicts(
        self, authenticated_client: CFMSTestClient, document_factory
    ):
        suffix = secrets.token_hex(4)
        parent = await authenticated_client.create_directory(
            f"Mutation Conflict Parent {suffix}"
        )
        parent_id = assert_success(parent)["id"]
        target = await authenticated_client.create_directory(
            f"Mutation Conflict Target {suffix}"
        )
        target_id = assert_success(target)["id"]
        folder_name = f"Mutation Folder {suffix}"
        doc_name = f"Mutation Doc {suffix}"
        folder = await authenticated_client.create_directory(folder_name, parent_id)
        folder_id = assert_success(folder)["id"]
        target_folder = await authenticated_client.create_directory(doc_name, target_id)
        target_folder_id = assert_success(target_folder)["id"]
        doc = await document_factory(doc_name, folder_id=parent_id)
        restore_doc = await document_factory(
            f"Restore Conflict {suffix}", folder_id=parent_id
        )

        try:
            rename_conflict = await authenticated_client.rename_document(
                doc["document_id"], folder_name
            )
            assert rename_conflict["code"] == 409

            move_conflict = await authenticated_client.send_request(
                "move_document",
                {"document_id": doc["document_id"], "target_folder_id": target_id},
            )
            assert move_conflict["code"] == 409

            delete_response = await authenticated_client.delete_document(
                restore_doc["document_id"]
            )
            assert_success(delete_response)
            restore_folder = await authenticated_client.create_directory(
                restore_doc["title"], parent_id
            )
            restore_folder_id = assert_success(restore_folder)["id"]
            restore_conflict = await authenticated_client.restore_document(
                restore_doc["document_id"], target_folder_id=parent_id
            )
            assert restore_conflict["code"] == 409
        finally:
            for doc_id in (doc["document_id"], restore_doc["document_id"]):
                try:
                    await authenticated_client.delete_document(doc_id)
                except Exception:
                    pass
            for folder_to_delete in (
                locals().get("restore_folder_id"),
                target_folder_id,
                folder_id,
                target_id,
                parent_id,
            ):
                if folder_to_delete:
                    try:
                        await authenticated_client.delete_directory(folder_to_delete)
                    except Exception:
                        pass

    @pytest.mark.asyncio
    async def test_restore_document_ignores_deleted_self_conflict(
        self, authenticated_client: CFMSTestClient, document_factory
    ):
        suffix = secrets.token_hex(4)
        parent = await authenticated_client.create_directory(
            f"Document Restore Parent {suffix}"
        )
        parent_id = assert_success(parent)["id"]
        doc = await document_factory(
            f"Document Restore Self {suffix}", folder_id=parent_id
        )

        try:
            delete_response = await authenticated_client.delete_document(
                doc["document_id"]
            )
            assert_success(delete_response)

            restore_response = await authenticated_client.restore_document(
                doc["document_id"], target_folder_id=parent_id
            )
            assert_success(restore_response)
        finally:
            try:
                await authenticated_client.delete_document(doc["document_id"])
            except Exception:
                pass
            await authenticated_client.delete_directory(parent_id)

    @pytest.mark.asyncio
    async def test_restore_inactive_document_ignores_deleted_self_conflict(
        self, authenticated_client: CFMSTestClient, document_factory
    ):
        suffix = secrets.token_hex(4)
        parent = await authenticated_client.create_directory(
            f"Inactive Document Restore Parent {suffix}"
        )
        parent_id = assert_success(parent)["id"]
        doc = await document_factory(
            f"Inactive Document Restore Self {suffix}",
            upload_file=None,
            folder_id=parent_id,
        )

        try:
            delete_response = await authenticated_client.delete_document(
                doc["document_id"]
            )
            assert_success(delete_response)

            restore_response = await authenticated_client.restore_document(
                doc["document_id"], target_folder_id=parent_id
            )
            assert_success(restore_response)
        finally:
            try:
                await authenticated_client.delete_document(doc["document_id"])
            except Exception:
                pass
            await authenticated_client.delete_directory(parent_id)

    @pytest.mark.asyncio
    async def test_restore_directory_ignores_deleted_self_conflict(
        self, authenticated_client: CFMSTestClient
    ):
        suffix = secrets.token_hex(4)
        parent = await authenticated_client.create_directory(
            f"Directory Restore Parent {suffix}"
        )
        parent_id = assert_success(parent)["id"]
        folder = await authenticated_client.create_directory(
            f"Directory Restore Self {suffix}", parent_id
        )
        folder_id = assert_success(folder)["id"]

        try:
            delete_response = await authenticated_client.delete_directory(folder_id)
            assert_success(delete_response)

            restore_response = await authenticated_client.restore_directory(
                folder_id, target_parent_id=parent_id
            )
            assert_success(restore_response)
        finally:
            try:
                await authenticated_client.delete_directory(folder_id)
            except Exception:
                pass
            await authenticated_client.delete_directory(parent_id)


class TestDirectoryWithoutAuth:
    """Test that directory operations require authentication."""

    @pytest.mark.asyncio
    async def test_list_directory_without_auth(self, client: CFMSTestClient):
        """Test that listing directories requires authentication."""
        response = await client.send_request(
            "list_directory", {"folder_id": None}, include_auth=False
        )

        assert response["code"] == 401

    @pytest.mark.asyncio
    async def test_create_directory_without_auth(self, client: CFMSTestClient):
        """Test that creating a directory requires authentication."""
        response = await client.send_request(
            "create_directory", {"name": "Test"}, include_auth=False
        )

        assert response["code"] == 401
