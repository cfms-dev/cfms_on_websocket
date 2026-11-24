"""Integration tests for CACL DACL authorization, reparenting, and atomic directory deletion."""

from pathlib import Path

import pytest

from include.domains.access.permissions import Permissions
from tests.support.client import CFMSTestClient
from tests.support.utils import assert_error, assert_success, permission_entry

pytestmark = pytest.mark.integration


class TestCaclDaclEndpoints:
    """Test CACL DACL inspection, updates, diagnostics, and anti-lockout."""

    @pytest.mark.asyncio
    async def test_document_and_directory_dacl_round_trip_and_annotations(
        self,
        authenticated_client: CFMSTestClient,
        directory_factory,
        document_factory,
        user_factory,
    ):
        user = await user_factory()
        directory = await directory_factory()
        document = await document_factory(folder_id=directory["folder_id"])

        dir_policy = (
            "inherit off;\n"
            f'allow [TRAVERSE, LIST_DIRECTORY, READ_METADATA] to user("{user["user_id"]}");\n'
        )
        set_dir = assert_success(
            await authenticated_client.set_directory_dacl(
                directory["folder_id"], dir_policy
            )
        )
        assert set_dir["inherit"] is False
        assert set_dir["diagnostics"] == []

        get_dir = assert_success(
            await authenticated_client.get_directory_dacl(
                directory["folder_id"], annotate_users=True
            )
        )
        assert get_dir["inherit"] is False
        assert user["user_id"] in get_dir["dacl"]
        assert user["username"] not in get_dir["dacl"]
        assert user["username"] in get_dir["annotated_dacl"]
        assert get_dir["fingerprint"] == set_dir["fingerprint"]

        doc_policy = (
            f'allow [READ_CONTENT, READ_METADATA] to user("{user["user_id"]}");\n'
            'allow [READ_METADATA] to user("00000000-0000-4000-8000-000000000099");\n'
        )
        set_doc = assert_success(
            await authenticated_client.set_document_dacl(
                document["document_id"], doc_policy
            )
        )
        assert set_doc["inherit"] is True
        assert any(d["code"] == "W301" for d in set_doc["diagnostics"])

        get_doc = assert_success(
            await authenticated_client.get_document_dacl(document["document_id"])
        )
        assert get_doc["inherit"] is True
        assert "00000000-0000-4000-8000-000000000099" in get_doc["dacl"]

        invalid = await authenticated_client.set_document_dacl(
            document["document_id"], "allow [BOGUS_OP] to any;"
        )
        err = assert_error(invalid, 400)
        assert err["data"]["diagnostics"]
        # Failed save must not mutate the persisted DACL.
        after_invalid = assert_success(
            await authenticated_client.get_document_dacl(document["document_id"])
        )
        assert after_invalid["dacl"] == get_doc["dacl"]

    @pytest.mark.asyncio
    async def test_soft_anti_lockout_and_explicit_override(
        self,
        authenticated_client: CFMSTestClient,
        directory_factory,
        user_factory,
        client_factory,
    ):
        user = await user_factory()
        directory = await directory_factory()
        assert_success(
            await authenticated_client.set_directory_dacl(
                directory["folder_id"],
                (
                    "inherit off; "
                    "allow [TRAVERSE, READ_DACL, WRITE_DACL, READ_METADATA] "
                    f'to user("{user["user_id"]}");'
                ),
            )
        )

        user_client = await client_factory()
        assert_success(await user_client.login(user["username"], user["password"]))

        # Removing own write_dacl without allow_self_lockout returns 409 warning.
        blocked = await user_client.set_directory_dacl(
            directory["folder_id"],
            f'inherit off; allow [READ_METADATA] to user("{user["user_id"]}");',
        )
        err = assert_error(blocked, 409)
        assert err["data"]["self_lockout_warning"] is True

        # Retry with allow_self_lockout=True succeeds, and subsequent edits are forbidden.
        assert_success(
            await user_client.set_directory_dacl(
                directory["folder_id"],
                f'inherit off; allow [READ_METADATA] to user("{user["user_id"]}");',
                allow_self_lockout=True,
            )
        )
        assert_error(
            await user_client.set_directory_dacl(
                directory["folder_id"],
                f'inherit off; allow [WRITE_DACL] to user("{user["user_id"]}");',
            ),
            403,
        )

        # Admin with BYPASS_DACL can always recover access.
        assert_success(
            await authenticated_client.set_directory_dacl(
                directory["folder_id"],
                f'inherit off; allow [READ_DACL, WRITE_DACL] to user("{user["user_id"]}");',
            )
        )
        assert_success(await user_client.get_directory_dacl(directory["folder_id"]))

    @pytest.mark.asyncio
    async def test_create_with_initial_dacl_requires_write_dacl_on_parent(
        self,
        authenticated_client: CFMSTestClient,
        directory_factory,
        user_factory,
        client_factory,
        owned_entities,
    ):
        user = await user_factory()
        parent = await directory_factory()
        assert_success(
            await authenticated_client.set_directory_dacl(
                parent["folder_id"],
                (
                    "inherit off; "
                    "allow [TRAVERSE, CREATE_DIRECTORY, CREATE_DOCUMENT] "
                    f'to user("{user["user_id"]}");'
                ),
            )
        )
        user_client = await client_factory()
        assert_success(await user_client.login(user["username"], user["password"]))

        # Creating with initial dacl without write_dacl on parent is rejected (403).
        assert_error(
            await user_client.create_directory(
                "NeedsWriteDacl",
                parent_id=parent["folder_id"],
                dacl="inherit off;",
            ),
            403,
        )
        assert_error(
            await user_client.create_document(
                "DocNeedsWriteDacl",
                folder_id=parent["folder_id"],
                dacl="inherit off;",
            ),
            403,
        )

        # Granting write_dacl allows setting initial dacl (with anti-lockout check).
        assert_success(
            await authenticated_client.set_directory_dacl(
                parent["folder_id"],
                (
                    "inherit off; "
                    "allow [TRAVERSE, CREATE_DIRECTORY, CREATE_DOCUMENT, WRITE_DACL] "
                    f'to user("{user["user_id"]}");'
                ),
            )
        )
        lockout = await user_client.create_directory(
            "LockoutChild",
            parent_id=parent["folder_id"],
            dacl="inherit off;",
        )
        assert assert_error(lockout, 409)["data"]["self_lockout_warning"] is True

        created = assert_success(
            await user_client.create_directory(
                "AllowedChild",
                parent_id=parent["folder_id"],
                dacl=f'inherit off; allow [READ_DACL, WRITE_DACL] to user("{user["user_id"]}");',
            )
        )
        owned_entities["directories"].append(created["id"])
        dacl_info = assert_success(await user_client.get_directory_dacl(created["id"]))
        assert dacl_info["inherit"] is False


class TestCaclAuthorizationSemantics:
    """Test inheritance, traverse, scopes, revisions, atomic deletion, and reparent."""

    @pytest.mark.asyncio
    async def test_ancestor_traverse_and_bypass_traverse_checking_permission(
        self,
        authenticated_client: CFMSTestClient,
        directory_factory,
        document_factory,
        user_factory,
        client_factory,
    ):
        user = await user_factory()
        parent = await directory_factory()
        doc = await document_factory(folder_id=parent["folder_id"])

        assert_success(
            await authenticated_client.set_directory_dacl(
                parent["folder_id"], "inherit off;"
            )
        )
        assert_success(
            await authenticated_client.set_document_dacl(
                doc["document_id"],
                f'inherit off; allow [READ_METADATA] to user("{user["user_id"]}");',
            )
        )

        user_client = await client_factory()
        assert_success(await user_client.login(user["username"], user["password"]))
        # Denied because user lacks TRAVERSE on parent.
        assert_error(await user_client.get_document_info(doc["document_id"]), 403)

        # Granting BYPASS_TRAVERSE_CHECKING bypasses ancestor traverse check.
        assert_success(
            await authenticated_client.change_user_permissions(
                user["user_id"],
                [permission_entry(Permissions.BYPASS_TRAVERSE_CHECKING)],
            )
        )
        assert_success(await user_client.get_document_info(doc["document_id"]))

    @pytest.mark.asyncio
    async def test_revision_get_distinguishes_current_vs_historical_ops(
        self,
        authenticated_client: CFMSTestClient,
        document_factory,
        user_factory,
        client_factory,
        tmp_path: Path,
    ):
        user = await user_factory()
        doc = await document_factory("RevisionAuthDoc")
        doc_id = doc["document_id"]
        first_revs = assert_success(await authenticated_client.list_revisions(doc_id))
        historical_rev_id = first_revs["items"][0]["id"]

        second_file = tmp_path / "v2.bin"
        second_file.write_bytes(b"version-2")
        upload_task = assert_success(await authenticated_client.upload_document(doc_id))
        await authenticated_client.upload_file_to_server(
            upload_task["task_data"]["task_id"], str(second_file)
        )
        all_revs = assert_success(await authenticated_client.list_revisions(doc_id))
        current_rev_id = next(r["id"] for r in all_revs["items"] if r["is_current"])

        # Grant ONLY READ_CONTENT (not READ_REVISION).
        assert_success(
            await authenticated_client.set_document_dacl(
                doc_id,
                f'inherit off; allow [READ_CONTENT] to user("{user["user_id"]}");',
            )
        )
        user_client = await client_factory()
        assert_success(await user_client.login(user["username"], user["password"]))

        assert_success(await user_client.get_revision(current_rev_id))
        assert_error(await user_client.get_revision(historical_rev_id), 403)

        # Grant ONLY READ_REVISION (not READ_CONTENT).
        assert_success(
            await authenticated_client.set_document_dacl(
                doc_id,
                f'inherit off; allow [READ_REVISION] to user("{user["user_id"]}");',
            )
        )
        assert_error(await user_client.get_revision(current_rev_id), 403)
        assert_success(await user_client.get_revision(historical_rev_id))

    @pytest.mark.asyncio
    async def test_directory_soft_delete_is_atomic_and_honors_delete_child(
        self,
        authenticated_client: CFMSTestClient,
        directory_factory,
        document_factory,
        user_factory,
        client_factory,
    ):
        user = await user_factory()
        parent = await directory_factory()
        child_dir = await directory_factory(parent_id=parent["folder_id"])
        protected_doc = await document_factory(
            "ProtectedChildDoc", folder_id=child_dir["folder_id"]
        )

        # User has DELETE on parent & child_dir, but NOT on protected_doc, and NO DIRECTORY_DELETE_CHILD.
        assert_success(
            await authenticated_client.set_directory_dacl(
                parent["folder_id"],
                f'inherit off; allow [TRAVERSE, DELETE] to user("{user["user_id"]}");',
            )
        )
        assert_success(
            await authenticated_client.set_document_dacl(
                protected_doc["document_id"],
                f'inherit off; allow [READ_METADATA] to user("{user["user_id"]}");',
            )
        )

        user_client = await client_factory()
        assert_success(await user_client.login(user["username"], user["password"]))

        assert_error(await user_client.delete_directory(parent["folder_id"]), 403)
        # Atomic check: neither parent, child_dir, nor protected_doc was deleted.
        assert_success(
            await authenticated_client.get_directory_info(parent["folder_id"])
        )
        assert_success(
            await authenticated_client.get_directory_info(child_dir["folder_id"])
        )
        assert_success(
            await authenticated_client.get_document_info(protected_doc["document_id"])
        )

        # Granting DIRECTORY_DELETE_CHILD on parent authorizes the entire subtree delete.
        assert_success(
            await authenticated_client.set_directory_dacl(
                parent["folder_id"],
                (
                    "inherit off; "
                    "allow [TRAVERSE, DELETE, DIRECTORY_DELETE_CHILD] "
                    f'to user("{user["user_id"]}");'
                ),
            )
        )
        assert_success(await user_client.delete_directory(parent["folder_id"]))
        assert_error(
            await authenticated_client.get_directory_info(parent["folder_id"]), 404
        )
        assert_error(
            await authenticated_client.get_document_info(protected_doc["document_id"]),
            404,
        )

    @pytest.mark.asyncio
    async def test_reparent_authorization_and_inherited_dacl_change(
        self,
        authenticated_client: CFMSTestClient,
        directory_factory,
        document_factory,
        user_factory,
        client_factory,
    ):
        actor = await user_factory()
        observer = await user_factory()
        source = await directory_factory()
        target = await directory_factory()
        doc = await document_factory("ReparentAuthDoc", folder_id=source["folder_id"])

        # Source lets observer read; target denies observer.
        assert_success(
            await authenticated_client.set_directory_dacl(
                source["folder_id"],
                (
                    "inherit off;\n"
                    f'allow [TRAVERSE, REPARENT] to user("{actor["user_id"]}");\n'
                    f'allow [TRAVERSE, READ_METADATA] to user("{observer["user_id"]}");\n'
                ),
            )
        )
        assert_success(
            await authenticated_client.set_directory_dacl(
                target["folder_id"],
                f'inherit off; allow [TRAVERSE] to user("{actor["user_id"]}");',
            )
        )

        actor_client = await client_factory()
        assert_success(await actor_client.login(actor["username"], actor["password"]))
        observer_client = await client_factory()
        assert_success(
            await observer_client.login(observer["username"], observer["password"])
        )

        # Observer can read before reparent.
        assert_success(await observer_client.get_document_info(doc["document_id"]))

        # Actor lacks CREATE_DOCUMENT on target -> 403.
        assert_error(
            await actor_client.reparent_document(
                doc["document_id"], target["folder_id"]
            ),
            403,
        )

        # Grant CREATE_DOCUMENT on target -> reparent succeeds.
        assert_success(
            await authenticated_client.set_directory_dacl(
                target["folder_id"],
                (
                    "inherit off; "
                    f'allow [TRAVERSE, CREATE_DOCUMENT] to user("{actor["user_id"]}");'
                ),
            )
        )
        assert_success(
            await actor_client.reparent_document(
                doc["document_id"], target["folder_id"]
            )
        )

        # After reparent, doc inherits target's DACL so observer loses access.
        assert_error(await observer_client.get_document_info(doc["document_id"]), 403)
