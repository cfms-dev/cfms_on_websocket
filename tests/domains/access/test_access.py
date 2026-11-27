"""Integration tests for CACL DACL authorization, reparenting, and atomic directory deletion."""

from pathlib import Path

import pytest
from cacl_compiler import AtomicOp

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

    @pytest.mark.asyncio
    async def test_set_dacl_authorizes_before_compiling_invalid_source(
        self,
        authenticated_client: CFMSTestClient,
        directory_factory,
        document_factory,
        user_factory,
        client_factory,
    ):
        user = await user_factory()
        directory = await directory_factory()
        doc = await document_factory("AuthBeforeCompileDoc")

        user_client = await client_factory()
        assert_success(await user_client.login(user["username"], user["password"]))

        # User lacks WRITE_DACL -> must return 403 even when CACL syntax is invalid.
        assert_error(
            await user_client.set_directory_dacl(
                directory["folder_id"], "allow [INVALID_OP] to any;"
            ),
            403,
        )
        assert_error(
            await user_client.set_document_dacl(
                doc["document_id"], "allow [INVALID_OP] to any;"
            ),
            403,
        )

    @pytest.mark.asyncio
    async def test_reparent_authorizes_before_topology_and_same_parent_checks(
        self,
        authenticated_client: CFMSTestClient,
        directory_factory,
        document_factory,
        user_factory,
        client_factory,
    ):
        actor = await user_factory()
        parent = await directory_factory()
        child = await directory_factory(parent_id=parent["folder_id"])
        grandchild = await directory_factory(parent_id=child["folder_id"])
        doc = await document_factory("ReparentOrderDoc", folder_id=parent["folder_id"])

        assert_success(
            await authenticated_client.set_directory_dacl(
                parent["folder_id"], "inherit off;"
            )
        )

        actor_client = await client_factory()
        assert_success(await actor_client.login(actor["username"], actor["password"]))

        assert_error(
            await actor_client.reparent_directory(
                child["folder_id"], parent["folder_id"]
            ),
            403,
        )
        assert_error(
            await actor_client.reparent_directory(
                parent["folder_id"], parent["folder_id"]
            ),
            403,
        )
        assert_error(
            await actor_client.reparent_directory(
                parent["folder_id"], grandchild["folder_id"]
            ),
            403,
        )
        assert_error(
            await actor_client.reparent_document(
                doc["document_id"], parent["folder_id"]
            ),
            403,
        )

    @pytest.mark.asyncio
    async def test_directory_create_rejects_removed_protocol30_fields(
        self,
        authenticated_client: CFMSTestClient,
    ):
        for extra_field, extra_value in (
            ("access_rules", {}),
            ("inherit_parent", False),
        ):
            response = await authenticated_client.send_request(
                "core.directory.create",
                {"name": "LegacyBlockedDir", extra_field: extra_value},
            )
            assert_error(response, 400)

    @pytest.mark.asyncio
    async def test_create_document_self_lockout_and_dacl_get_forbidden(
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
                    "allow [TRAVERSE, CREATE_DOCUMENT, WRITE_DACL] "
                    f'to user("{user["user_id"]}");'
                ),
            )
        )
        user_client = await client_factory()
        assert_success(await user_client.login(user["username"], user["password"]))

        blocked = await user_client.create_document(
            "LockoutDoc",
            folder_id=parent["folder_id"],
            dacl="inherit off;",
        )
        assert assert_error(blocked, 409)["data"]["self_lockout_warning"] is True

        created = assert_success(
            await user_client.create_document(
                "LockoutDocOverride",
                folder_id=parent["folder_id"],
                dacl="inherit off;",
                allow_self_lockout=True,
            )
        )
        owned_entities["documents"].append(created["document_id"])

        assert_error(await user_client.get_directory_dacl(parent["folder_id"]), 403)
        assert_error(await user_client.get_document_dacl(created["document_id"]), 403)

    @pytest.mark.asyncio
    async def test_directory_purge_is_atomic_on_descendant_denial(
        self,
        authenticated_client: CFMSTestClient,
        directory_factory,
        document_factory,
        user_factory,
        client_factory,
    ):
        actor = await user_factory(permissions=[permission_entry(Permissions.PURGE)])
        parent = await directory_factory()
        child_dir = await directory_factory(parent_id=parent["folder_id"])
        protected_doc = await document_factory(
            "ProtectedPurgeDoc", folder_id=child_dir["folder_id"]
        )

        # Grant PURGE on parent & child_dir (via inheritance), deny PURGE on descendant doc.
        assert_success(
            await authenticated_client.set_directory_dacl(
                parent["folder_id"],
                (
                    "inherit off; "
                    "allow [TRAVERSE, DELETE, DIRECTORY_DELETE_CHILD, LIST_DELETED, PURGE] "
                    f'to user("{actor["user_id"]}");'
                ),
            )
        )
        assert_success(
            await authenticated_client.set_document_dacl(
                protected_doc["document_id"],
                f'inherit on; deny [PURGE] to user("{actor["user_id"]}");',
            )
        )

        actor_client = await client_factory()
        assert_success(await actor_client.login(actor["username"], actor["password"]))
        assert_success(await actor_client.delete_directory(parent["folder_id"]))

        assert_error(await actor_client.purge_directory(parent["folder_id"]), 403)

        # Atomic check: parent, child_dir, and protected_doc still exist in deleted state.
        deleted_root = assert_success(
            await authenticated_client.list_deleted_items("/")
        )
        assert any(item["id"] == parent["folder_id"] for item in deleted_root["items"])
        deleted_child = assert_success(
            await authenticated_client.list_deleted_items(parent["folder_id"])
        )
        assert any(
            item["id"] == child_dir["folder_id"] for item in deleted_child["items"]
        )
        deleted_grandchild = assert_success(
            await authenticated_client.list_deleted_items(child_dir["folder_id"])
        )
        assert any(
            item["id"] == protected_doc["document_id"]
            for item in deleted_grandchild["items"]
        )

    @pytest.mark.asyncio
    async def test_directory_restore_scopes_to_subtree_avoids_old_name_collision_and_checks_descendants(
        self,
        authenticated_client: CFMSTestClient,
        directory_factory,
        document_factory,
        user_factory,
        client_factory,
        owned_entities,
    ):
        actor = await user_factory()
        parent = await directory_factory("RestoreScopeParent")
        sibling = await directory_factory(
            "RestoreScopeSibling", parent_id=parent["folder_id"]
        )
        target = await directory_factory("RestoreTarget", parent_id=parent["folder_id"])
        nested_dir = await directory_factory("NestedDir", parent_id=target["folder_id"])
        nested_doc = await document_factory(
            "NestedDoc", folder_id=nested_dir["folder_id"]
        )
        dest_parent = await directory_factory("RestoreDest")

        assert_success(
            await authenticated_client.set_directory_dacl(
                parent["folder_id"],
                (
                    "inherit off; "
                    f'allow [TRAVERSE, RESTORE] to user("{actor["user_id"]}");'
                ),
            )
        )
        # Deny RESTORE on sibling so cross-subtree bleed would also violate authz.
        assert_success(
            await authenticated_client.set_directory_dacl(
                sibling["folder_id"],
                f'inherit on; deny [RESTORE] to user("{actor["user_id"]}");',
            )
        )
        assert_success(
            await authenticated_client.set_directory_dacl(
                dest_parent["folder_id"],
                (
                    "inherit off; "
                    f'allow [TRAVERSE, CREATE_DIRECTORY, LIST_DIRECTORY] to user("{actor["user_id"]}");'
                ),
            )
        )
        # Initially block RESTORE on nested_doc to verify atomic 403 on descendant denial.
        assert_success(
            await authenticated_client.set_document_dacl(
                nested_doc["document_id"],
                f'inherit on; deny [RESTORE] to user("{actor["user_id"]}");',
            )
        )

        assert_success(await authenticated_client.delete_directory(parent["folder_id"]))

        # Occupy target's original name under parent (after restoring/simulating or in new active dest):
        # Also test collision at old (parent_id, name) by placing an active node with same name under parent
        # using a fresh parent-level active folder isn't possible while parent is deleted, so restore target
        # into dest_parent (different parent) with a new name while a sibling shares op_id.
        actor_client = await client_factory()
        assert_success(await actor_client.login(actor["username"], actor["password"]))

        # Denied atomically because nested_doc denies RESTORE.
        assert_error(
            await actor_client.restore_directory(
                target["folder_id"],
                target_parent_id=dest_parent["folder_id"],
                new_name="RestoredSafely",
            ),
            403,
        )
        assert_error(
            await authenticated_client.get_directory_info(target["folder_id"]), 404
        )

        # Case 1: Parent, sibling, target, and child all share the SAME status_operation_id.
        # Restoring target into dest_parent must restore ONLY target + child, leaving parent + sibling deleted.
        batch_parent = await directory_factory("BatchRestoreParent")
        batch_sibling = await directory_factory(
            "BatchRestoreSibling", parent_id=batch_parent["folder_id"]
        )
        batch_target = await directory_factory(
            "BatchRestoreTarget", parent_id=batch_parent["folder_id"]
        )
        batch_child = await directory_factory(
            "BatchRestoreChild", parent_id=batch_target["folder_id"]
        )
        assert_success(
            await authenticated_client.set_directory_dacl(
                batch_parent["folder_id"],
                (
                    "inherit off; "
                    f'allow [TRAVERSE, RESTORE] to user("{actor["user_id"]}");'
                ),
            )
        )
        assert_success(
            await authenticated_client.set_directory_dacl(
                batch_sibling["folder_id"],
                f'inherit on; deny [RESTORE] to user("{actor["user_id"]}");',
            )
        )
        assert_success(
            await authenticated_client.delete_directory(batch_parent["folder_id"])
        )

        batch_restored = assert_success(
            await actor_client.restore_directory(
                batch_target["folder_id"],
                target_parent_id=dest_parent["folder_id"],
                new_name="BatchTargetRestored",
            )
        )
        assert batch_restored["parent_id"] == dest_parent["folder_id"]
        assert batch_restored["name"] == "BatchTargetRestored"
        batch_child_info = assert_success(
            await authenticated_client.get_directory_info(batch_child["folder_id"])
        )
        assert batch_child_info["parent_id"] == batch_target["folder_id"]
        assert_error(
            await authenticated_client.get_directory_info(batch_parent["folder_id"]),
            404,
        )
        assert_error(
            await authenticated_client.get_directory_info(batch_sibling["folder_id"]),
            404,
        )

        # Case 2: When an active occupant now holds target's old (parent_id, name),
        # restoring with new_name / target_parent_id avoids colliding with the old slot.
        old_parent = await directory_factory("OldParentForCollision")
        re_target = await directory_factory(
            "SharedName", parent_id=old_parent["folder_id"]
        )
        re_child = await directory_factory("ReChild", parent_id=re_target["folder_id"])
        assert_success(
            await authenticated_client.set_directory_dacl(
                old_parent["folder_id"],
                (
                    "inherit off; "
                    f'allow [TRAVERSE, RESTORE] to user("{actor["user_id"]}");'
                ),
            )
        )
        assert_success(
            await authenticated_client.delete_directory(re_target["folder_id"])
        )
        occupant = assert_success(
            await authenticated_client.create_directory(
                "SharedName", parent_id=old_parent["folder_id"]
            )
        )
        owned_entities["directories"].append(occupant["id"])

        restored = assert_success(
            await actor_client.restore_directory(
                re_target["folder_id"],
                target_parent_id=dest_parent["folder_id"],
                new_name="SharedNameRestored",
            )
        )
        assert restored["parent_id"] == dest_parent["folder_id"]
        assert restored["name"] == "SharedNameRestored"
        child_info = assert_success(
            await authenticated_client.get_directory_info(re_child["folder_id"])
        )
        assert child_info["parent_id"] == re_target["folder_id"]

    @pytest.mark.asyncio
    async def test_set_user_avatar_authorizes_actor_read_content(
        self,
        authenticated_client: CFMSTestClient,
        document_factory,
        user_factory,
        client_factory,
        tmp_path: Path,
    ):
        png_path = tmp_path / "avatar.png"
        png_path.write_bytes(
            b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
            b"\x08\x06\x00\x00\x00\x1f\x15c4\x00\x00\x00\nIDATx\x9cc\x00\x01"
            b"\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82"
        )
        victim = await user_factory()
        delegated_admin = await user_factory(
            permissions=[permission_entry(Permissions.SUPER_SET_USER_AVATAR)]
        )
        private_doc = await document_factory(
            "VictimPrivateAvatar", upload_file=str(png_path)
        )

        # Only victim (NOT delegated_admin) has READ_CONTENT on private_doc.
        assert_success(
            await authenticated_client.set_document_dacl(
                private_doc["document_id"],
                f'inherit off; allow [READ_CONTENT] to user("{victim["user_id"]}");',
            )
        )

        admin_client = await client_factory()
        assert_success(
            await admin_client.login(
                delegated_admin["username"], delegated_admin["password"]
            )
        )
        assert_error(
            await admin_client.send_request(
                "core.user.avatar.set",
                {
                    "user_id": victim["user_id"],
                    "document_id": private_doc["document_id"],
                },
            ),
            403,
        )

        # Granting victim SET_USER_AVATAR lets victim set their own avatar.
        assert_success(
            await authenticated_client.change_user_permissions(
                victim["user_id"], [permission_entry(Permissions.SET_USER_AVATAR)]
            )
        )
        victim_client = await client_factory()
        assert_success(
            await victim_client.login(victim["username"], victim["password"])
        )
        assert_success(
            await victim_client.send_request(
                "core.user.avatar.set",
                {
                    "user_id": victim["user_id"],
                    "document_id": private_doc["document_id"],
                },
            )
        )


class TestEffectiveMaskEndpoints:
    """End-to-end effective_mask contracts and side-channel regression tests."""

    @pytest.mark.asyncio
    async def test_directory_list_root_and_child_masks_and_side_channel_guards(
        self,
        authenticated_client: CFMSTestClient,
        directory_factory,
        document_factory,
        user_factory,
        client_factory,
    ):
        # Root directory never exposes RENAME/REPARENT/DELETE/DIRECTORY_DELETE_CHILD/RESTORE/PURGE.
        root_listing = assert_success(await authenticated_client.list_directory("/"))
        root_mask = root_listing["effective_mask"]
        assert root_mask & int(
            AtomicOp.LIST_DIRECTORY | AtomicOp.CREATE_DIRECTORY | AtomicOp.LIST_DELETED
        )
        assert not (
            root_mask
            & int(
                AtomicOp.RENAME
                | AtomicOp.REPARENT
                | AtomicOp.DELETE
                | AtomicOp.DIRECTORY_DELETE_CHILD
                | AtomicOp.RESTORE
                | AtomicOp.PURGE
            )
        )

        actor = await user_factory()
        parent = await directory_factory("MaskParent")
        doc_explicit_deny = await document_factory(
            "ExplicitDenyDoc", folder_id=parent["folder_id"]
        )
        doc_inherit_off = await document_factory(
            "InheritOffDoc", folder_id=parent["folder_id"]
        )
        doc_future_rule = await document_factory(
            "FutureRuleDoc", folder_id=parent["folder_id"]
        )
        doc_readable = await document_factory(
            "ReadableDoc", folder_id=parent["folder_id"]
        )
        nested_dir = await directory_factory("NestedDir", parent_id=parent["folder_id"])
        hidden_sub = await directory_factory(
            "HiddenSub", parent_id=nested_dir["folder_id"]
        )

        # Grant LIST_DIRECTORY WITHOUT TRAVERSE on parent first (T2 check).
        assert_success(
            await authenticated_client.set_directory_dacl(
                parent["folder_id"],
                f'inherit off; allow [LIST_DIRECTORY] to user("{actor["user_id"]}");',
            )
        )
        assert_success(
            await authenticated_client.set_document_dacl(
                doc_readable["document_id"],
                f'inherit off; allow [READ_CONTENT, READ_METADATA] to user("{actor["user_id"]}");',
            )
        )
        assert_success(
            await authenticated_client.set_document_dacl(
                doc_explicit_deny["document_id"],
                f'inherit on; deny [READ_CONTENT, READ_METADATA] to user("{actor["user_id"]}");',
            )
        )
        assert_success(
            await authenticated_client.set_document_dacl(
                doc_inherit_off["document_id"],
                "inherit off;",
            )
        )
        assert_success(
            await authenticated_client.set_document_dacl(
                doc_future_rule["document_id"],
                (
                    "inherit off; "
                    f'allow [READ_CONTENT, READ_METADATA] to user("{actor["user_id"]}") '
                    'from "2099-01-01T00:00:00Z";'
                ),
            )
        )

        actor_client = await client_factory()
        assert_success(await actor_client.login(actor["username"], actor["password"]))

        # Without TRAVERSE on parent, ALL child masks MUST be 0 (no child DACL leakage).
        no_trav_list = assert_success(
            await actor_client.list_directory(parent["folder_id"])
        )
        assert no_trav_list["effective_mask"] == int(AtomicOp.LIST_DIRECTORY)
        assert all(item["effective_mask"] == 0 for item in no_trav_list["items"])
        for item in no_trav_list["items"]:
            assert "inherit" not in item
            assert "_node_inherit" not in item
            assert "effective_allow_mask" not in item
            assert "effective_deny_mask" not in item
            assert "next_transition_at" not in item

        # Granting BYPASS_TRAVERSE_CHECKING exposes the reachable child mask without parent TRAVERSE.
        assert_success(
            await authenticated_client.change_user_permissions(
                actor["user_id"],
                [permission_entry(Permissions.BYPASS_TRAVERSE_CHECKING)],
            )
        )
        bypass_trav_list = assert_success(
            await actor_client.list_directory(parent["folder_id"])
        )
        by_id = {item["id"]: item for item in bypass_trav_list["items"]}
        assert by_id[doc_readable["document_id"]]["effective_mask"] == int(
            AtomicOp.READ_CONTENT | AtomicOp.READ_METADATA
        )
        # Explicit deny, inherit off, and future-scheduled rules are indistinguishable (all 0).
        assert by_id[doc_explicit_deny["document_id"]]["effective_mask"] == 0
        assert by_id[doc_inherit_off["document_id"]]["effective_mask"] == 0
        assert by_id[doc_future_rule["document_id"]]["effective_mask"] == 0

        # T3 hidden descendant check: adding a protected file inside unreadable hidden_sub
        # must NOT change nested_dir's DELETE bit in parent listing.
        assert_success(
            await authenticated_client.set_directory_dacl(
                nested_dir["folder_id"],
                f'inherit off; allow [LIST_DIRECTORY, DELETE] to user("{actor["user_id"]}");',
            )
        )
        assert_success(
            await authenticated_client.set_directory_dacl(
                hidden_sub["folder_id"],
                "inherit off;",
            )
        )
        before_list = assert_success(
            await actor_client.list_directory(parent["folder_id"])
        )
        before_mask = next(
            i["effective_mask"]
            for i in before_list["items"]
            if i["id"] == nested_dir["folder_id"]
        )
        assert before_mask == int(AtomicOp.LIST_DIRECTORY | AtomicOp.DELETE)

        await document_factory("ClassifiedDoc", folder_id=hidden_sub["folder_id"])
        after_list = assert_success(
            await actor_client.list_directory(parent["folder_id"])
        )
        after_mask = next(
            i["effective_mask"]
            for i in after_list["items"]
            if i["id"] == nested_dir["folder_id"]
        )
        assert after_mask == before_mask

    @pytest.mark.asyncio
    async def test_deleted_listing_search_info_revisions_dacl_and_create_masks(
        self,
        authenticated_client: CFMSTestClient,
        directory_factory,
        document_factory,
        user_factory,
        client_factory,
        owned_entities,
    ):
        actor = await user_factory(permissions=[permission_entry(Permissions.SEARCH)])
        parent = await directory_factory("FullMaskParent")
        sub = await directory_factory("FullMaskSub", parent_id=parent["folder_id"])
        doc = await document_factory("FullMaskDoc", folder_id=sub["folder_id"])

        assert_success(
            await authenticated_client.set_directory_dacl(
                parent["folder_id"],
                (
                    "inherit off; "
                    "allow [TRAVERSE, LIST_DIRECTORY, CREATE_DIRECTORY, CREATE_DOCUMENT, "
                    "READ_METADATA, READ_CONTENT, LIST_REVISIONS, READ_REVISION, "
                    "DELETE_REVISION, LIST_DELETED, RESTORE, PURGE, READ_DACL, WRITE_DACL] "
                    f'to user("{actor["user_id"]}");'
                ),
            )
        )

        actor_client = await client_factory()
        assert_success(await actor_client.login(actor["username"], actor["password"]))

        # info.get & revision.list & dacl.get: DELETE_REVISION bit must be 0 without global gate.
        dir_info = assert_success(
            await actor_client.get_directory_info(sub["folder_id"])
        )
        assert dir_info["effective_mask"] & int(
            AtomicOp.READ_METADATA | AtomicOp.WRITE_DACL
        )
        assert not (dir_info["effective_mask"] & int(AtomicOp.PURGE | AtomicOp.RESTORE))

        doc_info = assert_success(
            await actor_client.get_document_info(doc["document_id"])
        )
        assert doc_info["effective_mask"] & int(
            AtomicOp.READ_CONTENT
            | AtomicOp.READ_METADATA
            | AtomicOp.LIST_REVISIONS
            | AtomicOp.READ_REVISION
        )
        assert not (
            doc_info["effective_mask"] & int(AtomicOp.DELETE_REVISION | AtomicOp.PURGE)
        )

        revs = assert_success(await actor_client.list_revisions(doc["document_id"]))
        assert revs["effective_mask"] == doc_info["effective_mask"]

        search_res = assert_success(
            await actor_client.search("FullMaskDoc", search_directories=False)
        )
        search_hit = next(
            i for i in search_res["items"] if i["id"] == doc["document_id"]
        )
        assert search_hit["effective_mask"] == doc_info["effective_mask"]
        assert (
            search_res["parent_effective_masks"][sub["folder_id"]]
            == dir_info["effective_mask"]
        )

        # Grant global DELETE_REVISION -> bit immediately appears in info & revisions.
        assert_success(
            await authenticated_client.change_user_permissions(
                actor["user_id"],
                [
                    permission_entry(Permissions.SEARCH),
                    permission_entry(Permissions.DELETE_REVISION),
                ],
            )
        )
        revs_after = assert_success(
            await actor_client.list_revisions(doc["document_id"])
        )
        assert revs_after["effective_mask"] & int(AtomicOp.DELETE_REVISION)

        # create directory (new + exists_ok) and create document return effective_mask.
        created_dir = assert_success(
            await actor_client.create_directory(
                "CreatedMaskDir", parent_id=parent["folder_id"]
            )
        )
        owned_entities["directories"].append(created_dir["id"])
        assert created_dir["effective_mask"] & int(
            AtomicOp.LIST_DIRECTORY | AtomicOp.WRITE_DACL
        )

        existing_dir = assert_success(
            await actor_client.send_request(
                "core.directory.create",
                {
                    "name": "CreatedMaskDir",
                    "parent_id": parent["folder_id"],
                    "exists_ok": True,
                },
            )
        )
        assert existing_dir["id"] == created_dir["id"]
        assert existing_dir["effective_mask"] == created_dir["effective_mask"]

        created_doc = assert_success(
            await actor_client.create_document(
                "CreatedMaskDoc",
                folder_id=parent["folder_id"],
                dacl=(
                    "inherit off; "
                    f'allow [READ_CONTENT, WRITE_DACL] to user("{actor["user_id"]}");'
                ),
            )
        )
        owned_entities["documents"].append(created_doc["document_id"])
        assert created_doc["effective_mask"] == int(
            AtomicOp.READ_CONTENT | AtomicOp.WRITE_DACL
        )

        # dacl.get & dacl.set (including self-lockout override updating effective_mask).
        dacl_get = assert_success(
            await actor_client.get_directory_dacl(created_dir["id"])
        )
        assert dacl_get["effective_mask"] == created_dir["effective_mask"]

        lockout_err = assert_error(
            await actor_client.set_directory_dacl(
                created_dir["id"],
                f'inherit off; allow [READ_METADATA] to user("{actor["user_id"]}");',
            ),
            409,
        )
        assert "effective_mask" not in lockout_err["data"]

        dacl_set = assert_success(
            await actor_client.set_directory_dacl(
                created_dir["id"],
                f'inherit off; allow [READ_METADATA] to user("{actor["user_id"]}");',
                allow_self_lockout=True,
            )
        )
        assert dacl_set["effective_mask"] == int(AtomicOp.READ_METADATA)

        # Soft-delete sub (and its child doc): verify deleted_item.list inside BOTH normal parent
        # and soft-deleted sub, plus global PURGE gate masking.
        assert_success(await authenticated_client.delete_directory(sub["folder_id"]))

        deleted_under_normal = assert_success(
            await actor_client.list_deleted_items(parent["folder_id"])
        )
        assert deleted_under_normal["effective_mask"] & int(AtomicOp.LIST_DELETED)
        sub_deleted_item = next(
            i for i in deleted_under_normal["items"] if i["id"] == sub["folder_id"]
        )
        # Lacks global Permissions.PURGE -> PURGE bit is 0.
        assert sub_deleted_item["effective_mask"] == int(
            AtomicOp.LIST_DELETED | AtomicOp.RESTORE
        )

        deleted_under_deleted = assert_success(
            await actor_client.list_deleted_items(sub["folder_id"])
        )
        assert deleted_under_deleted["effective_mask"] == int(
            AtomicOp.LIST_DELETED | AtomicOp.RESTORE
        )
        doc_deleted_item = next(
            i for i in deleted_under_deleted["items"] if i["id"] == doc["document_id"]
        )
        assert doc_deleted_item["effective_mask"] == int(AtomicOp.RESTORE)

        # Grant global PURGE -> PURGE bit appears in deleted_item.list.
        assert_success(
            await authenticated_client.change_user_permissions(
                actor["user_id"], [permission_entry(Permissions.PURGE)]
            )
        )
        deleted_with_purge = assert_success(
            await actor_client.list_deleted_items(sub["folder_id"])
        )
        assert deleted_with_purge["effective_mask"] == int(
            AtomicOp.LIST_DELETED | AtomicOp.RESTORE | AtomicOp.PURGE
        )
        doc_with_purge = next(
            i for i in deleted_with_purge["items"] if i["id"] == doc["document_id"]
        )
        assert doc_with_purge["effective_mask"] == int(
            AtomicOp.RESTORE | AtomicOp.PURGE
        )

        # Error responses (403 / 404) never include effective_mask.
        forbidden_dacl = assert_error(
            await actor_client.get_directory_dacl(created_dir["id"]), 403
        )
        assert "effective_mask" not in forbidden_dacl["data"]
        missing_info = assert_error(
            await actor_client.get_directory_info("nonexistent-dir-mask-test"), 404
        )
        assert "effective_mask" not in missing_info["data"]

    @pytest.mark.asyncio
    async def test_search_parent_effective_masks_distinguish_traverse_only_and_listable_parents(
        self,
        authenticated_client: CFMSTestClient,
        directory_factory,
        document_factory,
        user_factory,
        client_factory,
    ):
        actor = await user_factory(permissions=[permission_entry(Permissions.SEARCH)])
        traverse_only_dir = await directory_factory("SearchParentTraverseOnlyDir")
        listable_dir = await directory_factory("SearchParentListableDir")

        trav_doc = await document_factory(
            "SearchParentAccessDoc A", folder_id=traverse_only_dir["folder_id"]
        )
        list_doc = await document_factory(
            "SearchParentAccessDoc B", folder_id=listable_dir["folder_id"]
        )

        assert_success(
            await authenticated_client.set_directory_dacl(
                traverse_only_dir["folder_id"],
                f'inherit off; allow [TRAVERSE] to user("{actor["user_id"]}");',
            )
        )
        assert_success(
            await authenticated_client.set_document_dacl(
                trav_doc["document_id"],
                f'inherit off; allow [READ_CONTENT, READ_METADATA] to user("{actor["user_id"]}");',
            )
        )
        assert_success(
            await authenticated_client.set_directory_dacl(
                listable_dir["folder_id"],
                (
                    "inherit off; "
                    "allow [TRAVERSE, LIST_DIRECTORY, READ_METADATA, READ_CONTENT] "
                    f'to user("{actor["user_id"]}");'
                ),
            )
        )

        actor_client = await client_factory()
        assert_success(await actor_client.login(actor["username"], actor["password"]))

        search_res = assert_success(
            await actor_client.search(
                "SearchParentAccessDoc",
                search_documents=True,
                search_directories=False,
            )
        )
        by_id = {item["id"]: item for item in search_res["items"]}
        assert set(by_id) == {trav_doc["document_id"], list_doc["document_id"]}

        parent_masks = search_res["parent_effective_masks"]
        assert set(parent_masks) == {
            traverse_only_dir["folder_id"],
            listable_dir["folder_id"],
        }
        assert parent_masks[traverse_only_dir["folder_id"]] == int(AtomicOp.TRAVERSE)
        assert not (
            parent_masks[traverse_only_dir["folder_id"]] & int(AtomicOp.LIST_DIRECTORY)
        )
        assert_error(
            await actor_client.list_directory(traverse_only_dir["folder_id"]), 403
        )

        listed_parent = assert_success(
            await actor_client.list_directory(listable_dir["folder_id"])
        )
        assert (
            parent_masks[listable_dir["folder_id"]] == listed_parent["effective_mask"]
        )
        assert parent_masks[listable_dir["folder_id"]] & int(AtomicOp.LIST_DIRECTORY)
