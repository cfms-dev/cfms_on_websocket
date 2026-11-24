"""Unit tests for the server-side CEP 2 Section 6 CACL runtime authorization engine."""

import datetime
from uuid import UUID

import pytest
from cacl_compiler import AtomicOp, CompilerConfig, ObjectType, compile_cacl

from include.domains.access.authorization.engine import (
    NamespaceNode,
    ObjectState,
    Subject,
    SubtreeNode,
    evaluate_access,
    evaluate_effective_masks,
    evaluate_path_masks,
    evaluate_reparent,
    evaluate_soft_delete,
    evaluate_soft_delete_subtree,
    simulate_policy_save_lockout,
)

pytestmark = pytest.mark.unit

NOW = datetime.datetime(2026, 11, 24, tzinfo=datetime.UTC)
U_ALICE = UUID("11111111-1111-4111-8111-111111111111")
U_BOB = UUID("5a52345a-ae51-4516-b277-bbd94b99d73a")
D = ObjectType.DIRECTORY
F = ObjectType.DOCUMENT
ALICE = Subject(user_id=U_ALICE, groups=frozenset({"g"}), perms=frozenset({"p"}))


def _compile(src: str):
    return compile_cacl(src, CompilerConfig(now_utc=NOW))


def _node(
    name: str,
    typ: ObjectType,
    src: str = "",
    state: ObjectState = ObjectState.NORMAL,
) -> NamespaceNode:
    res = _compile(src) if src else _compile("inherit on;")
    assert res.ok, res.diagnostics
    assert res.policy is not None, "res.ok is True, but res.policy is None"
    return NamespaceNode(name, name, typ, state, res.policy)


def _ev(path, op, subj=ALICE, t=NOW, **kw):
    return evaluate_access(subj, path, op, t, **kw)


def test_default_deny_and_deny_overrides_order_independent():
    allow_stmt = f'allow [READ_CONTENT] to user("{U_ALICE}");'
    deny_stmt = 'deny [READ_CONTENT] to group("g");'
    for src in (allow_stmt + deny_stmt, deny_stmt + allow_stmt):
        decision = _ev(
            [_node("f", F, src)],
            AtomicOp.READ_CONTENT,
            check_ancestor_traverse=False,
        )
        assert not decision.allowed
        assert decision.step == "4_deny_overrides"
    default_deny = _ev([_node("f", F)], AtomicOp.READ_CONTENT)
    assert not default_deny.allowed
    assert default_deny.step == "4_default_deny"


def test_user_match_by_uuid():
    mine = _node("f", F, f'allow [READ_CONTENT] to user("{str(U_ALICE).upper()}");')
    other = _node("f", F, f'allow [READ_CONTENT] to user("{U_BOB}");')
    assert _ev([mine], AtomicOp.READ_CONTENT, check_ancestor_traverse=False).allowed
    assert not _ev(
        [other], AtomicOp.READ_CONTENT, check_ancestor_traverse=False
    ).allowed


def test_anonymous_never_matches_any():
    doc = _node("f", F, "allow [READ_CONTENT] to any;")
    assert _ev([doc], AtomicOp.READ_CONTENT).allowed
    anon = evaluate_access(None, [doc], AtomicOp.READ_CONTENT, NOW)
    assert not anon.allowed
    assert anon.step == "0_unauthenticated"


def test_scope_matrix_and_inherit_off():
    root = _node(
        "root",
        D,
        "allow [TRAVERSE, READ_CONTENT] on docs to any; allow [TRAVERSE] on self to any;",
    )
    sub = _node("sub", D, "allow [TRAVERSE] on dirs to any;")
    doc = _node("doc", F)
    assert _ev([root, sub, doc], AtomicOp.READ_CONTENT).allowed
    assert _ev([root, sub], AtomicOp.TRAVERSE, check_ancestor_traverse=False).allowed
    cut = _node("cut", D, "inherit off;\nallow [TRAVERSE] on self to any;")
    assert not _ev([root, cut, doc], AtomicOp.READ_CONTENT).allowed


def test_inherit_off_retains_own_rules():
    root = _node("root", D, "allow [TRAVERSE, READ_CONTENT] to any;")
    cut = _node("cut", D, "inherit off; allow [TRAVERSE] to any;")
    doc = _node("doc", F, "allow [READ_CONTENT] to any;")
    assert _ev([root, cut, doc], AtomicOp.READ_CONTENT).allowed
    assert not _ev([root, cut, _node("d2", F)], AtomicOp.READ_CONTENT).allowed


def test_half_open_interval():
    doc = _node(
        "f",
        F,
        'allow [READ_CONTENT] to any from "2026-12-01T00:00:00Z" until "2026-12-02T00:00:00Z";',
    )
    before = datetime.datetime.fromisoformat("2026-11-30T23:59:59+00:00")
    start = datetime.datetime.fromisoformat("2026-12-01T00:00:00+00:00")
    end = datetime.datetime.fromisoformat("2026-12-02T00:00:00+00:00")
    assert not _ev(
        [doc], AtomicOp.READ_CONTENT, t=before, check_ancestor_traverse=False
    ).allowed
    assert _ev(
        [doc], AtomicOp.READ_CONTENT, t=start, check_ancestor_traverse=False
    ).allowed
    assert not _ev(
        [doc], AtomicOp.READ_CONTENT, t=end, check_ancestor_traverse=False
    ).allowed


def test_ancestor_traverse_required_and_bypassable():
    root = _node("root", D)
    doc = _node("f", F, "allow [READ_CONTENT] to any;")
    assert not _ev([root, doc], AtomicOp.READ_CONTENT).allowed
    assert _ev(
        [root, doc], AtomicOp.READ_CONTENT, check_ancestor_traverse=False
    ).allowed
    root_t = _node("root", D, "allow [TRAVERSE] to any;")
    assert _ev([root_t, doc], AtomicOp.READ_CONTENT).allowed


def test_trash_lifecycle_rules():
    allow_all = "allow [LIST_DELETED, RESTORE, PURGE, READ_CONTENT, DELETE] to any;"
    live = _node("d", D, allow_all)
    dead = _node("d", D, allow_all, ObjectState.SOFT_DELETED)
    assert not _ev([dead], AtomicOp.READ_CONTENT).allowed
    assert not _ev([dead], AtomicOp.DELETE).allowed
    assert _ev([dead], AtomicOp.RESTORE).allowed
    assert _ev([dead], AtomicOp.PURGE).allowed
    assert _ev([dead], AtomicOp.LIST_DELETED).allowed
    assert not _ev([live], AtomicOp.RESTORE).allowed
    assert not _ev([live], AtomicOp.PURGE).allowed
    doc_dead = _node("f", F, allow_all, ObjectState.SOFT_DELETED)
    assert not _ev([doc_dead], AtomicOp.LIST_DELETED).allowed


def test_trash_traverse_skips_soft_deleted_ancestors():
    allow = "allow [TRAVERSE, RESTORE, PURGE] to any;"
    root = _node("root", D, allow)
    dead_dir = _node("dd", D, allow, ObjectState.SOFT_DELETED)
    dead_doc = _node("df", F, allow, ObjectState.SOFT_DELETED)
    assert _ev([root, dead_dir, dead_doc], AtomicOp.PURGE).allowed
    assert not _ev(
        [root, dead_dir, _node("dd2", D, allow, ObjectState.SOFT_DELETED)],
        AtomicOp.RESTORE,
    ).allowed
    assert _ev([root, dead_dir], AtomicOp.RESTORE).allowed


def test_reparent_composite():
    allow_src = "allow [TRAVERSE, REPARENT] to any;"
    src = [_node("s", D, allow_src), _node("x", F, allow_src)]
    dst = [_node("dst", D, "allow [TRAVERSE, CREATE_DOCUMENT] to any;")]
    assert evaluate_reparent(ALICE, src, dst, NOW).allowed

    dst_nocreate = [_node("dst", D, "allow [TRAVERSE] to any;")]
    denied = evaluate_reparent(ALICE, src, dst_nocreate, NOW)
    assert not denied.allowed
    assert denied.step == "5_composite_destination"


def test_soft_delete_non_empty_directory():
    base = "allow [TRAVERSE] to any;\n"
    target = [_node("d", D, base + "allow [DELETE] to any;")]
    child = target + [_node("c", F, "deny [DELETE] to any;")]
    assert not evaluate_soft_delete(ALICE, target, [child], NOW).allowed

    with_bypass = [
        _node("d", D, base + "allow [DELETE, DIRECTORY_DELETE_CHILD] to any;")
    ]
    child2 = with_bypass + [_node("c", F, "deny [DELETE] to any;")]
    assert evaluate_soft_delete(ALICE, with_bypass, [child2], NOW).allowed

    only_bypass = [_node("d", D, base + "allow [DIRECTORY_DELETE_CHILD] to any;")]
    assert not evaluate_soft_delete(ALICE, only_bypass, [], NOW).allowed


def test_composite_evaluators_forward_bypass_traverse():
    root_no_traverse = _node("root", D)
    src_doc = _node("x", F, "allow [REPARENT] to any;")
    dst_dir = _node("dst", D, "allow [CREATE_DOCUMENT] to any;")
    assert not evaluate_reparent(
        ALICE, [root_no_traverse, src_doc], [root_no_traverse, dst_dir], NOW
    ).allowed
    assert evaluate_reparent(
        ALICE,
        [root_no_traverse, src_doc],
        [root_no_traverse, dst_dir],
        NOW,
        check_ancestor_traverse=False,
    ).allowed

    dacl_doc = _node("p", F, "allow [WRITE_DACL] to any;")
    proposed = _compile("inherit off;").policy
    keep_policy = _compile("inherit off; allow [WRITE_DACL] to any;").policy
    assert proposed is not None
    assert keep_policy is not None
    assert not evaluate_access(
        ALICE, [root_no_traverse, dacl_doc], AtomicOp.WRITE_DACL, NOW
    ).allowed
    assert simulate_policy_save_lockout(
        ALICE,
        [root_no_traverse, dacl_doc],
        keep_policy,
        NOW,
        check_ancestor_traverse=True,
    )
    assert evaluate_access(
        ALICE,
        [root_no_traverse, dacl_doc],
        AtomicOp.WRITE_DACL,
        NOW,
        check_ancestor_traverse=False,
    ).allowed
    assert simulate_policy_save_lockout(
        ALICE,
        [root_no_traverse, dacl_doc],
        proposed,
        NOW,
        check_ancestor_traverse=False,
    )
    assert not simulate_policy_save_lockout(
        ALICE,
        [root_no_traverse, dacl_doc],
        keep_policy,
        NOW,
        check_ancestor_traverse=False,
    )


def test_next_transition_at_and_evaluate_effective_masks():
    root = _node(
        "root",
        D,
        'allow [TRAVERSE, READ_CONTENT] to any until "2026-12-10T00:00:00Z";',
    )
    doc = _node(
        "doc",
        F,
        'allow [WRITE_CONTENT] to any from "2026-12-01T00:00:00Z";\n'
        'deny [READ_CONTENT] to any until "2026-11-25T00:00:00Z";',
    )
    decision = evaluate_access(ALICE, [root, doc], AtomicOp.READ_CONTENT, NOW)
    assert not decision.allowed
    assert decision.next_transition_at == datetime.datetime(
        2026, 11, 25, tzinfo=datetime.UTC
    )

    masks = evaluate_effective_masks(ALICE, [root, doc], NOW)
    assert masks.allowed_traverse
    assert masks.effective_allow_mask == int(AtomicOp.TRAVERSE | AtomicOp.READ_CONTENT)
    assert masks.effective_deny_mask == int(AtomicOp.READ_CONTENT)
    assert masks.effective_mask == int(AtomicOp.TRAVERSE)
    assert masks.next_transition_at == datetime.datetime(
        2026, 11, 25, tzinfo=datetime.UTC
    )


def test_deep_path_single_pass_handles_scopes_inherit_off_and_transitions():
    chain: list[NamespaceNode] = [
        _node(
            "root",
            D,
            'inherit off; allow [TRAVERSE] to any; allow [READ_CONTENT] on docs to any until "2026-12-20T00:00:00Z";',
        )
    ]
    for depth in range(1, 15):
        if depth == 5:
            chain.append(
                _node(
                    f"d{depth}",
                    D,
                    'inherit off; allow [TRAVERSE] to any; allow [LIST_DIRECTORY] on self to any; allow [READ_METADATA] on docs to any from "2026-12-01T00:00:00Z";',
                )
            )
        elif depth == 10:
            chain.append(
                _node(
                    f"d{depth}",
                    D,
                    'allow [READ_CONTENT] on docs to any until "2026-11-30T00:00:00Z";',
                )
            )
        else:
            chain.append(_node(f"d{depth}", D))
    leaf_doc = _node(
        "leaf", F, 'deny [WRITE_CONTENT] to any until "2026-11-28T00:00:00Z";'
    )
    full_path = [*chain, leaf_doc]

    decision = evaluate_access(ALICE, full_path, AtomicOp.READ_CONTENT, NOW)
    assert decision.allowed
    assert decision.next_transition_at == datetime.datetime(
        2026, 11, 28, tzinfo=datetime.UTC
    )
    assert len(decision.matched_allows) == 1
    assert decision.matched_allows[0].node_id == "d10"
    assert decision.matched_allows[0].distance == 5

    # Ancestor d5 granted LIST_DIRECTORY only on self, so leaf parent d14 does not have LIST_DIRECTORY.
    path_masks = evaluate_path_masks(ALICE, full_path, NOW)
    assert path_masks.target.allowed_traverse
    assert path_masks.parent_state is ObjectState.NORMAL
    assert not (path_masks.parent_effective_mask & int(AtomicOp.LIST_DIRECTORY))
    assert path_masks.parent_effective_mask & int(AtomicOp.TRAVERSE)

    # Check direct child of d5 sees LIST_DIRECTORY on parent d5.
    child_of_d5 = evaluate_path_masks(ALICE, [*chain[:6], _node("c", D)], NOW)
    assert child_of_d5.target.allowed_traverse
    assert child_of_d5.parent_effective_mask & int(AtomicOp.LIST_DIRECTORY)


def test_evaluate_soft_delete_subtree_linear_traversal_and_edge_cases():
    root = _node("root", D, "inherit off; allow [TRAVERSE, DELETE] to any;")
    target = _node("target", D)
    target_masks = evaluate_path_masks(ALICE, [root, target], NOW)
    assert target_masks.target.allowed_traverse

    d1_policy = _compile("inherit on;").policy
    doc1_policy = _compile("inherit on;").policy
    denied_doc_policy = _compile("inherit on; deny [DELETE] to any;").policy
    no_traverse_dir_policy = _compile("inherit off; allow [DELETE] to any;").policy
    assert d1_policy is not None
    assert doc1_policy is not None
    assert denied_doc_policy is not None
    assert no_traverse_dir_policy is not None

    ok_nodes = [
        SubtreeNode("d1", "target", "d1", D, ObjectState.NORMAL, d1_policy),
        SubtreeNode("doc1", "d1", "doc1", F, ObjectState.NORMAL, doc1_policy),
    ]
    assert evaluate_soft_delete_subtree(
        ALICE,
        "target",
        target_masks.target.effective_mask,
        target_masks.target_inherited,
        ok_nodes,
        NOW,
    ).allowed

    denied_nodes = [
        SubtreeNode("d1", "target", "d1", D, ObjectState.NORMAL, d1_policy),
        SubtreeNode("doc1", "d1", "doc1", F, ObjectState.NORMAL, denied_doc_policy),
    ]
    denied_res = evaluate_soft_delete_subtree(
        ALICE,
        "target",
        target_masks.target.effective_mask,
        target_masks.target_inherited,
        denied_nodes,
        NOW,
    )
    assert not denied_res.allowed
    assert denied_res.step == "5_composite_delete_descendant"

    # Intermediate directory lacking TRAVERSE blocks deleting its child when traverse checking is on.
    blocked_traverse_nodes = [
        SubtreeNode(
            "d1", "target", "d1", D, ObjectState.NORMAL, no_traverse_dir_policy
        ),
        SubtreeNode(
            "doc1",
            "d1",
            "doc1",
            F,
            ObjectState.NORMAL,
            _compile("inherit off; allow [DELETE] to any;").policy,
        ),  # type: ignore[arg-type]
    ]
    assert not evaluate_soft_delete_subtree(
        ALICE,
        "target",
        target_masks.target.effective_mask,
        target_masks.target_inherited,
        blocked_traverse_nodes,
        NOW,
        check_ancestor_traverse=True,
    ).allowed
    assert evaluate_soft_delete_subtree(
        ALICE,
        "target",
        target_masks.target.effective_mask,
        target_masks.target_inherited,
        blocked_traverse_nodes,
        NOW,
        check_ancestor_traverse=False,
    ).allowed


def test_evaluate_access_collect_traces_false_skips_trace_pass(monkeypatch):
    from include.domains.access.authorization import engine as engine_mod

    root_allow = _node(
        "root",
        D,
        'inherit off; allow [TRAVERSE, READ_CONTENT] to any until "2026-12-10T00:00:00Z";',
    )
    doc_allow = _node("doc-allow", F)
    doc_deny = _node(
        "doc-deny",
        F,
        'deny [READ_CONTENT] to any until "2026-11-26T00:00:00Z";',
    )
    root_no_traverse = _node("root-nt", D, "inherit off;")
    doc_default_deny = _node("doc-dd", F, "inherit off;")

    cases = [
        ([root_allow, doc_allow], AtomicOp.READ_CONTENT),
        ([root_allow, doc_deny], AtomicOp.READ_CONTENT),
        ([root_allow, doc_default_deny], AtomicOp.READ_CONTENT),
        ([root_no_traverse, doc_allow], AtomicOp.READ_CONTENT),
    ]
    with_traces = [
        evaluate_access(ALICE, path, op, NOW, collect_traces=True) for path, op in cases
    ]

    def _fail_if_called(*args, **kwargs):
        raise AssertionError("_collect_op_traces_on_chain should not be called")

    monkeypatch.setattr(engine_mod, "_collect_op_traces_on_chain", _fail_if_called)

    for (path, op), expected in zip(cases, with_traces, strict=True):
        fast = evaluate_access(ALICE, path, op, NOW, collect_traces=False)
        assert fast.allowed == expected.allowed
        assert fast.step == expected.step
        assert fast.effective_allow_mask == expected.effective_allow_mask
        assert fast.effective_deny_mask == expected.effective_deny_mask
        assert fast.next_transition_at == expected.next_transition_at
        assert fast.matched_allows == ()
        assert fast.matched_denies == ()


def test_path_masks_inherit_off_pruning_preserves_parent_masks(monkeypatch):
    from include.domains.access.authorization import engine as engine_mod

    root = _node(
        "root",
        D,
        'inherit off; allow [LIST_DIRECTORY, READ_CONTENT] to any until "2026-12-10T00:00:00Z";',
    )
    mid = _node("mid", D, "inherit off; allow [LIST_DIRECTORY] to any;")
    parent = _node("parent", D)
    target = _node("target", D, "inherit off; allow [READ_METADATA] to any;")

    # Target has inherit off, but parent inherits LIST_DIRECTORY from root.
    # With check_ancestor_traverse=False, evaluate_path_masks must still compute parent's mask.
    pm_inherit_parent = evaluate_path_masks(
        ALICE,
        [root, parent, target],
        NOW,
        check_ancestor_traverse=False,
    )
    assert pm_inherit_parent.target.allowed_traverse
    assert pm_inherit_parent.target.effective_mask == int(AtomicOp.READ_METADATA)
    assert pm_inherit_parent.parent_state is ObjectState.NORMAL
    assert pm_inherit_parent.parent_effective_mask == int(
        AtomicOp.LIST_DIRECTORY | AtomicOp.READ_CONTENT
    )

    # When an ancestor at or above parent sets inherit off, ancestors above it are pruned.
    step_calls = 0
    orig_step = engine_mod.step_node_dacl

    def _counting_step(*args, **kwargs):
        nonlocal step_calls
        step_calls += 1
        return orig_step(*args, **kwargs)

    monkeypatch.setattr(engine_mod, "step_node_dacl", _counting_step)

    pm_pruned = evaluate_path_masks(
        ALICE,
        [root, mid, parent, target],
        NOW,
        check_ancestor_traverse=False,
    )
    assert step_calls == 3  # mid, parent, target (root pruned)
    assert pm_pruned.target.allowed_traverse
    assert pm_pruned.target.effective_mask == int(AtomicOp.READ_METADATA)
    assert pm_pruned.target.next_transition_at is None
    assert pm_pruned.parent_effective_mask == int(AtomicOp.LIST_DIRECTORY)

    # evaluate_effective_masks does not need parent_effective_mask, so it prunes all the way to target.
    step_calls = 0
    em_pruned = evaluate_effective_masks(
        ALICE,
        [root, mid, parent, target],
        NOW,
        check_ancestor_traverse=False,
    )
    assert step_calls == 1  # target only
    assert em_pruned.allowed_traverse
    assert em_pruned.effective_mask == int(AtomicOp.READ_METADATA)
    assert em_pruned.next_transition_at is None
