__all__ = [
    "BatchVisibilityEvaluator",
    "VisibilityCandidate",
]

import datetime
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from itertools import batched
from typing import Self

from cacl_compiler import CompiledPolicy, ObjectType
from sqlalchemy.orm import Session as OrmSession

from include.config.constants import QUERY_CHUNK_SIZE, ROOT_DIRECTORY_ID
from include.database.models.documents import EntityStatus
from include.database.models.identity import User
from include.domains.access.authorization.engine import (
    InheritedDaclState,
    ObjectState,
    Subject,
    is_ancestor_dir_traversable,
    is_effective_mask_visible,
    step_node_dacl,
)
from include.domains.access.authorization.evaluation import (
    has_bypass_dacl,
    should_check_ancestor_traverse,
    user_to_subject,
)
from include.domains.access.authorization.storage import (
    AncestorNodeMeta,
    load_ancestors_and_active_policies,
    load_node_policies,
)

_EMPTY_INHERITED_STATE = InheritedDaclState()


@dataclass(frozen=True, slots=True)
class VisibilityCandidate:
    node_id: str
    parent_id: str | None
    object_type: ObjectType
    inherit: bool
    status: int = EntityStatus.OK.value


class BatchVisibilityEvaluator:
    """Request-scoped memoized CACL evaluator for batched visibility checks."""

    def __init__(
        self,
        session: OrmSession,
        subject: Subject,
        now_utc: datetime.datetime,
        *,
        check_traverse: bool,
        bypass_dacl: bool = False,
    ) -> None:
        self._session = session
        self._subject = subject
        self._now_utc = now_utc.astimezone(datetime.UTC)
        self._check_traverse = check_traverse
        self._bypass_dacl = bypass_dacl
        self._node_meta: dict[str, AncestorNodeMeta] = {}
        self._node_policies: dict[str, CompiledPolicy] = {}
        self._dir_state_cache: dict[str, tuple[bool, InheritedDaclState]] = {}

    @classmethod
    def for_user(
        cls,
        session: OrmSession,
        user: User,
        now_utc: datetime.datetime,
    ) -> Self:
        bypass_dacl = has_bypass_dacl(user)
        return cls(
            session,
            user_to_subject(user),
            now_utc,
            check_traverse=False
            if bypass_dacl
            else should_check_ancestor_traverse(session, user),
            bypass_dacl=bypass_dacl,
        )

    def _register_candidates_and_collect_missing(
        self,
        candidates: Sequence[VisibilityCandidate],
    ) -> tuple[list[str], list[str], dict[str, bool]]:
        batch_inherit: dict[str, bool] = {}
        for candidate in candidates:
            batch_inherit[candidate.node_id] = candidate.inherit
            if (
                candidate.object_type is ObjectType.DIRECTORY
                and candidate.node_id not in self._node_meta
            ):
                self._node_meta[candidate.node_id] = AncestorNodeMeta(
                    parent_id=candidate.parent_id,
                    status=candidate.status,
                    inherit=candidate.inherit,
                )

        missing_ancestors: list[str] = []
        seen_missing: set[str] = set()
        new_candidate_ids: list[str] = []
        seen_candidate: set[str] = set()

        for candidate in candidates:
            parent_id = candidate.parent_id
            if (
                parent_id is not None
                and parent_id not in self._node_meta
                and parent_id not in seen_missing
            ):
                seen_missing.add(parent_id)
                missing_ancestors.append(parent_id)

            if parent_id is not None:
                parent_state = self._dir_state_cache.get(parent_id)
                if parent_state is not None and not parent_state[0]:
                    continue

            if (
                candidate.node_id not in self._node_policies
                and candidate.node_id not in seen_candidate
            ):
                seen_candidate.add(candidate.node_id)
                new_candidate_ids.append(candidate.node_id)

        return missing_ancestors, new_candidate_ids, batch_inherit

    def _load_combined_batch(
        self,
        missing_ancestors: Sequence[str],
        candidate_ids: Sequence[str],
        batch_inherit: Mapping[str, bool],
    ) -> int:
        cand_offset = 0
        for anc_chunk in batched(missing_ancestors, QUERY_CHUNK_SIZE):
            anc_ids = list(anc_chunk)
            cand_budget = max(0, QUERY_CHUNK_SIZE - len(anc_ids))
            cand_slice = candidate_ids[cand_offset : cand_offset + cand_budget]
            cand_offset += len(cand_slice)

            ancestor_meta, rules_by_node, loaded_node_ids = (
                load_ancestors_and_active_policies(
                    self._session,
                    anc_ids,
                    cand_slice,
                    active_at_utc=self._now_utc,
                )
            )
            for node_id, meta in ancestor_meta.items():
                if node_id not in self._node_meta:
                    self._node_meta[node_id] = meta

            for nid in loaded_node_ids:
                if nid in self._node_policies:
                    continue
                node_meta = self._node_meta.get(nid)
                default_inherit = (
                    node_meta.inherit
                    if node_meta is not None
                    else batch_inherit.get(nid, True)
                )
                self._node_policies[nid] = CompiledPolicy(
                    inherit=default_inherit,
                    rules=tuple(rules_by_node.get(nid, ())),
                )
        return cand_offset

    def _load_leftover_candidate_policies(
        self,
        leftover_candidates: Sequence[str],
        batch_inherit: Mapping[str, bool],
    ) -> None:
        if not leftover_candidates:
            return
        preloaded_inherit = {
            nid: (
                self._node_meta[nid].inherit
                if nid in self._node_meta
                else batch_inherit[nid]
            )
            for nid in leftover_candidates
            if nid in self._node_meta or nid in batch_inherit
        }
        loaded = load_node_policies(
            self._session,
            leftover_candidates,
            include_deleted=True,
            preloaded_inherit=preloaded_inherit,
            active_at_utc=self._now_utc,
            canonicalize=False,
        )
        for nid in leftover_candidates:
            node_meta = self._node_meta.get(nid)
            default_inherit = (
                node_meta.inherit
                if node_meta is not None
                else batch_inherit.get(nid, True)
            )
            self._node_policies[nid] = loaded.get(
                nid, CompiledPolicy(inherit=default_inherit, rules=())
            )

    def preload(self, candidates: Sequence[VisibilityCandidate]) -> None:
        """Batch-load missing ancestor chains and active policies for a chunk of candidates."""
        if self._bypass_dacl:
            return
        missing_ancestors, new_candidate_ids, batch_inherit = (
            self._register_candidates_and_collect_missing(candidates)
        )
        if not missing_ancestors and not new_candidate_ids:
            return

        cand_offset = (
            self._load_combined_batch(
                missing_ancestors, new_candidate_ids, batch_inherit
            )
            if missing_ancestors
            else 0
        )
        leftover_candidates = [
            nid
            for nid in new_candidate_ids[cand_offset:]
            if nid not in self._node_policies
        ]
        self._load_leftover_candidate_policies(leftover_candidates, batch_inherit)

    def _resolve_ancestor_dir(self, dir_id: str) -> tuple[bool, InheritedDaclState]:
        cached = self._dir_state_cache.get(dir_id)
        if cached is not None:
            return cached

        uncomputed: list[str] = []
        visited: set[str] = set()
        curr_id: str | None = dir_id
        while curr_id is not None and curr_id not in self._dir_state_cache:
            if curr_id in visited:
                raise RuntimeError(f"Cycle detected in folder hierarchy at {curr_id!r}")
            visited.add(curr_id)
            meta = self._node_meta.get(curr_id)
            if meta is None:
                break
            uncomputed.append(curr_id)
            curr_id = meta.parent_id

        if curr_id is None:
            accessible = bool(uncomputed) and uncomputed[-1] == ROOT_DIRECTORY_ID
            inherited = _EMPTY_INHERITED_STATE
        elif curr_id in self._dir_state_cache:
            accessible, inherited = self._dir_state_cache[curr_id]
        else:
            # Missing parent or truncated ancestor chain: fail-closed unconditionally.
            accessible, inherited = False, _EMPTY_INHERITED_STATE

        for nid in reversed(uncomputed):
            if not accessible:
                self._dir_state_cache[nid] = (False, _EMPTY_INHERITED_STATE)
                continue
            meta = self._node_meta[nid]
            policy = self._node_policies.get(
                nid, CompiledPolicy(inherit=meta.inherit, rules=())
            )
            own_allow, own_deny, _, next_inherited = step_node_dacl(
                self._subject,
                policy,
                ObjectType.DIRECTORY,
                inherited,
                self._now_utc,
            )
            ancestor_state = (
                ObjectState.SOFT_DELETED
                if meta.status == EntityStatus.DELETED.value
                else ObjectState.NORMAL
            )
            node_accessible = is_ancestor_dir_traversable(
                ancestor_state,
                own_allow,
                own_deny,
                check_traverse=self._check_traverse,
            )
            self._dir_state_cache[nid] = (node_accessible, next_inherited)
            accessible, inherited = node_accessible, next_inherited

        return self._dir_state_cache.get(dir_id, (False, _EMPTY_INHERITED_STATE))

    def is_visible(self, candidate: VisibilityCandidate) -> bool:
        if self._bypass_dacl:
            return True

        is_document = candidate.object_type is ObjectType.DOCUMENT
        parent_id = candidate.parent_id
        if parent_id is not None:
            accessible, parent_inherited = self._resolve_ancestor_dir(parent_id)
            if not accessible:
                if is_document:
                    self._node_policies.pop(candidate.node_id, None)
                return False
        else:
            if candidate.node_id != ROOT_DIRECTORY_ID:
                if is_document:
                    self._node_policies.pop(candidate.node_id, None)
                return False
            parent_inherited = _EMPTY_INHERITED_STATE

        fallback_policy = CompiledPolicy(inherit=candidate.inherit, rules=())
        policy = (
            self._node_policies.pop(candidate.node_id, fallback_policy)
            if is_document
            else self._node_policies.get(candidate.node_id, fallback_policy)
        )
        own_allow, own_deny, _, _ = step_node_dacl(
            self._subject,
            policy,
            candidate.object_type,
            parent_inherited,
            self._now_utc,
        )
        return is_effective_mask_visible(candidate.object_type, own_allow & ~own_deny)
