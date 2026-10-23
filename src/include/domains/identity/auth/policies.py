import uuid
from collections.abc import Sequence

from include.domains.identity.auth.types import (
    AuthChains,
    AuthEvidence,
    AuthPolicyDecision,
    AuthPurpose,
    AuthStep,
    RegisteredCredential,
)


def evaluate_auth_policy(
    purpose: AuthPurpose,
    chains: AuthChains,
    credentials: Sequence[RegisteredCredential],
    evidence: Sequence[AuthEvidence],
    *,
    user_id: uuid.UUID,
    attempt_id: str,
) -> AuthPolicyDecision:
    """Match ordered alternatives against evidence from exactly one attempt."""
    active = {(c.method, c.credential_id): c for c in credentials if c.active}
    if len({e.event_id for e in evidence}) != len(evidence) or any(
        e.user_id != user_id
        or e.attempt_id != attempt_id
        or (e.method, e.credential_id) not in active
        for e in evidence
    ):
        return AuthPolicyDecision(satisfied=False)
    if not chains:
        return AuthPolicyDecision(satisfied=purpose == AuthPurpose.MFA)

    next_steps: list[AuthStep] = []
    for chain in chains:
        if any(
            not any((s.method, cid) in active for cid in s.credential_ids)
            for s in chain
        ):
            continue
        states = {(0, frozenset())}
        for event in evidence:
            following = set(states)
            for position, used_keys in states:
                if position == len(chain):
                    return AuthPolicyDecision(satisfied=True)
                step = chain[position]
                if (
                    event.method != step.method
                    or event.credential_id not in step.credential_ids
                ):
                    continue
                keys = used_keys
                if event.method == "publickey":
                    identity = active[(event.method, event.credential_id)].key_identity
                    if identity is None or identity in used_keys:
                        continue
                    keys = used_keys | {identity}
                following.add((position + 1, frozenset(keys)))
            states = following
        if any(position == len(chain) for position, _ in states):
            return AuthPolicyDecision(satisfied=True)
        progress = max(position for position, _ in states)
        for position, used_keys in states:
            if position != progress:
                continue
            step = chain[position]
            permitted = [
                cid
                for cid in step.credential_ids
                if (step.method, cid) in active
                and (
                    step.method != "publickey"
                    or active[(step.method, cid)].key_identity not in used_keys
                )
            ]
            if permitted:
                candidate = AuthStep(method=step.method, credential_ids=permitted)
                if candidate not in next_steps:
                    next_steps.append(candidate)
    return AuthPolicyDecision(satisfied=False, next_steps=next_steps)
