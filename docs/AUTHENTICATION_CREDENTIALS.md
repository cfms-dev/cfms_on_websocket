# Authentication credentials and purpose policies

`User` owns account identity, status, permissions and the token signing key.
Each authentication method owns its credential tables and verification logic.
Credentials and policies reference `users.id`; `User` has no reverse credential
relationships or method-specific properties.

## Registered credentials are not authorization

Password and TOTP remain singleton rows keyed by `user_id`. Their independent
random `credential_id` identifies the registration, not its current secret.
Changing a password keeps its ID; deleting and registering a replacement creates
a new ID. Public keys and OIDC bindings use their existing/random row IDs.
Pending TOTP credentials appear in inventory with `active=False`.

Providers implement `list_credentials(session, user)` and
`verify(session, user, payload, context)`, plus optional `create_challenge`.
Inventory exposes method, credential ID, active state and display information,
never passwords, TOTP secrets, backup codes or external tokens. Successful
verification identifies the credential that actually verified. Verification does
not grant a purpose. `primary`, `secondary` and `federated` are descriptive
categories only.

`auth_registry.list_user_credentials(session, user)` enumerates registrations.
`evaluate_user_policy` determines authorization and next steps for a purpose.
`user_requires_mfa` and `get_user_mfa_methods` read the MFA policy rather than
inferring requirements from enabled TOTP credentials.

## Purpose policies

`UserAuthPolicy` has composite key `(user_id, purpose)`, a positive `revision`,
and JSON `chains`. Purposes are `login`, `mfa`, and `escalation`.
An absent/empty login or escalation policy denies authentication. An absent/empty
MFA policy requires no additional verification. A nonempty policy with missing
or inactive credentials remains required and cannot be satisfied through them.

Alternatives are OR; steps inside an alternative are ordered AND. Each step has
`method` and an explicit nonempty `credential_ids` pool. There are no wildcards
that would automatically authorize future registrations.

```json
[
  [
    {"method": "publickey", "credential_ids": ["key-A", "key-B"]},
    {"method": "publickey", "credential_ids": ["key-A", "key-B"]}
  ],
  [{"method": "password", "credential_ids": ["password-1"]}]
]
```

This accepts two different authorized public keys, in either order, or the
selected password. Repeated public-key steps cannot reuse the same key material,
even through separate evidence events or different registration IDs. The ordered
chain model follows [OpenSSH AuthenticationMethods](https://man.openbsd.org/sshd_config#AuthenticationMethods).

Use `replace_auth_policy(session, user, purpose, chains,
expected_revision=...)` from trusted domain code. Revision zero creates a missing
policy; existing policies require their current revision. Concurrent changes raise
`AuthPolicyConflict`. The operation validates method and credential ownership,
participates in the caller's transaction, and never commits. Registered but
currently inactive credentials may be selected; activation is still required to
use them. Structurally valid combinations can be stored before protocol support
exists; execution never skips unsupported requirements.

## Defaults and credential lifecycle

`set_password` creates/updates only a credential and rotates the account signing
key in the same transaction. Standard `create_user(password=...)` separately
grants that password's single-step login policy. New keys and replacement
credentials gain no purpose automatically.

`setup_totp` returns a pending credential and plaintext backup codes, storing only
hashed codes. `credential.enable()` activates verification without enabling login
MFA; this supports TOTP used only for escalation. The standard `validate_2fa`
workflow calls `enable_login_totp`, which explicitly installs a single-step TOTP
MFA policy only when the MFA policy is empty. It preserves custom policies.

Removing a credential leaves policy references intact. `remove_totp` additionally
clears the MFA policy when it is exactly that credential's single-step standard
policy. The self-service disable/cancel and maintenance clear workflows use this
operation. Custom combinations are preserved, including unavailable references;
removal never silently shortens a chain or turns required MFA off.

The password-change and self-service 2FA-disable endpoints retain their dedicated
password checks. They do not implement the escalation policy in this release.

## Authentication attempts

Password and OIDC entrypoints authorize the actual verified credential as an
initial login step. They issue a GENERAL token only after both login and MFA
policies pass. Supported continuation uses the existing 202/AUTH token and
`complete_mfa` TOTP request. Other missing requirements return 403. Public-key
login transport and independent escalation-token issuance remain unimplemented.

AUTH tokens carry a signed `auth_context`: an attempt ID, login/MFA policy
revisions, and ordered credential evidence. No raw credential secrets are stored.
Continuation rechecks scope, active registrations and policy revisions; changed
policies, revoked evidence or legacy AUTH tokens require restarting login.
The original attempt expiry is not extended by continuation. GENERAL tokens have
no added claim; existing sessions retain their existing lifetime.

Evidence can satisfy login and MFA independently within the same attempt, in the
required order. A single event counts only once inside a chain. Historical login
sessions do not supply evidence for a future escalation attempt. Backup-code
consumption is committed with successful authentication/continuation, and rolled
back when the request cannot continue.

`get_2fa_status.enabled` means the MFA policy is nonempty. `methods` lists policy
methods; legacy `method` is that method when exactly one exists, otherwise null.
TOTP activation alone does not set this flag.

## OIDC binding and rollout

OIDC credentials persist the local user ID and exact `(issuer, subject)` identity.
The model, binding commands and archive codecs belong to `oidc_sso`; its
independent data entrypoint is usable even while OIDC login is disabled and
without installing its optional HTTP/OAuth dependencies. Core imports do not
register or create this model. See [Extension-owned data](EXTENSIONS.md#extension-owned-data).
A SHA-256 digest of the JSON pair provides a fixed-length unique database key;
lookup also compares the original strings. These are the stable identity claims
specified by [OIDC Core 5.7](https://openid.net/specs/openid-connect-core-1_0.html#ClaimStability).
Username claims are used only when choosing a name for a newly provisioned account.

Existing accounts must be explicitly linked before their next SSO login. After
loading the enabled OIDC provider, trusted code can bind and grant independently:

```python
from include.domains.identity.auth.types import AuthPurpose
from include.domains.identity.commands.auth_policies import replace_auth_policy
from include.extensions.oidc_sso.credentials import bind_oidc_identity

with sessions.begin() as session:
    user = session.get(User, user_id)
    credential = bind_oidc_identity(session, user, issuer, subject)
    replace_auth_policy(
        session,
        user,
        AuthPurpose.LOGIN,
        [[{"method": "oidc", "credential_ids": [credential.id]}]],
        expected_revision=current_login_revision,
    )
```

The example replaces login authorization; include other desired alternatives when
retaining them. Binding alone grants nothing. Existing accounts are never linked
by matching an unbound identity's username claim. Auto-provisioning creates a
new passwordless account, binding, memberships and default OIDC login policy in
one transaction; a collision with an existing username rejects provisioning.
Existing bindings survive local/remote display-name changes. OIDC callbacks keep
their state, PKCE, signature, nonce, issuer and audience checks. Provider evidence
is created only from a verified callback; client-supplied issuer/subject pairs
cannot substitute for verification. Upstream MFA claims do not satisfy local MFA.

Extensions register providers through `ext_register_auth_methods`, invoked before
requests are served. Optional OIDC dependencies stay within the extension.

## Migration and backups

The migration assigns credential IDs and explicitly preserves existing password
login and enabled-TOTP MFA. Public keys and escalation receive no automatic
authorization. Existing OIDC identities cannot be inferred from usernames and
must be bound explicitly. No production database is upgraded by editing source.
Downgrade refuses OIDC bindings or policies that cannot preserve legacy behavior.

Account backups and database transfers include policies, credential IDs and OIDC
bindings while the extension is installed, including when it is disabled. If the
extension is missing, maintenance refuses its tables rather than dropping data.
Existing binding rows and credential IDs are adopted unchanged. Legacy archives without a policy table receive IDs and legacy local
policies during restore. An included but empty policy table is authoritative and
never gains reconstructed authorization. New archives must retain credential IDs.
The existing archive format and encryption remain unchanged.

Foreign keys cascade on user deletion, never from a credential to a user. Keep
all credential reads and verification effects in the caller's session. Password
rehashing preserves age/forced-update markers; backup-code verification may
mutate a credential and must be committed by the owning workflow.
