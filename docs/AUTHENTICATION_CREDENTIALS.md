# Authentication credentials and purpose policies

`User` owns account identity, status, permissions and the token signing key.
Each authentication method owns its credential tables and verification logic.
Credentials and policies reference `users.id`; `User` has no reverse credential
relationships or method-specific properties.

## User signing keys and the global key

Every persisted user has an independent, non-empty `secret_key`, including
passwordless and OIDC-provisioned accounts. SQLAlchemy generates a random
32-byte key encoded as 64 hexadecimal characters when inserting a new user.
The database rejects NULL and empty strings. The default is applied at INSERT,
so callers must flush a newly constructed user before issuing tokens.

All user JWT purposes (AUTH, POST_AUTH, GENERAL and GENERAL|ESCALATION) are signed
and verified exclusively with that user's key. Authentication contexts store
its SHA256 digest to detect key changes during authentication. Changing a
password or running `maintain user rotate-secrets` replaces user signing keys,
invalidating their previous tokens and authentication contexts.

`server.secret_key` remains independent configuration for pagination cursor
encryption and rate-limit identity digests. Changing it invalidates old cursors
and changes rate-limit bucket identities; it does not revoke user tokens or
authentication contexts. `security.pepper` is a separate secret used by password
and backup-code verification.

When upgrading from nullable user keys, stop every instance sharing the
database, back up the database, run
`uv run --locked maintain database upgrade --yes`, and then start the new
release. The migration generates independent random keys only for users whose
key is NULL or empty; those users must log in again. Existing non-empty keys
and their tokens remain valid. Restoring a historical backup applies the same
rule to missing, NULL or empty user keys. Downgrading relaxes the constraints
without restoring missing keys or reviving invalidated tokens.

## Registered credentials are not authorization

Password and TOTP remain singleton rows keyed by `user_id`. Their independent
random `credential_id` identifies the registration, not its current secret.
Changing a password keeps its ID; deleting and registering a replacement creates
a new ID. Public keys and OIDC bindings use their existing/random row IDs.
Pending TOTP credentials appear in inventory with `active=False`.

Providers declare `supported_purposes` and implement
`authenticate(handler, attempt, payload)`, `list_credentials(session, user)` and
`verify(session, user, payload, context)`. The request handler selects the provider
immediately; the selected provider validates its payload, resolves the login
identity, and owns its complete verification/dialog flow. Password and public-key
providers support all purposes. TOTP supports only MFA and escalation. Extension
methods declare their own purposes; category alone grants none.

`AuthenticationAttempt` is a request-local dataclass. Its `bind`, `progress`,
`permitted_credentials`, `accept`, and `receive` operations enforce account,
policy, expiry, evidence, throttling and interaction boundaries. Providers must
check permission before credential verification and call `accept` with an
immutable `AuthVerificationResult` for each verified credential. `accept` commits
verification effects. A provider returns only after completing its selected
method's policy. Shared finalization then issues the appropriate token.
Provider instances are shared and must never retain request-local state.

`permitted_credentials` returns an empty set when the selected method has no
authorized credentials. Providers reject this with the same 401 `Invalid
credentials` response and empty data as a missing account or invalid proof,
and record an authentication failure. They must not expose method availability
through a separate permission error. Password login performs dummy password
verification for missing accounts or unauthorized methods. Public-key login
sends no challenge without an authorized matching key.

Credential inventory exposes IDs, method, activity and display information,
never credential secrets. Verification success names the actual credential.
Challenge state belongs only to the current request and is never trusted from
client input. Password assessment is returned as a typed result, not through a
mutable verification-context dictionary.

`auth_registry.list_user_credentials(session, user)` enumerates registrations.
`evaluate_user_policy` determines authorization and next steps for a purpose.
`user_requires_mfa` and `get_user_mfa_methods` read the MFA policy rather than
inferring requirements from enabled TOTP credentials.

## Purpose policies

`UserAuthPolicy` has composite key `(user_id, purpose)`, a positive `revision`,
and JSON `chains`. Purposes are `login`, `mfa`, and `escalation`.
An absent/empty login policy denies authentication. An absent/empty escalation
policy permits a valid GENERAL token to be exchanged directly for an elevated
token, without further proof. An absent/empty MFA policy requires no additional
verification. A nonempty policy with missing
or inactive credentials remains required and cannot be satisfied through them.

Alternatives are OR; steps inside an alternative are ordered AND. Every chain
uses exactly one method. Separate alternatives may use different methods. Each step has
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

Policy chains define which credential proofs are required and their order. Each
provider owns the dialog that collects those proofs. The public-key provider
supports multiple steps in one request, using a fresh challenge for each distinct
key; password, TOTP and OIDC providers each verify one credential per request.

Use `replace_auth_policy(session, user, purpose, chains,
expected_revision=...)` from trusted domain code. Revision zero creates a missing
policy; existing policies require their current revision. Concurrent changes raise
`AuthPolicyConflict`. The operation validates method and credential ownership,
participates in the caller's transaction, and never commits. Registered but
currently inactive credentials may be selected; activation is still required to
use them. Policy replacement rejects mixed-method chains and methods that do not support
the requested purpose. Existing mixed or unsupported chains are unavailable as
whole alternatives; their requirements are never removed or shortened.

Policy replacement rejects login chains containing TOTP before changing the
stored policy or revision. At runtime, any existing login alternative containing
TOTP is entirely unavailable; its steps are never removed or shortened. Other
valid alternatives remain usable. Accounts with only such login alternatives
need their policies replaced through trusted management code. No automatic
policy migration is performed.

## Defaults and credential lifecycle

`set_password` creates/updates only a credential and rotates the account signing
key in the same transaction. Standard `create_user(password=...)` separately
grants that password's single-step login policy. New keys and replacement
credentials gain no purpose automatically.

`setup_totp` returns a pending credential and plaintext backup codes, storing only
hashed codes. `core.user.authentication.totp.setup.confirm` verifies the setup code
and activates the TOTP credential without creating or modifying any authentication
policy or revision. Configure multi_factor_auth (MFA) explicitly through
`core.user.authentication.policy.set` with `purpose: "mfa"`. An active TOTP
credential may instead be used only for escalation, and MFA may use other supported
methods such as public keys. Existing credentials and policies survive the upgrade
unchanged. See [the protocol 29 migration guide](PROTOCOL_29_MIGRATION.md).

Public-key deletion and `remove_totp` remove the deleted credential ID from
all purpose policies in the same transaction. Nonempty credential pools retain
their remaining selectors. A chain is removed in full if any pool becomes empty
or distinct public keys can no longer satisfy its steps; steps are never removed
to shorten a chain. Pending registrations are retained. Reduced duplicate chains
are merged, preserving the first alternative, and each changed policy revision
increments once. Empty policy rows retain their revision.

Deletion must preserve a complete login/MFA path; otherwise it rolls back with
`409` and `reason: login_unavailable`. MFA and escalation policies may become
empty, disabling their additional verification. The self-service disable/cancel
and maintenance clear workflows use the shared TOTP removal operation. Extension
credential removal workflows should call
`remove_credential_from_auth_policies(session, user, method, credential_id)` in
their transaction and check availability before committing.

Ordinary password configuration requires a GENERAL|ESCALATION token and the
applicable configuration permission, without the old password. Self-service
TOTP deletion retains its password verification in addition to configuration
permission. Empty escalation policies still allow elevation without another
proof; an elevated token alone does not imply that MFA was performed.

## Authentication attempts and token exchange (protocol 29)

Protocol 29 renames `complete_mfa` to `core.auth.token.exchange` and removes the old action.
Clients must use the new action for both login MFA and escalation. Deployments
with an `action_costs.complete_mfa` override must rename it to
`action_costs."core.auth.token.exchange"`. Policy storage and token formats are unchanged;
this rename does not require signing-key rotation.

Each login or `core.auth.token.exchange` Request uses exactly one method for its entire
lifetime. Method changes in PROCESS responses are rejected with 400. Password
login verifies the initial Request and sends no PROCESS messages. Repeated
password steps that one proof cannot satisfy fail with 403. TOTP likewise
verifies the token submitted in the initial MFA/escalation request. Only methods
that need dialogs, such as public keys, ask for additional input.

Login completes its `login` policy first. An empty `mfa` policy needs no further
verification. A nonempty MFA policy uses fresh evidence and excludes the entire
login method, even if it authorizes another credential of that method. Login
evidence never also satisfies MFA. If no remaining authorized method is usable,
login returns 403 without a continuation token; MFA is not silently disabled.
Otherwise login returns 202 with an AUTH token and the eligible method names.

AUTH and POST_AUTH contain signed `auth_context` with the login method,
attempt ID, policy revisions, signing-key digest and credential evidence. Token
purpose determines the operation; there is no redundant context stage marker or
shared cache entry identifying the operation. Changed policies, signing keys,
registrations require a fresh login. Contexts have no version field; incompatible
authentication upgrades require administrators to rotate all user signing keys
as described below. This also invalidates existing GENERAL sessions.

### Requests and dialogs

Password login retains its payload:

```json
{"action":"core.auth.login","data":{"method":"password","credential":{"username":"alice","password":"current password"}}}
```

Public-key login uses `credential.username` and `credential.fingerprint` (hex or
base64). Extensions own their `credential` payload shape and identity resolution.
TOTP cannot initiate a login. MFA/escalation always fixes the account to the
verified source token's subject; method payloads cannot select another account.

`core.auth.token.exchange` requires `target_purpose` as an integer, either 2 or 6:

```json
{"method":"totp","data":{"token":"123456"},"target_purpose":2}
```

| Source token | Requested purpose | Operation |
| --- | --- | --- |
| AUTH | GENERAL | Finish login MFA using the `mfa` policy |
| GENERAL | GENERAL\|ESCALATION | Reauthenticate using the `escalation` policy |
| POST_AUTH, any other combination | Any | Denied |

POST_AUTH cannot be requested. Invalid/missing target values return 400; invalid
source/target combinations return 403. Successful issuance responses expose the
actual integer `purpose` alongside `token` and `exp`.

Public-key authentication owns the following same-Stream PROCESS exchange:

```json
{"action":"auth_challenge","data":{"stage":"login","method":"publickey","interaction_id":"random-id","challenge":"base64-exact-bytes","expires_in":60}}
```

The client signs the exact decoded bytes, without reserialization, then replies:

```json
{"action":"auth_response","interaction_id":"random-id","method":"publickey","data":{"fingerprint":"key-fingerprint","signature":"base64-signature"}}
```

For another required public key, `auth_continue` supplies same-method
`next_steps`, a new `interaction_id`, and stage (`login`, `mfa`, or `escalation`).
The client replies with that interaction ID, `method="publickey"`, and
`data.fingerprint`; a fresh challenge follows. Distinct required keys cannot reuse
the same key material. Dialogs have no fixed round cap or idle/total deadline;
policy progress bounds successful credential submissions.

The immutable signed challenge contains scope `cfms.auth.publickey`, user UUID,
attempt ID, stage, Stream ID, interaction ID, fingerprint and a fresh nonce.
Challenges are request-local, single-use, and expire after 60 seconds. Ed25519,
RSA SHA-256 (PSS or PKCS#1 v1.5), and ECDSA SHA-256 algorithms are unchanged.
Waiting holds no database session or transaction. Expiry is checked after every
wait and before credential consumption or issuance. Every credential is
throttled using the provider's `throttle_factor`; PROCESS responses also incur
request-rate charges. Disconnects are audited as 499; timeouts as 408; malformed
interactions as 400; invalid proofs as 401.

### Escalation and refresh

Escalation has no preceding authentication step in the current Request. It can
use password, public key, TOTP, or an extension method explicitly authorized by
the independent `escalation` policy. With a missing/empty escalation policy,
submit `{"target_purpose":6}` to `core.auth.token.exchange` using a valid GENERAL token;
`method` and `data` may be omitted and no provider is invoked. A configured
nonempty policy requires both fields and fresh verification; missing fields
return 400. Login MFA always requires both fields. Direct escalation rechecks
the account status, token expiry and current signing key under the same user
write lock used by authentication management. Historical login evidence is
never reused. Issuing the escalation flag
does not bypass any existing business permission checks and does not update
`last_login`.

`ESCALATION_TOKEN_EXPIRY_SECONDS` defaults to 300. Its lifetime starts at successful
issuance and is not capped by the old GENERAL token's expiry. The old token must
still be valid when verification finishes. `core.auth.token.refresh` returns only GENERAL,
including when refreshing a GENERAL|ESCALATION token; further escalation requires
fresh verification. AUTH and POST_AUTH cannot be refreshed.

### Required password changes and POST_AUTH

A correct password remains valid authentication evidence even when expired,
forced to change, or failing current password rules. Verification returns a typed
assessment without retaining plaintext. Its credential ID, modification time,
policy digest and compliance result are kept in the existing caching provider
when continuation is needed. The cache does not identify the operation. Lost
assessment state or changed password policy requires restarting login. Shared
caching or sticky routing remains necessary for multi-node continuation.

Only passwords actually verified in the attempt are checked. Pure public-key or
OIDC login does not require changing an unused password. Rule compliance takes
precedence over expiration; forced updates apply even if periodic expiry is off.
After login and MFA pass, an AUTH request for GENERAL can instead return
4001/4002 with a POST_AUTH token:

```json
{"token":"POST_AUTH-JWT","exp":1234567890,"purpose":8,"required_actions":["change_password"]}
```

POST_AUTH lasts at most five minutes, bounded by the source AUTH expiry. It
allows only `core.user.password.set` with `new_passwd`, normal nonce/timestamp protection, and
the token subject as target. No account selectors, old password or administrator
options are accepted. It grants no GENERAL/ESCALATION authority and cannot be
used for MFA, refresh, or other WebSocket/HTTP endpoints. Only the restricted
password-change action receives the existing lockdown exception.

The new password must satisfy current rules and differ from the old password.
Policy/credential state is rechecked. Password update and conditional signing-key
rotation commit atomically, so concurrent uses have one winner. Success returns
200 with no token: the user must log in again, and old account tokens are invalid.
Ordinary authenticated password changes require configuration permission and
a token with ESCALATION purpose. GENERAL may coexist with ESCALATION but is not
required for password changes. POST_AUTH remains a restricted permission-free
exception. `last_login` changes only when a completed login issues GENERAL.

`core.user.password.set` relies on request-entry token authentication in the router and does
not revalidate the token during handler execution. Self-service password changes
and POST_AUTH atomically match and rotate the signing key associated with the
request token in the same transaction as the password update. Requests using the
same old key have at most one successful commit; a key or account-status conflict
returns 401 without changing the password or key and is not retried automatically.
The existing password-rule and unchanged-password checks run before the
conditional update, so an unchanged password still returns 400. POST_AUTH also
checks its authentication context. Administrator resets of other users retain
serialized writes without this version check and may overwrite an earlier reset.

Protocol 29 requires clients to submit `target_purpose` and handle the actual
issued purpose. No database or archive migration is needed.
`core.user.authentication.totp.status.get` returns `configured`, `enabled`, and
`backup_codes_count` for the TOTP credential only. Read MFA configuration from
`core.user.authentication.get` under `policies.mfa`; a nonempty chain list requires
additional login authentication. TOTP activation alone does not enable MFA.

### Breaking authentication upgrades

Authentication contexts have no format or semantic version marker. Whenever a
release changes authentication or token semantics incompatibly, administrators
must invalidate all existing tokens before allowing requests on the new release:

1. Stop every server instance, including HTTP API servers and any other process
   that can authenticate users or issue tokens. Drain or terminate existing
   requests and authentication dialogs.
2. Deploy the new release to every instance while keeping services stopped.
3. From the server root or its project directory, run:

   ```powershell
   uv run --locked maintain user rotate-secrets
   ```

   Confirm the operation, or supply `--yes` for an unattended upgrade.
4. After the command succeeds, start all instances on the new release. Every
   user must log in again. For separate user databases, repeat the rotation for
   each database before starting its services.

This procedure is required when removing the context version field as well.
Apply the same procedure to rollbacks with incompatible authentication semantics.
There is no automatic context migration or version negotiation.

The command assigns each user an independent random 32-byte signing key in a
single transaction, including inactive and passwordless users. It reports the
affected user count without printing keys. A failure rolls back the entire
rotation. Passwords, TOTP secrets, registered credentials, policies and the
server configuration are unchanged. AUTH, POST_AUTH, GENERAL and GENERAL|ESCALATION tokens signed with
the previous keys fail signature verification. Updating only `server.secret_key`
does not invalidate tokens belonging to users with independent signing keys.

Keep policy revision and signing-key digest validation: these still invalidate
authentication in progress when the relevant policies or keys change. Rotation
does not undo requests that already passed authentication, which is why services
must be stopped. Restoring a database backup can restore old signing keys;
repeat the rotation before serving requests after an incompatible restore.

## User authentication management

These authenticated protocol-29 WebSocket actions accept optional `user_id`
(an account UUID), defaulting to the caller. Self inventory requires no special
permission. Reading another account's inventory or TOTP status requires
`super_list_user_auth_methods`. Configuring oneself requires
`configure_auth_methods` or `super_configure_auth_methods`; configuring another
account requires `super_configure_auth_methods`. Super configuration does not
grant cross-user read access, and writes do not additionally require read access.
Authorization precedes target existence disclosure and credential reads.

The read action accepts GENERAL tokens; all four write actions require
GENERAL|ESCALATION. Password and TOTP lifecycle endpoints use the same
configuration permission rules. TOTP retains its existing verification
requirements. OIDC binding/unbinding remains extension-owned.
New installations grant `configure_auth_methods` to `user` and both super
permissions to `sysop`. Existing installations must grant the new permissions
explicitly; there is no data migration or mapping from removed permissions.

| Action | Request fields besides optional `user_id` | Response data |
| --- | --- | --- |
| `core.user.authentication.get` | None | `user_id`, `methods`, `credentials`, `policies` |
| `core.user.authentication.policy.set` | Nonempty `policies` array of `{purpose, expected_revision, chains}` | Updated `policies`, keyed by purpose, with `revision` and `chains` |
| `core.user.authentication.public_key.register` | `public_key` (OpenSSH text), optional `label` | `credential_id`, `fingerprint` (hex), `label` |
| `core.user.authentication.public_key.update` | `credential_id`, required `label` (text or null) | `credential_id`, `label` |
| `core.user.authentication.public_key.delete` | `credential_id` | `credential_id` |

`methods` is keyed by each loaded provider's method ID, with `category`,
`throttle_factor`, supported `purposes`, and credential JSON `schema`.
`credentials` contains the existing public inventory fields: `method`,
`credential_id`, `active`, `label`, and `key_identity` (hex fingerprint for public
keys). It never contains passwords, hashes, signing keys, TOTP secrets or backup
codes. Loaded extension providers participate in both inventory and policy
configuration. `policies` always contains `login`, `mfa` and `escalation`; absent
policies have `revision: 0` and `chains: []`.

Public-key registration accepts Ed25519, RSA and ECDSA OpenSSH keys, normalizes
storage to SubjectPublicKeyInfo DER and calculates SHA-256 over the canonical
OpenSSH public-key text without its comment. The latter matches existing CFMS
fingerprints; it is not the SSH wire-blob fingerprint used by `ssh-keygen`.
Labels contain at most 255 characters; null clears a label. A registration is
authorized by the elevated caller without an additional possession challenge.
It grants no authentication purpose. Keys cannot be replaced in place: register
a replacement, update policies and then remove the old key. Deletion prunes policy
dependencies atomically as described above and does not shorten chains.

For example, after registering a key, a caller can configure public-key login
with password MFA and public-key escalation in one transaction:

```json
{"action":"core.user.authentication.policy.set","data":{"policies":[
  {"purpose":"login","expected_revision":1,"chains":[[{"method":"publickey","credential_ids":["key-id"]}]]},
  {"purpose":"mfa","expected_revision":0,"chains":[[{"method":"password","credential_ids":["password-id"]}]]},
  {"purpose":"escalation","expected_revision":0,"chains":[[{"method":"publickey","credential_ids":["key-id"]}]]}
]}}
```

Each purpose may appear once. Within each purpose, duplicate complete chains
are rejected with `400` and `reason: invalid_policy`. Equality preserves step
order and compares each step's method and credential ID set, ignoring pool
order. Identical chains in different purposes are allowed.
Updates use current revisions, increment each changed revision by one, and
commit or roll back as a group. Write operations
serialize on the target user's row before reading authentication state. Policy
updates and key deletion must preserve at least one complete login path,
including a different-method MFA alternative when MFA is required. Policy
replacements must also preserve a completable nonempty escalation policy. Credential deletion may
clear escalation by removing its last dependent chain. Inactive registrations
do not count as available; repeated public-key steps require a distinct key
assignment. Single-proof password, TOTP and OIDC flows cannot satisfy multi-step
chains. An escalation policy can be cleared by setting `chains: []` with its
current revision using a GENERAL|ESCALATION token. This disables the additional
verification for subsequent escalation: a valid GENERAL token can then be
exchanged directly for a short-lived GENERAL|ESCALATION token without method
or proof data. An empty MFA policy is allowed and disables login MFA. Availability
checks also apply to TOTP deletion workflows; ordinary trusted policy replacement
commands leave final availability checks to their caller. Availability describes
registered active credentials;
it does not prove the user still possesses their secrets or that an external
identity provider is currently reachable.

Successful actions return 200; invalid fields, keys or policies return 400,
invalid authentication returns 401, insufficient authority returns 403, and
missing users or keys return 404. Conflicts return 409 with `data.reason`:

| Reason | Meaning |
| --- | --- |
| `revision_conflict` | A supplied policy revision is stale |
| `duplicate_public_key` | The target user already registered this key |
| `login_unavailable` | No complete login/MFA path would remain |
| `escalation_unavailable` | A nonempty escalation policy would become unusable |

Malformed or unsupported keys expose `invalid_public_key` or
`unsupported_public_key`; invalid policy references or methods expose
`invalid_policy`. Audit records identify the caller, target UUID, changed
purposes and affected credential ID, without credential material. These actions
are not added to the lockdown whitelist. Rate costs are 2 for inventory and
label updates, 5 for policy updates and registration, and 3 for deletion.

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
requests are served. OIDC declares only the `login` purpose. Both the existing
`oidc_sso.session.callback` action and `core.auth.login` with `method="oidc"` use its provider flow
and the shared login finalization. The prior `oidc_sso.session.start` flow is unchanged. Optional OIDC dependencies stay within the extension.

## Migration and backups

The migration assigns credential IDs and explicitly preserves existing password
login and enabled-TOTP MFA. Public keys and escalation receive no automatic
authorization. Existing OIDC identities cannot be inferred from usernames and
must be bound explicitly. No production database is upgraded by editing source.
Downgrade refuses OIDC bindings or policies that cannot preserve legacy behavior.

Account backups and database transfers include policies, credential IDs and OIDC
bindings while the extension is installed, including when it is disabled. If the
extension is missing, maintenance refuses its tables rather than dropping data.
Existing binding rows and credential IDs are adopted unchanged. Pre-UUID archives
are converted in the temporary extraction directory: account usernames receive
UUIDs, account references are translated, and inline password/TOTP fields become
credential rows. Missing nullable account references become null; orphaned
required references are rejected and grants to deleted accounts are removed.
Legacy archives without a policy table receive IDs and legacy local
policies during restore. An included but empty policy table is authoritative and
never gains reconstructed authorization. New archives must retain credential IDs.
The existing archive format and encryption remain unchanged.

Foreign keys cascade on user deletion, never from a credential to a user. Keep
all credential reads and verification effects in the caller's session. Password
rehashing preserves age/forced-update markers; backup-code verification may
mutate a credential and must be committed by the owning workflow.
