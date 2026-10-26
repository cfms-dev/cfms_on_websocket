# Protocol 29 request names and MFA migration

Protocol 29 replaces every built-in top-level request name with
`namespace.resource[.subresource...].action`. Core requests, including the built-in
extension and debug handler, use `core`; optional extensions use their identifier.
Resources are singular and words within a segment use snake_case. The server does
not enforce this naming grammar on third-party registrations.

Old request names are not registered and have no aliases. Upgrade clients,
extensions, and action-cost configuration together. Handler registration, removal,
overrides, and lockdown allowlists use the new names. Restart server instances
after deploying the matching code and configuration.

Only top-level requests change. Authentication PROCESS messages (`auth_challenge`,
`auth_continue`, `auth_response`), file-transfer messages (`transfer_file`,
`file_chunk`, `aes_key`, `transfer_complete`), and raw transfer acknowledgements
keep their existing values. Permissions, scheduled task types, HTTP routes, and
internal audit events are unchanged. The package version is independent of the
protocol version.

## MFA and TOTP

The general concept is **multi_factor_auth (MFA)**. TOTP is one authentication
method; an active TOTP credential does not itself require MFA. Confirming TOTP
setup now only activates that credential and never changes authentication policies
or their revisions. Existing credentials and policies remain unchanged on upgrade.

To require login MFA, explicitly set `purpose: "mfa"` through
`core.user.authentication.policy.set` using the current revision and registered
credential IDs from `core.user.authentication.get`. This preserves the existing
permission and ESCALATION-token requirements. Clients may activate TOTP solely for
escalation, or configure MFA using another supported method such as a public key.
Token exchange continues to complete the configured policy.

`core.user.authentication.totp.status.get` accepts the same optional `user_id` and
uses the existing read permissions. Its response data has exactly these fields:

```json
{"configured": true, "enabled": false, "backup_codes_count": 10}
```

`configured` means a TOTP credential exists, `enabled` means it is active, and
`backup_codes_count` counts its remaining backup codes. Missing credentials report
`false`, `false`, and `0`. Pending setup reports configured but not enabled.
Read general MFA configuration from `core.user.authentication.get` under
`policies.mfa`; a nonempty chain list requires additional login authentication.
The status response no longer contains the generic `method` or `methods` fields.

Deleting TOTP removes that credential and prunes its policy dependencies using the
existing transaction, revision-conflict and authentication-availability checks. It
does not delete other credentials or unrelated policies. Cancelling setup only
removes a pending credential. Other request and response fields remain unchanged.

## Configuration, cursors and history

TOML action-cost keys containing dots must be quoted:

```toml
[security.request_rate_control.action_costs]
"core.search.query" = 4
"core.document.upload" = 8
```

Rename existing overrides explicitly. Old keys are unknown actions and continue to
produce the existing startup warning; there is no automatic conversion.

Pagination cursors bind to the new request names. Discard pre-upgrade cursors and
restart pagination. New request audit entries use new names. Historical entries
retain their original values and filters match exactly: use an old filter string
when reading old records. No database migration rewrites audit history.
The brute-force-lockdown extension counts `core.auth.login` failures only, so
pre-upgrade `login` entries do not contribute to the new detection window.

## Complete request mapping

The debug request is registered only when debugging is enabled. OIDC requests
require the optional `oidc_sso` extension.

| Previous request | Protocol 29 request |
| --- | --- |
| `login` | `core.auth.login` |
| `exchange_token` | `core.auth.token.exchange` |
| `refresh_token` | `core.auth.token.refresh` |
| `get_user_authentication` | `core.user.authentication.get` |
| `set_user_auth_policies` | `core.user.authentication.policy.set` |
| `register_user_auth_public_key` | `core.user.authentication.public_key.register` |
| `update_user_auth_public_key` | `core.user.authentication.public_key.update` |
| `delete_user_auth_public_key` | `core.user.authentication.public_key.delete` |
| `setup_2fa` | `core.user.authentication.totp.setup` |
| `cancel_2fa_setup` | `core.user.authentication.totp.setup.cancel` |
| `validate_2fa` | `core.user.authentication.totp.setup.confirm` |
| `disable_2fa` | `core.user.authentication.totp.delete` |
| `get_2fa_status` | `core.user.authentication.totp.status.get` |
| `list_banned_subnets` | `core.security.banned_subnet.list` |
| `create_banned_subnet` | `core.security.banned_subnet.create` |
| `update_banned_subnet` | `core.security.banned_subnet.update` |
| `delete_banned_subnet` | `core.security.banned_subnet.delete` |
| `list_auth_lockouts` | `core.security.auth_lockout.list` |
| `unlock_auth_lockouts` | `core.security.auth_lockout.unlock` |
| `get_document` | `core.document.get` |
| `create_document` | `core.document.create` |
| `upload_document` | `core.document.upload` |
| `delete_document` | `core.document.delete` |
| `restore_document` | `core.document.restore` |
| `purge_document` | `core.document.purge` |
| `rename_document` | `core.document.rename` |
| `move_document` | `core.document.move` |
| `get_document_info` | `core.document.info.get` |
| `get_document_access_rules` | `core.document.access_rule.get` |
| `set_document_rules` | `core.document.access_rule.set` |
| `set_document_tags` | `core.document.tag.set` |
| `list_revisions` | `core.document.revision.list` |
| `get_revision` | `core.document.revision.get` |
| `set_current_revision` | `core.document.revision.current.set` |
| `delete_revision` | `core.document.revision.delete` |
| `download_file` | `core.file.download` |
| `upload_file` | `core.file.upload` |
| `list_directory` | `core.directory.list` |
| `get_directory_info` | `core.directory.info.get` |
| `get_directory_access_rules` | `core.directory.access_rule.get` |
| `set_directory_rules` | `core.directory.access_rule.set` |
| `create_directory` | `core.directory.create` |
| `delete_directory` | `core.directory.delete` |
| `restore_directory` | `core.directory.restore` |
| `purge_directory` | `core.directory.purge` |
| `rename_directory` | `core.directory.rename` |
| `move_directory` | `core.directory.move` |
| `list_deleted_items` | `core.directory.deleted_item.list` |
| `search` | `core.search.query` |
| `manage_user_status` | `core.user.status.set` |
| `block_user` | `core.user.block.create` |
| `unblock_user` | `core.user.block.delete` |
| `update_user_block` | `core.user.block.update` |
| `list_user_blocks` | `core.user.block.list` |
| `list_users` | `core.user.list` |
| `create_user` | `core.user.create` |
| `delete_user` | `core.user.delete` |
| `rename_user` | `core.user.rename` |
| `get_user_info` | `core.user.info.get` |
| `get_user_avatar` | `core.user.avatar.get` |
| `set_user_avatar` | `core.user.avatar.set` |
| `change_user_groups` | `core.user.group.change` |
| `change_user_permissions` | `core.user.permission.change` |
| `set_passwd` | `core.user.password.set` |
| `list_groups` | `core.group.list` |
| `create_group` | `core.group.create` |
| `delete_group` | `core.group.delete` |
| `rename_group` | `core.group.rename` |
| `get_group_info` | `core.group.info.get` |
| `change_group_permissions` | `core.group.permission.change` |
| `grant_access` | `core.access.entry.grant` |
| `revoke_access` | `core.access.entry.revoke` |
| `view_access_entries` | `core.access.entry.list` |
| `lockdown` | `core.server.lockdown.set` |
| `view_audit_logs` | `core.audit.entry.list` |
| `list_scheduled_task_types` | `core.schedule.task_type.list` |
| `create_schedule` | `core.schedule.create` |
| `get_schedule` | `core.schedule.get` |
| `list_schedules` | `core.schedule.list` |
| `update_schedule` | `core.schedule.update` |
| `delete_schedule` | `core.schedule.delete` |
| `upload_user_key` | `core.user.key.upload` |
| `get_user_key` | `core.user.key.get` |
| `delete_user_key` | `core.user.key.delete` |
| `set_user_preference_dek` | `core.user.preferred_dek.set` |
| `list_user_keys` | `core.user.key.list` |
| `server_info` | `core.server.info.get` |
| `diagnostics` | `core.server.diagnostics.get` |
| `shutdown` | `core.server.shutdown` |
| `sso_oidc_start` | `oidc_sso.session.start` |
| `sso_oidc_callback` | `oidc_sso.session.callback` |
| `throw_exception` | `core.debug.exception.throw` |
