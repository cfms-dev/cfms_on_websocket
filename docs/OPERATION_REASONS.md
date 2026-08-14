# Operation reasons

Administrative actions use one shared reason contract. A reason is a JSON string
between 1 and 1024 characters. Whitespace is preserved; an empty string is
invalid.

For actions that can update an active operation, the `reason` field has
tri-state semantics:

| Request value | Meaning |
| --- | --- |
| field omitted | Preserve the current reason |
| string | Replace the current reason |
| `null` | Clear the current reason |

Sending the current value again is an idempotent success. It does not create a
reason-change audit payload or repeat operational side effects.

## Supported actions

| Business operation | Create or activate | Update an active reason | Storage | Visibility |
| --- | --- | --- | --- | --- |
| Account disabled status | `manage_user_status` with `status: "disabled"` | Repeat `manage_user_status` while disabled | Deduplicated comment | Included in disabled-login response |
| User block | `block_user` | `update_user_block` | Deduplicated comment | Included in `block_user`, `update_user_block`, and `list_user_blocks` responses; users may list their own blocks |
| Service lockdown | `lockdown` with `status: true` | Repeat `lockdown` while enabled | Lockdown state | Included in lockdown state and broadcast responses |
| Banned subnet | `create_banned_subnet` | `update_banned_subnet` | Deduplicated comment | Included in banned-subnet responses |

`manage_user_status` and `lockdown` reject a `reason` field when activating an
incompatible state (`status: "active"` and `status: false`, respectively).
Changing only a lockdown reason does not cancel file tasks. Changing only a
banned-subnet reason does not refresh the active subnet guard.

## Audit data

When a reason actually changes, the normal audit entry contains this stable
shape in its `data` object:

```json
{
  "reason_change": {
    "previous": "Old reason",
    "current": "Corrected reason"
  }
}
```

Either value may be `null`. Initial reason creation uses `previous: null`.
