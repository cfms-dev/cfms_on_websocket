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
| Account disabled status | `core.user.status.set` with `status: "disabled"` | Repeat `core.user.status.set` while disabled | Deduplicated comment | Included in disabled-login response |
| User block | `core.user.block.create` | `core.user.block.update` | Deduplicated comment | Included in `core.user.block.create`, `core.user.block.update`, and `core.user.block.list` responses; users may list their own blocks |
| Service lockdown | `core.server.lockdown.set` with `status: true` | Repeat `core.server.lockdown.set` while enabled | Lockdown state | Included in lockdown state and broadcast responses |
| Banned subnet | `core.security.banned_subnet.create` | `core.security.banned_subnet.update` | Deduplicated comment | Included in banned-subnet responses |

`core.user.status.set` and `core.server.lockdown.set` reject a `reason` field when activating an
incompatible state (`status: "active"` and `status: false`, respectively).
Changing only a lockdown reason does not cancel file tasks. Changing only a
banned-subnet reason does not refresh the active subnet guard. When a lockdown was
started by a scheduled window, changing its reason is also an explicit manual
takeover: the window's automatic expiration is removed. Repeating the identical
reason remains a no-op and preserves that expiration.

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
