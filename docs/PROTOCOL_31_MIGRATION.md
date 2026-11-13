# Protocol 31: audit action exclusions

Upgrade clients and servers together. Protocol 31 adds optional `exclude_filters`
to `core.audit.entry.list`. See [Audit log API](AUDIT_LOG_API.md).

The query selects `(no includes OR action IN filters) AND action NOT IN exclude_filters`
before sorting and cursor pagination. Both arrays contain exact, case-sensitive
action values, including unknown extension and historical values. Empty or omitted
arrays impose no condition. If a value appears in both, exclusion wins.

Cursors bind both arrays as sorted sets. Reordering or repeating values is allowed;
changing either set with an existing cursor returns 400. Protocol 30 cursors are
not reusable. Response fields, permissions and request-rate cost remain unchanged.

The client management view initially excludes `core.audit.entry.list` and
`core.setting.get`. This is a visible, editable client preference for the current
management view, not a server default or a change to audit recording. Clearing both
lists returns all actions. No database migration or application version change is
required. Historical audit records remain unchanged.
