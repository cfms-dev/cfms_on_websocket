"""Presentation metadata for explicitly exposed database-backed settings."""

from dataclasses import dataclass

from include.config._policy import ConfigValidationError


@dataclass(frozen=True, slots=True)
class SettingMetadata:
    title: str
    description: str

    def __post_init__(self) -> None:
        if not self.title.strip() or not self.description.strip():
            raise ConfigValidationError(
                "Setting title and description must not be blank"
            )


_RISK_SETTINGS = {
    "mode": (
        "Enforcement mode",
        "Observe records risk decisions without rejecting requests; enforce applies them.",
    ),
    "refill_period_seconds": (
        "Bucket refill period",
        "Seconds per refill period for account and IP token buckets.",
    ),
    "new_account_seconds": (
        "New account age",
        "Account age in seconds below which new-account risk applies.",
    ),
    "ip_account_window_seconds": (
        "IP account window",
        "Seconds over which distinct accounts using an IP address are counted.",
    ),
    "ip_accounts_elevated": (
        "Elevated IP account threshold",
        "Distinct-account count for elevated risk; must be less than ip_accounts_high.",
    ),
    "ip_accounts_high": (
        "High IP account threshold",
        "Distinct-account count for high risk; must exceed ip_accounts_elevated.",
    ),
    "denial_window_seconds": (
        "Denial window",
        "Seconds over which recent denials are counted.",
    ),
    "denials_elevated": (
        "Elevated denial threshold",
        "Denial count for elevated risk; must be less than denials_high.",
    ),
    "denials_high": (
        "High denial threshold",
        "Denial count for high risk; must exceed denials_elevated.",
    ),
    "elevated_cost": (
        "Elevated risk cost",
        "Tokens charged for an elevated-risk operation.",
    ),
    "high_cost": (
        "High risk cost",
        "Tokens charged for a high-risk operation; must fit every account and IP bucket.",
    ),
    "state_retention_seconds": (
        "Risk state retention",
        "Seconds to retain risk state; must cover every refill and risk-counting window.",
    ),
}

_CORE_SETTING_TEXT = {
    "server": {
        "name": ("Server name", "Display name returned by the server information API."),
    },
    "access": {
        "enable_access_recursive_check": (
            "Check ancestor access rules",
            "Include ancestor rules when evaluating access to a document or directory.",
        ),
    },
    "security.password": {
        "passwd_min_length": (
            "Minimum password length",
            "Minimum character count; must not exceed passwd_max_length.",
        ),
        "passwd_max_length": (
            "Maximum password length",
            "Maximum character count; must not be less than passwd_min_length.",
        ),
        "passwd_rules": (
            "Password rules",
            "Array of valid regular expressions used to assess passwords; replace the whole array to change it.",
        ),
        "passwd_min_passed_count": (
            "Required password rules",
            "Minimum number of password rules that must pass.",
        ),
        "enable_passwd_force_expiration": (
            "Expire passwords",
            "Require password renewal when the configured password age is reached.",
        ),
        "passwd_expire_after_days": (
            "Password lifetime",
            "Password age in days after which renewal is required when expiration is enabled.",
        ),
    },
    "security.auth_throttle": {
        "enabled": (
            "Enable authentication throttling",
            "Apply account and IP authentication failure limits.",
        ),
        "account_failure_threshold": (
            "Account failure threshold",
            "Failed authentication count that starts account backoff.",
        ),
        "account_base_delay_seconds": (
            "Initial account backoff",
            "Initial backoff in seconds; must not exceed account_max_delay_seconds.",
        ),
        "account_max_delay_seconds": (
            "Maximum account backoff",
            "Backoff ceiling in seconds; must be at least account_base_delay_seconds.",
        ),
        "account_reset_seconds": (
            "Account failure reset",
            "Seconds of inactivity before an account failure history resets.",
        ),
        "account_ip_failure_threshold": (
            "Account and IP failure threshold",
            "Failures for an account and IP pair that trigger a temporary block.",
        ),
        "account_ip_window_seconds": (
            "Account and IP failure window",
            "Seconds over which failures for an account and IP pair are counted.",
        ),
        "account_ip_block_seconds": (
            "Account and IP block duration",
            "Seconds to block an account and IP pair after its threshold is reached.",
        ),
        "ip_failure_threshold": (
            "IP failure threshold",
            "Failures from an IP address that trigger a temporary block.",
        ),
        "ip_window_seconds": (
            "IP failure window",
            "Seconds over which authentication failures from an IP address are counted.",
        ),
        "ip_block_seconds": (
            "IP block duration",
            "Seconds to block an IP address after its threshold is reached.",
        ),
        "record_retention_days": (
            "Authentication history retention",
            "Days to retain authentication throttle records.",
        ),
    },
    "maintenance.audit_retention": {
        "retention_days": (
            "Audit retention",
            "Days of audit history retained by the audit cleanup task.",
        ),
        "batch_size": (
            "Audit cleanup batch size",
            "Maximum audit entries removed in one cleanup batch.",
        ),
    },
    "identity.permission_retention": {
        "retention_days": (
            "Expired permission retention",
            "Days to retain expired permission entries before cleanup.",
        ),
        "cleanup_interval_seconds": (
            "Permission cleanup interval",
            "Seconds between permission cleanup runs.",
        ),
        "batch_size": (
            "Permission cleanup batch size",
            "Maximum expired permission entries removed in one batch.",
        ),
    },
    "security.request_rate_control": {
        "mode": (
            "Request rate enforcement mode",
            "Disabled bypasses rate control; observe records decisions; enforce rejects excess traffic.",
        ),
        "connection_capacity": (
            "Connection bucket capacity",
            "Maximum tokens in each connection admission bucket.",
        ),
        "connection_refill_tokens": (
            "Connection refill tokens",
            "Tokens restored to a connection bucket per connection refill period.",
        ),
        "connection_refill_period_seconds": (
            "Connection refill period",
            "Seconds per connection admission bucket refill period.",
        ),
        "request_refill_period_seconds": (
            "Request refill period",
            "Seconds per account and IP request bucket refill period.",
        ),
        "account_capacity": (
            "Account request capacity",
            "Maximum account request tokens; must accommodate every configured action cost.",
        ),
        "account_refill_tokens": (
            "Account request refill tokens",
            "Tokens restored per account request refill period.",
        ),
        "ip_capacity": (
            "IP request capacity",
            "Maximum IP request tokens; must accommodate every configured action cost.",
        ),
        "ip_refill_tokens": (
            "IP request refill tokens",
            "Tokens restored per IP request refill period.",
        ),
        "state_retention_seconds": (
            "Rate state retention",
            "Seconds to retain rate-control state; must cover both refill periods.",
        ),
        "action_costs": (
            "Action token costs",
            "Map of action names to positive token costs, each no greater than account_capacity or ip_capacity; replace the whole map to change it.",
        ),
    },
    "document.upload": {
        "start_timeout_seconds": (
            "Upload start timeout",
            "Seconds allowed to start uploading; must be less than max_duration_seconds. Existing task deadlines are preserved.",
        ),
        "max_duration_seconds": (
            "Maximum upload duration",
            "Maximum upload lifetime in seconds; must exceed start_timeout_seconds and cover idle_timeout_seconds. Existing task deadlines are preserved.",
        ),
        "idle_timeout_seconds": (
            "Upload idle timeout",
            "Seconds allowed without upload activity; must not exceed max_duration_seconds. Existing task deadlines are preserved.",
        ),
        "cleanup_interval_seconds": (
            "Upload cleanup interval",
            "Seconds between expired upload task cleanup runs; reconciled by the scheduling loop.",
        ),
        "max_pending_documents_per_creator": (
            "Pending documents per creator",
            "Maximum pending documents permitted for one creator.",
        ),
    },
    "document.upload.creation_risk_control": {
        **_RISK_SETTINGS,
        "account_capacity": (
            "Creation account capacity",
            "Maximum creation tokens per account; must be at least high_cost.",
        ),
        "account_refill_tokens": (
            "Creation account refill tokens",
            "Creation tokens restored per account refill period.",
        ),
        "ip_capacity": (
            "Creation IP capacity",
            "Maximum creation tokens per IP address; must be at least high_cost.",
        ),
        "ip_refill_tokens": (
            "Creation IP refill tokens",
            "Creation tokens restored per IP refill period.",
        ),
        "pending_elevated_ratio": (
            "Elevated pending ratio",
            "Pending-document utilization ratio for elevated risk; must be less than pending_high_ratio.",
        ),
        "pending_high_ratio": (
            "High pending ratio",
            "Pending-document utilization ratio for high risk; must exceed pending_elevated_ratio.",
        ),
    },
    "document.download.risk_control": {
        **_RISK_SETTINGS,
        "issue_account_capacity": (
            "Download issue account capacity",
            "Maximum download issuance tokens per account; must be at least high_cost.",
        ),
        "issue_account_refill_tokens": (
            "Download issue account refill tokens",
            "Issuance tokens restored per account refill period.",
        ),
        "issue_ip_capacity": (
            "Download issue IP capacity",
            "Maximum download issuance tokens per IP address; must be at least high_cost.",
        ),
        "issue_ip_refill_tokens": (
            "Download issue IP refill tokens",
            "Issuance tokens restored per IP refill period.",
        ),
        "transfer_account_capacity": (
            "Transfer account capacity",
            "Maximum transfer tokens per account; must be at least high_cost.",
        ),
        "transfer_account_refill_tokens": (
            "Transfer account refill tokens",
            "Transfer tokens restored per account refill period.",
        ),
        "transfer_ip_capacity": (
            "Transfer IP capacity",
            "Maximum transfer tokens per IP address; must be at least high_cost.",
        ),
        "transfer_ip_refill_tokens": (
            "Transfer IP refill tokens",
            "Transfer tokens restored per IP refill period.",
        ),
        "task_capacity": (
            "Download task capacity",
            "Maximum tokens in a download task bucket.",
        ),
        "task_refill_tokens": (
            "Download task refill tokens",
            "Tokens restored per download task refill period.",
        ),
        "task_refill_period_seconds": (
            "Download task refill period",
            "Seconds per download task bucket refill period.",
        ),
    },
    "scheduling": {
        "misfire_grace_seconds": (
            "Schedule misfire grace",
            "Seconds of lateness allowed before a scheduled execution is treated as missed.",
        ),
        "history_retention_days": (
            "Schedule history retention",
            "Days to retain scheduled execution history.",
        ),
    },
}

_EFFECTIVE_TIMES = {
    "security.password": "Applies to subsequent password assessments and authentication decisions; changing the policy invalidates pending assessments.",
    "maintenance.audit_retention": "Applies to subsequent audit cleanup runs.",
    "identity.permission_retention": "Applies to subsequent cleanup runs; interval changes are reconciled by the scheduling loop.",
    "scheduling": "Applies to subsequent scheduling decisions and history cleanup runs.",
}

CORE_SETTING_METADATA = {
    namespace: {
        key: SettingMetadata(
            title,
            description
            + " "
            + _EFFECTIVE_TIMES.get(namespace, "Applies to subsequent operations."),
        )
        for key, (title, description) in settings.items()
    }
    for namespace, settings in _CORE_SETTING_TEXT.items()
}
