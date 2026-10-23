-- Schema from cfms-dev/cfms_on_websocket@3959ce69559c718d758182d3de1b1101e348dfc5
CREATE TABLE account_throttles (
	username VARCHAR(256) NOT NULL,
	factor VARCHAR(16) NOT NULL,
	failed_attempts INTEGER NOT NULL,
	last_attempt DOUBLE NOT NULL,
	locked_until DOUBLE,
	CONSTRAINT pk_account_throttles PRIMARY KEY (username, factor)
);

CREATE TABLE audit_entries (
	id VARCHAR(255) NOT NULL,
	action VARCHAR(255) NOT NULL,
	username VARCHAR(256),
	target VARCHAR(255),
	data JSON,
	result INTEGER NOT NULL,
	remote_address VARCHAR(64),
	logged_time DOUBLE NOT NULL,
	CONSTRAINT pk_audit_entries PRIMARY KEY (id),
	CONSTRAINT fk_audit_entries_username_users FOREIGN KEY(username) REFERENCES users (username)
);

CREATE TABLE banned_subnets (
	subnet VARCHAR(128) NOT NULL,
	reason_comment_id INTEGER,
	created_at DOUBLE NOT NULL,
	starts_at DOUBLE NOT NULL,
	expires_at DOUBLE,
	CONSTRAINT pk_banned_subnets PRIMARY KEY (subnet),
	CONSTRAINT fk_banned_subnets_reason_comment_id_comments FOREIGN KEY(reason_comment_id) REFERENCES comments (comment_id) ON DELETE SET NULL
);

CREATE TABLE comments (
	comment_id INTEGER NOT NULL,
	digest_version SMALLINT NOT NULL,
	content_digest BLOB NOT NULL,
	comment_text TEXT NOT NULL,
	comment_data JSON,
	CONSTRAINT pk_comments PRIMARY KEY (comment_id),
	CONSTRAINT uq_comments_content_digest UNIQUE (digest_version, content_digest)
);

CREATE TABLE compiled_access_rule_groups (
	id VARCHAR(32) NOT NULL,
	rule_id INTEGER NOT NULL,
	group_index INTEGER NOT NULL,
	match_mode VARCHAR(8) NOT NULL,
	rights_match_mode VARCHAR(8) NOT NULL,
	rights_empty BOOLEAN NOT NULL,
	groups_match_mode VARCHAR(8) NOT NULL,
	groups_empty BOOLEAN NOT NULL,
	CONSTRAINT pk_compiled_access_rule_groups PRIMARY KEY (id),
	CONSTRAINT fk_compiled_access_rule_groups_rule_id_compiled_access_rules FOREIGN KEY(rule_id) REFERENCES compiled_access_rules (id) ON DELETE CASCADE
);

CREATE TABLE compiled_access_rule_memberships (
	id INTEGER NOT NULL,
	group_id VARCHAR(32) NOT NULL,
	group_name VARCHAR(255) NOT NULL,
	CONSTRAINT pk_compiled_access_rule_memberships PRIMARY KEY (id),
	CONSTRAINT fk_compiled_access_rule_memberships_group_id_compiled_access_rule_groups FOREIGN KEY(group_id) REFERENCES compiled_access_rule_groups (id) ON DELETE CASCADE
);

CREATE TABLE compiled_access_rule_rights (
	id INTEGER NOT NULL,
	group_id VARCHAR(32) NOT NULL,
	permission VARCHAR(64) NOT NULL,
	CONSTRAINT pk_compiled_access_rule_rights PRIMARY KEY (id),
	CONSTRAINT fk_compiled_access_rule_rights_group_id_compiled_access_rule_groups FOREIGN KEY(group_id) REFERENCES compiled_access_rule_groups (id) ON DELETE CASCADE
);

CREATE TABLE compiled_access_rule_sets (
	id VARCHAR(32) NOT NULL,
	node_id VARCHAR(255) NOT NULL,
	created_at DOUBLE NOT NULL,
	CONSTRAINT pk_compiled_access_rule_sets PRIMARY KEY (id),
	CONSTRAINT fk_compiled_access_rule_sets_node_id_nodes FOREIGN KEY(node_id) REFERENCES nodes (id) ON DELETE CASCADE
);

CREATE TABLE compiled_access_rules (
	id INTEGER NOT NULL,
	rule_set_id VARCHAR(32) NOT NULL,
	access_type VARCHAR(64) NOT NULL,
	match_mode VARCHAR(8) NOT NULL,
	CONSTRAINT pk_compiled_access_rules PRIMARY KEY (id),
	CONSTRAINT fk_compiled_access_rules_rule_set_id_compiled_access_rule_sets FOREIGN KEY(rule_set_id) REFERENCES compiled_access_rule_sets (id) ON DELETE CASCADE
);

CREATE TABLE document_metadata (
	document_id VARCHAR(255) NOT NULL,
	creator_username VARCHAR(256),
	last_modified_by_username VARCHAR(256),
	CONSTRAINT pk_document_metadata PRIMARY KEY (document_id),
	CONSTRAINT fk_document_metadata_document_id_documents FOREIGN KEY(document_id) REFERENCES documents (id) ON DELETE CASCADE,
	CONSTRAINT fk_document_metadata_creator_username_users FOREIGN KEY(creator_username) REFERENCES users (username) ON DELETE SET NULL,
	CONSTRAINT fk_document_metadata_last_modified_by_username_users FOREIGN KEY(last_modified_by_username) REFERENCES users (username) ON DELETE SET NULL
);

CREATE TABLE document_metadata_tags (
	document_id VARCHAR(255) NOT NULL,
	tag VARCHAR(255) NOT NULL,
	position INTEGER NOT NULL,
	CONSTRAINT pk_document_metadata_tags PRIMARY KEY (document_id, tag),
	CONSTRAINT fk_document_metadata_tags_document_id_document_metadata FOREIGN KEY(document_id) REFERENCES document_metadata (document_id) ON DELETE CASCADE
);

CREATE TABLE document_revisions (
	id VARCHAR(64) NOT NULL,
	document_id VARCHAR(255) NOT NULL,
	file_id VARCHAR(255) NOT NULL,
	created_time DOUBLE NOT NULL,
	parent_revision_id VARCHAR(64),
	status INTEGER NOT NULL,
	CONSTRAINT pk_document_revisions PRIMARY KEY (id),
	CONSTRAINT fk_document_revisions_document_id_documents FOREIGN KEY(document_id) REFERENCES documents (id),
	CONSTRAINT fk_document_revisions_file_id_files FOREIGN KEY(file_id) REFERENCES files (id),
	CONSTRAINT fk_document_revisions_parent_revision_id_document_revisions FOREIGN KEY(parent_revision_id) REFERENCES document_revisions (id) ON DELETE SET NULL
);

CREATE TABLE documents (
	id VARCHAR(255) NOT NULL,
	created_time DOUBLE NOT NULL,
	current_revision_id VARCHAR(64),
	CONSTRAINT pk_documents PRIMARY KEY (id),
	CONSTRAINT fk_documents_id_nodes FOREIGN KEY(id) REFERENCES nodes (id) ON DELETE CASCADE,
	CONSTRAINT fk_documents_current_revision_id_document_revisions FOREIGN KEY(current_revision_id) REFERENCES document_revisions (id) ON DELETE SET NULL
);

CREATE TABLE file_deduplication_tasks (
	file_id VARCHAR(255) NOT NULL,
	phase INTEGER NOT NULL,
	available_at DOUBLE NOT NULL,
	lease_owner VARCHAR(64),
	lease_expires_at DOUBLE,
	attempts INTEGER NOT NULL,
	last_error TEXT,
	created_time DOUBLE NOT NULL,
	CONSTRAINT pk_file_deduplication_tasks PRIMARY KEY (file_id),
	CONSTRAINT ck_file_deduplication_tasks_phase_value CHECK (phase IN (0, 1)),
	CONSTRAINT fk_file_deduplication_tasks_file_id_files FOREIGN KEY(file_id) REFERENCES files (id) ON DELETE CASCADE
);

CREATE TABLE file_tasks (
	id VARCHAR(255) NOT NULL,
	file_id VARCHAR(255) NOT NULL,
	status INTEGER NOT NULL,
	mode INTEGER NOT NULL,
	start_time DOUBLE NOT NULL,
	end_time DOUBLE,
	issued_by_username VARCHAR(256),
	encryption_key VARCHAR(256),
	chunk_size INTEGER,
	upload_file_size BIGINT,
	upload_sha256 VARCHAR(64),
	upload_session_id TEXT,
	upload_checkpoint_size BIGINT,
	upload_checkpoint_data TEXT,
	CONSTRAINT pk_file_tasks PRIMARY KEY (id),
	CONSTRAINT ck_file_tasks_status_value CHECK (status IN (0, 1, 2, 3, 4)),
	CONSTRAINT fk_file_tasks_file_id_files FOREIGN KEY(file_id) REFERENCES files (id) ON DELETE CASCADE,
	CONSTRAINT fk_file_tasks_issued_by_username_users FOREIGN KEY(issued_by_username) REFERENCES users (username) ON DELETE SET NULL
);

CREATE TABLE files (
	id VARCHAR(255) NOT NULL,
	sha256 VARCHAR(64),
	path TEXT NOT NULL,
	size BIGINT,
	created_time DOUBLE NOT NULL,
	active BOOLEAN NOT NULL,
	CONSTRAINT pk_files PRIMARY KEY (id)
);

CREATE TABLE folders (
	id VARCHAR(255) NOT NULL,
	created_time DOUBLE NOT NULL,
	CONSTRAINT pk_folders PRIMARY KEY (id),
	CONSTRAINT fk_folders_id_nodes FOREIGN KEY(id) REFERENCES nodes (id) ON DELETE CASCADE
);

CREATE TABLE group_permissions (
	id INTEGER NOT NULL,
	group_name VARCHAR(255) NOT NULL,
	permission VARCHAR(255) NOT NULL,
	granted BOOLEAN NOT NULL,
	start_time DOUBLE NOT NULL,
	end_time DOUBLE,
	CONSTRAINT pk_group_permissions PRIMARY KEY (id),
	CONSTRAINT fk_group_permissions_group_name_user_groups FOREIGN KEY(group_name) REFERENCES user_groups (group_name) ON DELETE CASCADE
);

CREATE TABLE keyrings (
	id VARCHAR(64) NOT NULL,
	username VARCHAR(256) NOT NULL,
	content TEXT NOT NULL,
	label VARCHAR(255),
	created_time DOUBLE NOT NULL,
	CONSTRAINT pk_keyrings PRIMARY KEY (id),
	CONSTRAINT fk_keyrings_username_users FOREIGN KEY(username) REFERENCES users (username) ON DELETE CASCADE
);

CREATE TABLE login_throttles (
	username VARCHAR(255) NOT NULL,
	ip_address VARCHAR(45) NOT NULL,
	failed_attempts INTEGER NOT NULL,
	window_started_at DOUBLE NOT NULL,
	last_attempt DOUBLE NOT NULL,
	locked_until DOUBLE,
	CONSTRAINT pk_login_throttles PRIMARY KEY (username, ip_address)
);

CREATE TABLE nodes (
	id VARCHAR(255) NOT NULL,
	type VARCHAR(16) NOT NULL,
	name VARCHAR(255) NOT NULL,
	parent_id VARCHAR(255),
	active_name VARCHAR(255) GENERATED ALWAYS AS (CASE WHEN status = 1 THEN NULL ELSE name END) STORED,
	inherit BOOLEAN NOT NULL,
	status INTEGER NOT NULL,
	status_operation_id VARCHAR(255),
	access_rule_set_id VARCHAR(32),
	CONSTRAINT pk_nodes PRIMARY KEY (id),
	CONSTRAINT ck_nodes_root_parent CHECK (id = '/' AND parent_id IS NULL AND type = 'directory' OR id != '/' AND parent_id IS NOT NULL),
	CONSTRAINT uq_nodes_active_parent_name UNIQUE (parent_id, active_name),
	CONSTRAINT fk_nodes_parent_id_folders FOREIGN KEY(parent_id) REFERENCES folders (id) ON DELETE CASCADE,
	CONSTRAINT fk_nodes_access_rule_set_id_compiled_access_rule_sets FOREIGN KEY(access_rule_set_id) REFERENCES compiled_access_rule_sets (id)
);

CREATE TABLE object_access_entries (
	id INTEGER NOT NULL,
	entity_type VARCHAR(16) NOT NULL,
	entity_identifier VARCHAR(255) NOT NULL,
	target_type VARCHAR(16) NOT NULL,
	target_identifier VARCHAR(255) NOT NULL,
	access_type VARCHAR(16) NOT NULL,
	start_time DOUBLE NOT NULL,
	end_time DOUBLE,
	CONSTRAINT pk_object_access_entries PRIMARY KEY (id)
);

CREATE TABLE rate_limit_buckets (
	namespace VARCHAR(64) NOT NULL,
	scope VARCHAR(16) NOT NULL,
	identity VARCHAR(256) NOT NULL,
	tokens DOUBLE NOT NULL,
	last_refill_at DOUBLE NOT NULL,
	denial_count INTEGER NOT NULL,
	last_denied_at DOUBLE,
	last_attempt DOUBLE NOT NULL,
	CONSTRAINT pk_rate_limit_buckets PRIMARY KEY (namespace, scope, identity)
);

CREATE TABLE risk_ip_accounts (
	namespace VARCHAR(64) NOT NULL,
	ip_address VARCHAR(45) NOT NULL,
	username VARCHAR(256) NOT NULL,
	last_attempt DOUBLE NOT NULL,
	CONSTRAINT pk_risk_ip_accounts PRIMARY KEY (namespace, ip_address, username)
);

CREATE TABLE schedule_executions (
	id VARCHAR(64) NOT NULL,
	schedule_id VARCHAR(32) NOT NULL,
	task_name VARCHAR(255) NOT NULL,
	task_contract_version INTEGER NOT NULL,
	payload JSON NOT NULL,
	provider_generation BIGINT NOT NULL,
	scheduled_for DOUBLE NOT NULL,
	state VARCHAR(16) NOT NULL,
	dispatch_state VARCHAR(16) NOT NULL,
	attempt INTEGER NOT NULL,
	retry_at DOUBLE,
	dispatched_at DOUBLE,
	lease_owner VARCHAR(64),
	lease_expires_at DOUBLE,
	started_at DOUBLE,
	completed_at DOUBLE,
	result JSON,
	error VARCHAR(1024),
	created_at DOUBLE NOT NULL,
	CONSTRAINT pk_schedule_executions PRIMARY KEY (id),
	CONSTRAINT uq_schedule_executions_occurrence UNIQUE (schedule_id, scheduled_for),
	CONSTRAINT ck_schedule_executions_attempt CHECK (attempt >= 0),
	CONSTRAINT ck_schedule_executions_state CHECK (state IN ('pending', 'running', 'retry_wait', 'succeeded', 'failed', 'cancelled')),
	CONSTRAINT ck_schedule_executions_dispatch_state CHECK (dispatch_state IN ('pending', 'sent')),
	CONSTRAINT fk_schedule_executions_schedule_id_schedules FOREIGN KEY(schedule_id) REFERENCES schedules (id) ON DELETE CASCADE
);

CREATE TABLE schedules (
	id VARCHAR(32) NOT NULL,
	task_name VARCHAR(255) NOT NULL,
	task_contract_version INTEGER NOT NULL,
	payload JSON NOT NULL,
	trigger_type VARCHAR(16) NOT NULL,
	trigger_data JSON NOT NULL,
	timezone VARCHAR(255) NOT NULL,
	system_managed BOOLEAN DEFAULT 0 NOT NULL,
	enabled BOOLEAN NOT NULL,
	status VARCHAR(16) NOT NULL,
	revision BIGINT NOT NULL,
	next_run_at DOUBLE,
	active_execution_id VARCHAR(64),
	pending_scheduled_for DOUBLE,
	created_by VARCHAR(256),
	created_at DOUBLE NOT NULL,
	updated_by VARCHAR(256),
	updated_at DOUBLE NOT NULL,
	deleted_at DOUBLE,
	CONSTRAINT pk_schedules PRIMARY KEY (id),
	CONSTRAINT ck_schedules_revision_positive CHECK (revision > 0),
	CONSTRAINT ck_schedules_task_contract_version_positive CHECK (task_contract_version > 0),
	CONSTRAINT ck_schedules_trigger_type CHECK (trigger_type IN ('cron', 'date', 'interval')),
	CONSTRAINT ck_schedules_status CHECK (status IN ('active', 'completed', 'failed', 'deleted')),
	CONSTRAINT fk_schedules_created_by_users FOREIGN KEY(created_by) REFERENCES users (username) ON DELETE SET NULL,
	CONSTRAINT fk_schedules_updated_by_users FOREIGN KEY(updated_by) REFERENCES users (username) ON DELETE SET NULL
);

CREATE TABLE scheduling_runtime_state (
	id INTEGER NOT NULL,
	provider VARCHAR(16) NOT NULL,
	redis_namespace VARCHAR(63),
	generation BIGINT NOT NULL,
	schema_version INTEGER NOT NULL,
	updated_at DOUBLE NOT NULL,
	CONSTRAINT pk_scheduling_runtime_state PRIMARY KEY (id),
	CONSTRAINT ck_scheduling_runtime_state_singleton CHECK (id = 1),
	CONSTRAINT ck_scheduling_generation_positive CHECK (generation > 0),
	CONSTRAINT ck_scheduling_runtime_provider CHECK (provider IN ('local', 'redis'))
);

CREATE TABLE system_states (
	owner VARCHAR(255) NOT NULL,
	state_key VARCHAR(128) NOT NULL,
	schema_version INTEGER NOT NULL,
	revision BIGINT NOT NULL,
	payload JSON NOT NULL,
	updated_at DOUBLE NOT NULL,
	CONSTRAINT pk_system_states PRIMARY KEY (owner, state_key),
	CONSTRAINT ck_system_states_schema_version_positive CHECK (schema_version > 0),
	CONSTRAINT ck_system_states_revision_positive CHECK (revision > 0)
);

CREATE TABLE traffic_throttles (
	ip_address VARCHAR(45) NOT NULL,
	failed_attempts INTEGER NOT NULL,
	window_started_at DOUBLE NOT NULL,
	last_attempt DOUBLE NOT NULL,
	locked_until DOUBLE,
	CONSTRAINT pk_traffic_throttles PRIMARY KEY (ip_address)
);

CREATE TABLE user_groups (
	group_name VARCHAR(255) NOT NULL,
	group_display_name VARCHAR(128),
	CONSTRAINT pk_user_groups PRIMARY KEY (group_name)
);

CREATE TABLE user_memberships (
	id INTEGER NOT NULL,
	username VARCHAR(256) NOT NULL,
	group_name VARCHAR(255) NOT NULL,
	start_time DOUBLE NOT NULL,
	end_time DOUBLE,
	CONSTRAINT pk_user_memberships PRIMARY KEY (id),
	CONSTRAINT fk_user_memberships_username_users FOREIGN KEY(username) REFERENCES users (username) ON DELETE CASCADE,
	CONSTRAINT fk_user_memberships_group_name_user_groups FOREIGN KEY(group_name) REFERENCES user_groups (group_name) ON DELETE CASCADE
);

CREATE TABLE user_permissions (
	id INTEGER NOT NULL,
	username VARCHAR(256) NOT NULL,
	permission VARCHAR(255) NOT NULL,
	granted BOOLEAN NOT NULL,
	start_time DOUBLE NOT NULL,
	end_time DOUBLE,
	CONSTRAINT pk_user_permissions PRIMARY KEY (id),
	CONSTRAINT fk_user_permissions_username_users FOREIGN KEY(username) REFERENCES users (username) ON DELETE CASCADE
);

CREATE TABLE userblock_entries (
	block_id VARCHAR(32) NOT NULL,
	username VARCHAR(256) NOT NULL,
	timestamp DOUBLE NOT NULL,
	not_before DOUBLE NOT NULL,
	not_after DOUBLE NOT NULL,
	target_type VARCHAR(32) NOT NULL,
	target_id VARCHAR(255),
	reason_comment_id INTEGER,
	CONSTRAINT pk_userblock_entries PRIMARY KEY (block_id),
	CONSTRAINT fk_userblock_entries_username_users FOREIGN KEY(username) REFERENCES users (username) ON DELETE CASCADE,
	CONSTRAINT fk_userblock_entries_reason_comment_id_comments FOREIGN KEY(reason_comment_id) REFERENCES comments (comment_id) ON DELETE SET NULL
);

CREATE TABLE userblock_sub_entries (
	id INTEGER NOT NULL,
	parent_id VARCHAR(32) NOT NULL,
	block_type VARCHAR(64) NOT NULL,
	CONSTRAINT pk_userblock_sub_entries PRIMARY KEY (id),
	CONSTRAINT fk_userblock_sub_entries_parent_id_userblock_entries FOREIGN KEY(parent_id) REFERENCES userblock_entries (block_id) ON DELETE CASCADE
);

CREATE TABLE users (
	username VARCHAR(256) NOT NULL,
	pass_hash TEXT NOT NULL,
	passwd_last_modified DOUBLE NOT NULL,
	nickname VARCHAR(255),
	avatar_id VARCHAR(255),
	last_login DOUBLE,
	created_time DOUBLE NOT NULL,
	status INTEGER NOT NULL,
	status_comment_id INTEGER,
	secret_key VARCHAR(64),
	totp_secret VARCHAR(32),
	totp_enabled BOOLEAN NOT NULL,
	totp_backup_codes TEXT,
	preference_dek_id VARCHAR(64),
	CONSTRAINT pk_users PRIMARY KEY (username),
	CONSTRAINT fk_users_avatar_id_files FOREIGN KEY(avatar_id) REFERENCES files (id),
	CONSTRAINT fk_users_status_comment_id_comments FOREIGN KEY(status_comment_id) REFERENCES comments (comment_id) ON DELETE SET NULL,
	CONSTRAINT uq_users_preference_dek_id UNIQUE (preference_dek_id),
	CONSTRAINT fk_users_preference_dek_id FOREIGN KEY(preference_dek_id) REFERENCES keyrings (id) ON DELETE SET NULL
);

CREATE INDEX ix_account_throttles_last_attempt ON account_throttles (last_attempt);

CREATE INDEX ix_audit_entries_logged_time ON audit_entries (logged_time);

CREATE INDEX ix_compiled_access_rule_groups_rule_id ON compiled_access_rule_groups (rule_id);

CREATE INDEX ix_compiled_access_rule_memberships_group_id ON compiled_access_rule_memberships (group_id);

CREATE INDEX ix_compiled_access_rule_memberships_group_name ON compiled_access_rule_memberships (group_name);

CREATE INDEX ix_compiled_access_rule_rights_group_id ON compiled_access_rule_rights (group_id);

CREATE INDEX ix_compiled_access_rule_rights_permission ON compiled_access_rule_rights (permission);

CREATE INDEX ix_compiled_access_rule_sets_node_id ON compiled_access_rule_sets (node_id);

CREATE INDEX ix_compiled_access_rules_access_type ON compiled_access_rules (access_type);

CREATE INDEX ix_compiled_access_rules_rule_set_id ON compiled_access_rules (rule_set_id);

CREATE INDEX ix_document_metadata_creator_username ON document_metadata (creator_username);

CREATE INDEX ix_document_metadata_last_modified_by_username ON document_metadata (last_modified_by_username);

CREATE INDEX ix_document_metadata_tags_tag ON document_metadata_tags (tag);

CREATE INDEX ix_document_revisions_document_created_id ON document_revisions (document_id, created_time, id);

CREATE INDEX ix_document_revisions_file_id ON document_revisions (file_id);

CREATE INDEX ix_document_revisions_parent_revision_id ON document_revisions (parent_revision_id);

CREATE INDEX ix_documents_current_revision_id ON documents (current_revision_id);

CREATE INDEX ix_file_deduplication_tasks_available_lease ON file_deduplication_tasks (available_at, lease_expires_at);

CREATE INDEX ix_file_tasks_file_id_mode_status ON file_tasks (file_id, mode, status);

CREATE INDEX ix_file_tasks_mode_status_end_time ON file_tasks (mode, status, end_time);

CREATE INDEX ix_files_sha256_active_created_time_id ON files (sha256, active, created_time, id);

CREATE INDEX ix_group_permissions_end_time_id ON group_permissions (end_time, id);

CREATE INDEX ix_keyrings_username ON keyrings (username);

CREATE INDEX ix_login_throttles_ip_address ON login_throttles (ip_address);

CREATE INDEX ix_login_throttles_last_attempt ON login_throttles (last_attempt);

CREATE INDEX ix_nodes_access_rule_set_id ON nodes (access_rule_set_id);

CREATE INDEX ix_nodes_name ON nodes (name);

CREATE INDEX ix_nodes_parent_status_lower_name_id ON nodes (parent_id, status, lower(name), id);

CREATE INDEX ix_nodes_status_lower_name_id ON nodes (status, lower(name), id);

CREATE INDEX ix_nodes_status_operation_id ON nodes (status_operation_id);

CREATE INDEX ix_nodes_type ON nodes (type);

CREATE INDEX ix_object_access_entries_entity_identifier ON object_access_entries (entity_identifier);

CREATE INDEX ix_object_access_entries_target_identifier ON object_access_entries (target_identifier);

CREATE INDEX ix_rate_limit_buckets_last_attempt ON rate_limit_buckets (last_attempt);

CREATE INDEX ix_risk_ip_accounts_last_attempt ON risk_ip_accounts (last_attempt);

CREATE INDEX ix_schedule_executions_claim ON schedule_executions (state, dispatch_state, retry_at, lease_expires_at);

CREATE INDEX ix_schedule_executions_schedule_id ON schedule_executions (schedule_id);

CREATE INDEX ix_schedules_due ON schedules (enabled, status, next_run_at);

CREATE INDEX ix_traffic_throttles_last_attempt ON traffic_throttles (last_attempt);

CREATE INDEX ix_user_permissions_end_time_id ON user_permissions (end_time, id);

CREATE INDEX ix_users_avatar_id ON users (avatar_id);
