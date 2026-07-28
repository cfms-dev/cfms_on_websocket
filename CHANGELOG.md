# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

<!-- insertion marker -->
## Unreleased

<small>[Compare with latest](https://github.com/cfms-dev/cfms_on_websocket/compare/v0.2.0...HEAD)</small>

<!-- insertion marker -->

### Added

- Add adaptive document-creation risk control using persistent account and IP
  token buckets, explainable risk levels, observe/enforce modes, and a
  `bypass_document_creation_rate_limit` permission granted to `sysop` by
  default.
- Add two-stage upload leases, abandoned-upload cleanup, and configurable
  per-creator reservation and document-creation limits.
- Add explicit pending, in-progress, completed, cancelled, and expired file-task
  lifecycle states.
- Add versioned extension manifests and identifier-based extension activation.
- Add non-persistent lockdown reasons to lockdown responses, events, and server information.
- Expose account status in user information responses.

### Changed

- Replace fixed-window document-creation limits with risk-weighted continuous
  refill while preserving the protocol 18 `429` response shape and legacy
  configuration compatibility.
- Increase the protocol version to 18. Cancelled or expired transfer requests
  now return `410` with `data.task_status`; concurrent upload claims return
  `409`; document creation limits return `429` with limit details.
- Repeated `upload_document` calls reuse the pending initial upload instead of
  creating another revision or extending its lease.

### Fixed

- Cancel pending and active file transfers when the last live reference is
  removed by document, revision, directory, or lockdown operations, while
  preserving transfers for files still referenced elsewhere.
- Prevent OIDC clients from overriding the configured redirect URI.
- Enforce one shared active-name namespace for documents and directories at the
  database layer, eliminating concurrent create, rename, move, and restore races.
  Soft-deleted nodes release their names; upgrades stop and report historical
  conflicts before changing the schema.
- Treat the legacy `document.allow_name_duplicate` setting as obsolete and
  ignored. Active sibling names are now always unique.

## [v0.2.0](https://github.com/cfms-dev/cfms_on_websocket/releases/tag/v0.2.0) - 2026-05-17

<small>[Compare with first commit](https://github.com/cfms-dev/cfms_on_websocket/compare/3ed4a3a48f9d6ff0444f1c0b560146eb5a6e98e6...v0.2.0)</small>

### Chore

- generate upgrade scripts for new database structures ([11d6cf4](https://github.com/cfms-dev/cfms_on_websocket/commit/11d6cf401fb4c5a5ca756e59ddfb7942db022200) by Creeper19472).
- rename `handler.py` and `request.py` ([480a7c8](https://github.com/cfms-dev/cfms_on_websocket/commit/480a7c8534d3ea80ccff13adf7486f05d6e6561f) by Creeper19472).
- Update CORE_VERSION to 0.2.0.260401_alpha ([6598d45](https://github.com/cfms-dev/cfms_on_websocket/commit/6598d4537b9540c3bb9c2a3f2089ed9d07f7f658) by Creeper19472).
- update action versions in GitHub workflow for improved stability ([abd729c](https://github.com/cfms-dev/cfms_on_websocket/commit/abd729c0e04a48720c73ad717181cfc085e25119) by Creeper19472).
- bump protocol and core version ([1902378](https://github.com/cfms-dev/cfms_on_websocket/commit/190237809b033e1d9e90493e5162ac0f110afd78) by Creeper19472).
- update tests/__init__.py and README.md ([7b86bf5](https://github.com/cfms-dev/cfms_on_websocket/commit/7b86bf5e4e8b6b93edf2d39886438b9acbbcafea) by Creeper19472).
- update README.md ([d4f8dd6](https://github.com/cfms-dev/cfms_on_websocket/commit/d4f8dd67f4aedba73e6a6f9565998291255b8ac7) by Creeper19472).

### Docs

- hints for database migrations ([2aacf36](https://github.com/cfms-dev/cfms_on_websocket/commit/2aacf3612a51bcc5340f669b7839067286d19593) by Creeper19472).
- correct capitalization in project title and add run instructions ([e195912](https://github.com/cfms-dev/cfms_on_websocket/commit/e195912b10950d966ecfee9dc19fe6afef7c40d8) by Creeper19472).
- Update README for quick setup instructions and rename config sample file ([7e3d564](https://github.com/cfms-dev/cfms_on_websocket/commit/7e3d5640bc8d4ca6474f16a37054080b54a34e56) by Creeper19472).

### Features

- Add support for file download resumption and encryption key handling (#57) ([028ce45](https://github.com/cfms-dev/cfms_on_websocket/commit/028ce452d541cd0b820e095103b97cf048028a99) by Creeper19472). * fix: add offset alignment check in ConnectionHandler
- Reserve a description field for future new transmission methods ([52ef12e](https://github.com/cfms-dev/cfms_on_websocket/commit/52ef12ecea9c5aef025e33f6da54407404b53139) by Creeper19472).
- treat sub-directories as extensions (#55) ([83ac32f](https://github.com/cfms-dev/cfms_on_websocket/commit/83ac32f46a065f6b62ec8501a49a7cb8ac82845b) by Creeper19472). Co-authored-by: Copilot <copilot@github.com>
- Enhance concurrency control with indexing and with_for_update() (#53) ([ee36fc1](https://github.com/cfms-dev/cfms_on_websocket/commit/ee36fc136c5b0f2a92e985e8b31a4a52b34087ea) by Creeper19472). * feat: remove unnecessary upgrade logic
- Implement centralized file reference counting in database (#51) ([5abab2c](https://github.com/cfms-dev/cfms_on_websocket/commit/5abab2c45e1725564b24164280cffa677b8ba926) by Creeper19472). * feat: Update type hints for improved clarity in test file reference counting
- Enhance RequestDisable2FAHandler for username-based 2FA disabling (#50) ([aa9eb0d](https://github.com/cfms-dev/cfms_on_websocket/commit/aa9eb0d0a77e2e4917b305874263b1c3eddf3212) by Creeper19472). * fix: improve password validation logic in RequestDisable2FAHandler
- add pre-commit configuration and dependencies for code standardization ([ae45d9a](https://github.com/cfms-dev/cfms_on_websocket/commit/ae45d9ae30e6470df273ca25ca47f1692b047429) by Creeper19472).
- Implement file deduplication on upload and enhance hook signature (#48) ([4d23d7b](https://github.com/cfms-dev/cfms_on_websocket/commit/4d23d7b4919aad011c54acc00cc558338ece4384) by Creeper19472). * feat: Add filter for active files in file upload deduplication logic
- Refactor logging to use Loguru and clean up utilities (#47) ([c702fdd](https://github.com/cfms-dev/cfms_on_websocket/commit/c702fdd98cca574a1e819cb995c852f9a145abf7) by Creeper19472). * refactor: update logger binding name and enhance log format for clarity
- Implement and enhance plugin management system with hooks (#45) ([e0c3e4f](https://github.com/cfms-dev/cfms_on_websocket/commit/e0c3e4fd58ab554ca8828bca677928295e1adb96) by Creeper19472). Co-authored-by: Copilot <175728472+Copilot@users.noreply.github.com>
- Integrate UserStatus enumeration and manage user status permissions (#43) ([2da45f6](https://github.com/cfms-dev/cfms_on_websocket/commit/2da45f6a8ef99ce40be72b7ff34dd12a41f76d13) by Creeper19472). Co-authored-by: copilot-swe-agent[bot] <198982749+Copilot@users.noreply.github.com>
- Enhance centralized error reporting and handling with log IDs (#41) ([0102972](https://github.com/cfms-dev/cfms_on_websocket/commit/01029729ff2b27a77f50b3eee0f993b235f89947) by Creeper19472). * fix: Add early return in error handling for file send and receive operations
- Enhance authentication error handling and document access rules (#40) ([4c9e5cd](https://github.com/cfms-dev/cfms_on_websocket/commit/4c9e5cda4e467bff29ae50f00b1c2d8b9424b2ff) by Creeper19472). * fix: add exception handling in receive loop for WebSocket connection
- Add mutual TLS support and update security configurations (#38) ([8b1e2bb](https://github.com/cfms-dev/cfms_on_websocket/commit/8b1e2bbde71c6a46ad9834f687b8f77554b93a19) by Creeper19472). * fix(security): enhance client certificate CA path validation
- limit username length to 64 characters in database schema ([49234ee](https://github.com/cfms-dev/cfms_on_websocket/commit/49234ee210c3006ef2b437b716eb973a0b76035c) by Creeper19472).
- implement LoginGuard to mitigate brute-force attacks … (#35) ([d1ea811](https://github.com/cfms-dev/cfms_on_websocket/commit/d1ea81129b4a700909555815a4518d66c853f16f) by Creeper19472). Co-authored-by: Copilot Autofix powered by AI <175728472+Copilot@users.noreply.github.com>, Co-authored-by: Copilot <198982749+Copilot@users.noreply.github.com>
- add handler to list deleted items in a directory (#32) ([0075662](https://github.com/cfms-dev/cfms_on_websocket/commit/00756624e4fd5bed34e3627052402ef4aea62468) by Creeper19472). * fix(directory): add permission check
- Add restore permissions and handlers for documents and directories (#31) ([7cfff7d](https://github.com/cfms-dev/cfms_on_websocket/commit/7cfff7d349155b731da406a35835ad493d3e8082) by Creeper19472). * fix(security): update restore request handlers to allow null target IDs and improve access checks
- mark deletion (#30) ([3178a4e](https://github.com/cfms-dev/cfms_on_websocket/commit/3178a4e1e384c8b35a62b58b86c4eed5dd92ad43) by Creeper19472). * feat: update permissions to use StrEnum and enhance permission handling
- update CORE_VERSION to 0.1.0.260309_alpha ([d8a4234](https://github.com/cfms-dev/cfms_on_websocket/commit/d8a423485a282ad0be68f21cd2af023a816ebd2c) by Creeper19472).
- optimize search (#21) ([84ef7ca](https://github.com/cfms-dev/cfms_on_websocket/commit/84ef7caf1c42c70b3ffce0d4480cae85fd6cb001) by Copilot). Co-authored-by: copilot-swe-agent[bot] <198982749+Copilot@users.noreply.github.com>, Co-authored-by: Creeper19472 <38857196+Creeper19472@users.noreply.github.com>, Co-authored-by: Creeper19472 <creeper19472@crpteam.club>
- add `not_before` and `not_after` to `UserBlockEntry` ([edb2675](https://github.com/cfms-dev/cfms_on_websocket/commit/edb26753c2f9d866c4be435b700b5a0433246c55) by Creeper19472).
- add `RequestListUserBlocksHandler` ([ceddc6b](https://github.com/cfms-dev/cfms_on_websocket/commit/ceddc6bd7d5fafd27897e96fb4b50cb872ad01e8) by Creeper19472).
- add kdf support (#19) ([094eb79](https://github.com/cfms-dev/cfms_on_websocket/commit/094eb79ccaff3ee745dab148200f49623280b02d) by Creeper19472). Co-authored-by: Copilot <198982749+Copilot@users.noreply.github.com>, Co-authored-by: Copilot <175728472+Copilot@users.noreply.github.com>
- use `secrets.compare_digest()` to compare passwords ([707cd4b](https://github.com/cfms-dev/cfms_on_websocket/commit/707cd4bbfd8e0d6cbf7477e03cbdd669ffcb7f55) by Creeper19472).
- add `inherit` ([74035fd](https://github.com/cfms-dev/cfms_on_websocket/commit/74035fd52c8161593a2bfd7dd132a5d651ea0376) by Creeper19472).
- add revision management feature (#13) ([842fa37](https://github.com/cfms-dev/cfms_on_websocket/commit/842fa37ee7662b55e5bf56027fc36b6cf37e37e8) by Creeper19472). Co-authored-by: Copilot <198982749+Copilot@users.noreply.github.com>
- add access recursive check ([61d0e2b](https://github.com/cfms-dev/cfms_on_websocket/commit/61d0e2be28cdb0a5bf8208a996602a26265164c5) by Creeper19472).
- Add revoke_access API to delete access entries by ID (#12) ([008e808](https://github.com/cfms-dev/cfms_on_websocket/commit/008e808ec368c0ef7fac93f3f8ec6550ea2a4500) by Copilot). Co-authored-by: copilot-swe-agent[bot] <198982749+Copilot@users.noreply.github.com>, Co-authored-by: Creeper19472 <38857196+Creeper19472@users.noreply.github.com>, Co-authored-by: Creeper19472 <creeper19472@crpteam.club>
- Prevent moving directory into its own subdirectory (#10) ([0168363](https://github.com/cfms-dev/cfms_on_websocket/commit/0168363df885789a59ac79d41e6fc1e1623f56d7) by Copilot). Co-authored-by: copilot-swe-agent[bot] <198982749+Copilot@users.noreply.github.com>, Co-authored-by: Creeper19472 <38857196+Creeper19472@users.noreply.github.com>, Co-authored-by: Creeper19472 <creeper19472@crpteam.club>, Co-authored-by: Copilot <175728472+Copilot@users.noreply.github.com>
- Implement search API for documents and directories with permission filtering (#9) ([50ddf6f](https://github.com/cfms-dev/cfms_on_websocket/commit/50ddf6f481bfcd684f0417f9244be7bb0e2eb0cf) by Copilot). Co-authored-by: copilot-swe-agent[bot] <198982749+Copilot@users.noreply.github.com>, Co-authored-by: Creeper19472 <38857196+Creeper19472@users.noreply.github.com>, Co-authored-by: Creeper19472 <creeper19472@crpteam.club>

### Bug Fixes

- handle connection closure during file transmission and reception ([3a6cd77](https://github.com/cfms-dev/cfms_on_websocket/commit/3a6cd77ae8f83d458aade59705b88659704348ec) by Creeper19472).
- update repository URL in README and add optional MySQL dependency in pyproject.toml ([b581e33](https://github.com/cfms-dev/cfms_on_websocket/commit/b581e335f3fe840da53efa5830fa6b5c7706f3b8) by Creeper19472).
- increase VARCHAR length for `User` model to fix MySQL constraints ([a9ea583](https://github.com/cfms-dev/cfms_on_websocket/commit/a9ea583abd2e230c8f0d394de09848effd4ad903) by Creeper19472).
- Update database name in configuration and increment core version; fix database initialization ([32b143d](https://github.com/cfms-dev/cfms_on_websocket/commit/32b143d8a4c7a4d54070e89b7efd83711531d490) by Creeper19472).
- correct configuration key for ruff linting in pyproject.toml ([23b81d7](https://github.com/cfms-dev/cfms_on_websocket/commit/23b81d7ece9ef2c2773216798c525214431bece9) by Creeper19472).
- use Integer type to fix errors ([fe5adbb](https://github.com/cfms-dev/cfms_on_websocket/commit/fe5adbbc135e0785dd37ea10042c9b86672a8140) by Creeper19472).
- enhance client certificate subject extraction logic and improve docstring ([04a59bf](https://github.com/cfms-dev/cfms_on_websocket/commit/04a59bf2f0c2791642dcdcc9048770deb87ad6c1) by Creeper19472).
- update config sample file references in README and conftest.py ([52c71c1](https://github.com/cfms-dev/cfms_on_websocket/commit/52c71c1786a821795b628509502fd7aa228f90f1) by Creeper19472).
- use `IntEnum` to prevent access check issues (#37) ([d0f5ae2](https://github.com/cfms-dev/cfms_on_websocket/commit/d0f5ae2f2fa40bb7334cffc9c1aab78d458f52d5) by Creeper19472). * fix(constants): update CORE_VERSION to 0.1.0.260319_alpha
- return status code for permission denied in deleted items handler ([72b0ae8](https://github.com/cfms-dev/cfms_on_websocket/commit/72b0ae87f518ef2a573b047c27c085e244dcd773) by Creeper19472).
- add permissions for contents and pull-requests in test workflow ([2170978](https://github.com/cfms-dev/cfms_on_websocket/commit/2170978975d719e482322cd69eb5af0c92b71316) by Creeper19472).
- enforce minimum SSL version and warn about outdated OpenSSL ([a848919](https://github.com/cfms-dev/cfms_on_websocket/commit/a848919628fe87d7bb1360cc445d0cf67cde1447) by Creeper19472).
- allow users with 'super_list_directory' permission to access blocked documents and directories ([48ba1c8](https://github.com/cfms-dev/cfms_on_websocket/commit/48ba1c888a8d58660fd955dd3935c8ea40650cef) by Creeper19472).
- disable query access for root directory id ([5952e6e](https://github.com/cfms-dev/cfms_on_websocket/commit/5952e6e0fe45c7e763d25fe0b322bd4121da7222) by Creeper19472).
- unify root directory access control via database-backed sentinel record (#20) ([3b15cbf](https://github.com/cfms-dev/cfms_on_websocket/commit/3b15cbf28f0ec3a34851089853147845184bf200) by Copilot). Co-authored-by: copilot-swe-agent[bot] <198982749+Copilot@users.noreply.github.com>, Co-authored-by: Creeper19472 <38857196+Creeper19472@users.noreply.github.com>, Co-authored-by: Creeper19472 <creeper19472@crpteam.club>
- modify the database structure to resolve the type inconsistency issue ([54426b7](https://github.com/cfms-dev/cfms_on_websocket/commit/54426b7b19f098b531871d3812ff5210edcf98a0) by Creeper19472).
- allow `null` type for `username` and `token` ([02a3390](https://github.com/cfms-dev/cfms_on_websocket/commit/02a33907a54ef15c414fbb8ef8f11a1566493b16) by Creeper19472).
- add `User` avatar refs check ([0acd8d5](https://github.com/cfms-dev/cfms_on_websocket/commit/0acd8d5f311c88d036a961f1698c0cc75b6ffaa1) by Creeper19472).
- fix user avatar handling ([007224f](https://github.com/cfms-dev/cfms_on_websocket/commit/007224f60376cc639695e7b8e57bd81c975bbc8d) by Creeper19472).
- update folder and document queries to use target_folder_id for moving operations ([e1c6109](https://github.com/cfms-dev/cfms_on_websocket/commit/e1c6109756de9fbac86a39434116e27eaab6f7cd) by Creeper19472).
- improve document creation logic and error handling ([c79b844](https://github.com/cfms-dev/cfms_on_websocket/commit/c79b8440a7e5ff25afbfd7c846cb23278ce76380) by Creeper19472).
- update CORE_VERSION and improve document name conflict handling ([f8e400f](https://github.com/cfms-dev/cfms_on_websocket/commit/f8e400f84237c731a260ccc715c0b02fe7f72b9c) by Creeper19472).

### Performance Improvements

- eliminate N+1 queries, spurious commits, and I/O–DB inconsistency in bulk entity deletion (#24) ([9b32636](https://github.com/cfms-dev/cfms_on_websocket/commit/9b326360c0f127d97a81efc50e8a9fb01b85ce6f) by Copilot). Co-authored-by: copilot-swe-agent[bot] <198982749+Copilot@users.noreply.github.com>, Co-authored-by: Creeper19472 <38857196+Creeper19472@users.noreply.github.com>, Co-authored-by: Creeper19472 <creeper19472@crpteam.club>

### Code Refactoring

- Rename security models ([d9b7412](https://github.com/cfms-dev/cfms_on_websocket/commit/d9b7412daab679dbb2a59cafe8f2da4c165da244) by Creeper19472). Co-authored-by: Copilot <copilot@github.com>
- Update server initialization logic to check database type before removal ([9a38455](https://github.com/cfms-dev/cfms_on_websocket/commit/9a38455eb5a13465e77f21317b6be0577cfd3a58) by Creeper19472).
- rename `connection_handler.py` to `router.py` ([0bcca9e](https://github.com/cfms-dev/cfms_on_websocket/commit/0bcca9e9f773681fc9d41b3036f660eede8078c1) by Creeper19472). chore: remove ambiguous TODO comment
- Refactor to use centralized message constants in handlers (#52) ([df17f00](https://github.com/cfms-dev/cfms_on_websocket/commit/df17f002579e4c3c3b5948bc7d3d76e289acae06) by Creeper19472). * refactor: Update import statements for messages module across multiple handlers
- Improve file reference handling in ext_on_file_uploaded function ([ed95a1b](https://github.com/cfms-dev/cfms_on_websocket/commit/ed95a1b212f9e41cee71c5dd2faa3d905d273bda) by Creeper19472).
- update key owner retrieval method in RequestSetPreferenceDEKHandler ([b84719f](https://github.com/cfms-dev/cfms_on_websocket/commit/b84719f8e3399283d5428d23617afd7059a9a80b) by Creeper19472).
- Refactor user retrieval and improve address handling utilities (#49) ([0a8024b](https://github.com/cfms-dev/cfms_on_websocket/commit/0a8024b24017309cb805d1abde6181aa9b7b1541) by Creeper19472). * refactor: enable authentication requirement in RequestDeleteDirectoryHandler
- reorganize imports and enhance code clarity in test_client.py ([b322491](https://github.com/cfms-dev/cfms_on_websocket/commit/b322491c3eb010de60cd16ff1a6ae14075a97711) by Creeper19472).
- Refactor test assertions for clarity and consistency across user, group, keyring, and two-factor authentication tests ([f1d362a](https://github.com/cfms-dev/cfms_on_websocket/commit/f1d362ad3fdb253a928d3be997e0ff4945e7b2a7) by Creeper19472).
- Refactor imports and improve code organization across multiple modules ([939f1ce](https://github.com/cfms-dev/cfms_on_websocket/commit/939f1ce4370692397ead8da35b30c2c319d7aff4) by Creeper19472).
- replace all string permissions with `Permissions` enums ([136d99b](https://github.com/cfms-dev/cfms_on_websocket/commit/136d99b958721b29252e932794a76682c2f97817) by Creeper19472).
