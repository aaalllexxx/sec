# Changelog: AEngine Security (SEC)

All notable changes to the AEngine Security modules will be documented in this file.

## [3.5.0] - 2026-03-12

### Added
- **Hashed Authentication**: Migrated from plaintext `sec_config.py` to secure PBKDF2-SHA256 hashing in `.apm/sec/sec_admin.json`.
- **APM Bridge**: Created `APM/modules/sec.py` to allow global execution of security commands (`sign`, `unsign`, `logs`, etc.).
- **Interactive Security Analytics**: Added "Wow-effect" to HTML reports — clicking on attack chain nodes now scrolls to and highlights relevant log entries.
- **Cyber Kill Chain**: Automated mapping of security events to attack stages (Reconnaissance, Exploitation, Actions on Objectives).
- **Advanced File Protection**: Automatic enforcement of Read-Only, Hidden, and System attributes (R+H+S) for critical security files on Windows.

### Fixed
- **Subcommand Routing**: Fixed an issue where all `apm sec` commands were defaulting to `init`.
- **Permission Errors**: Fixed `PermissionError` when re-signing a project by automatically unlocking the signature file.
- **Indentation & Logic**: Corrected logic in `dashboard.py` to prioritize secure hashed login over legacy plaintext config.
- **Clean Configuration**: `sec_config.py` now only stores the administrator's login name, ensuring no sensitive data is exposed in the codebase.

### Improved
- **Premium UX**: Enhanced `report_template.html` with better navigation, horizontal attack chains, and horizontal scrolling support for large chains.
- **Cross-Platform Compatibility**: Refined `auth.py` and `sign.py` for better attribute handling across different operating systems.
- **Security Defaults**: Updated default signatures and threat scoring to minimize false positives while maintaining high sensitivity.

## [3.0.0] - 2026-03-10
- Initial implementation of the Advanced Security Analytics engine.
- Added Mermaid.js and Chart.js integration for visual reporting.
- Introduced `Code Signing` mechanism for runtime integrity verification.
