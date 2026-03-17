# Changelog: AEngine Security (SEC)

All notable changes to the AEngine Security modules will be documented in this file.

## [3.6.0] - 2026-03-17

### Added
- **Privilege Escalation**: `_run_as_admin()` — выполняет команды через `sudo` (Linux) / `powershell Start-Process -Verb RunAs` (Windows) при отсутствии прав администратора
- **Full File Protection**: `lock_file()` теперь использует `takeown /a` + ACL deny `Everyone:(D,DC)` (Windows) / `chown root` + `chattr +i` (Linux) для полного запрета удаления
- **Full Permission Restore**: `unlock_file()` полностью восстанавливает права: возвращает владельца текущему пользователю, снимает все deny-записи, восстанавливает наследование (Windows) / снимает immutable bit (Linux)

### Fixed
- **Base Path**: `init.py` — ненадёжный `os.sep.join(__file__.split(...))` заменён на `os.path.dirname(os.path.abspath(__file__))`
- **Input Conflict**: `auth.py` — `input()` заменён на `Prompt.ask()` для совместимости с кастомным `input()` из APM `helpers.py`

### Improved
- **sign.py** / **unsign.py**: предупреждение + автозапрос UAC/sudo если нет прав администратора ОС
- Улучшены сообщения о статусе защиты при sign/unsign

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
