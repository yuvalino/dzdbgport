# Changelog

## [0.3.0] - 2025-09-15
### Added
- Support for multiple DayZ instances (including server).
- Added "Select Target Port" command to change preferred connected port for code exec.
- First connected port is selected automatically.
- Recompile will recompile for all connected instances.
- Code execution can now be executed on all script modules (not only "World").

### Fixed
- Game disconnection wasn't handled properly, causing "zombie" connected ports.
- Non-critical notifications will now disappear after a few seconds.

## [0.2.2] - 2025-05-12
### Fixed
- Support for multiple VSCode windows: All windows will use the same debug port instance.

### Fixed
- Prevent duplicate WebSocket connections during restart
- WebView errors when plugin is toggled off

## [0.1.0] - 2025-05-06
- Initial release with code execution, recompile, and sidebar tools.