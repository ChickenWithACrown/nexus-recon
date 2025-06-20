# Changelog

All notable changes to the Nexus Recon project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Added
- Initial public release
- Core network scanning functionality
- GUI interface for easy interaction
- Multiple scan types (Port, WHOIS, DNS, etc.)
- Security testing capabilities

## [2.2.0] - 2025-06-19
### Added
- SQL Injection scanning module
- XSS testing capabilities
- Enhanced error handling and logging
- Improved GUI with dark theme
- Comprehensive documentation

### Changed
- Refactored core scanning engine
- Improved performance for large-scale scans
- Updated dependencies to latest secure versions

### Fixed
- Fixed UI initialization issues
- Resolved thread-safety problems
- Addressed various minor bugs

## [2.1.0] - 2025-05-15
### Added
- Subdomain enumeration feature
- IP geolocation capabilities
- Export functionality for scan results
- Progress tracking for long-running scans

### Changed
- Optimized network scanning algorithms
- Improved error reporting
- Enhanced documentation

## [2.0.0] - 2025-04-01
### Added
- Complete GUI rewrite with modern interface
- Support for multiple scan profiles
- Configurable scan parameters
- Comprehensive logging system

### Changed
- New project structure
- Improved code organization
- Better error handling

## [1.0.0] - 2025-01-15
### Added
- Initial release of Nexus Recon
- Basic port scanning functionality
- Command-line interface
- Core network utilities

---

## Versioning Policy

- **MAJOR** version for incompatible API changes
- **MINOR** version for added functionality in a backward-compatible manner
- **PATCH** version for backward-compatible bug fixes

## Deprecation Policy

Features marked as deprecated will be supported for at least one major version before removal.

## Security Fixes

Security-related fixes will be backported to the last two major versions.
