# Changelog

All notable changes to this project will be documented in this file.

## v1.1.0 - 2025-11-19

### Added
- New command-line arguments for better control:
  - `--passwords`: To enable password decryption.
  - `--theme`: To specify a color theme for SSH sessions.
  - `--export-dir`: To set a custom output directory.
- Error handling for when the input file is not found.
- Type hints for improved code clarity.

### Changed
- **Refactored the entire script for better readability and maintainability.**
- Replaced manual command-line argument parsing with Python's `argparse` module for a more robust and user-friendly CLI.
- Updated the script to use modern f-strings instead of `.format()`.
- Changed the shebang to explicitly use `python3`.
- Restructured the `Converter` class to separate concerns and improve logic flow.

### Fixed
- Resolved `AttributeError` crashes that occurred on newer versions of Python due to incompatibilities in the `configparser` module.
