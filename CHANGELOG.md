# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2025-01-30

### Added
- Hybrid PII detection combining rule-based and LLM-based approaches
- `--detection-mode` option to choose between `rules`, `llm`, or `hybrid` detection
- Ollama integration for local LLM-based PII detection
- Benchmark scripts for evaluating detection accuracy

### Fixed
- Ollama model detection for newer ollama library versions

## [0.2.0] - 2025-01-29

### Added
- PII processing profile management (save/load detection settings)
- VS Code as AI tool option in TUI
- Folder addition to existing workspace in TUI
- Auto-generation of CLAUDE.md and SYSTEM_PROMPT.md for AI tools

### Fixed
- Lazy import for ollama to avoid ModuleNotFoundError
- Consistent anonymization IDs for same values across files

## [0.1.0] - 2025-01-28

### Added
- Initial release
- Rule-based PII detection with regex patterns
- Support for CSV, Excel, Word, and PowerPoint files
- CLI interface with `dataairlock` command
- TUI (Text User Interface) with `dataairlock-tui` command
- Semantic ID generation (e.g., PATIENT_001, EMAIL_002)
- One-command restore functionality
- Folder-based batch processing
- Session-based mapping management
- Encrypted mapping storage
- Support for multiple AI tools (Claude Code, Codex CLI, Aider)
- Streamlit web interface (optional)

[0.3.0]: https://github.com/akira0907/dataairlock/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/akira0907/dataairlock/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/akira0907/dataairlock/releases/tag/v0.1.0
