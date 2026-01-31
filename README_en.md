<p align="center">
  <img src="assets/logo.png" alt="DataAirlock Logo" width="300">
</p>

<h1 align="center">DataAirlock</h1>

<p align="center">
  <a href="https://pypi.org/project/dataairlock/"><img src="https://img.shields.io/pypi/v/dataairlock" alt="PyPI version"></a>
  <a href="https://pypi.org/project/dataairlock/"><img src="https://img.shields.io/badge/python-3.10%2B-blue" alt="Python"></a>
  <img src="https://img.shields.io/badge/license-AGPL%20v3.0-green" alt="License">
  <img src="https://img.shields.io/badge/security-local--only-brightgreen" alt="Security">
  <img src="https://img.shields.io/badge/status-beta-orange" alt="Status">
</p>

<p align="center"><strong>A local pseudonymization pipeline for safe LLM usage</strong></p>

[Japanese Documentation](./README.md) | [Report Issues](https://github.com/akira0907/dataairlock/issues)

---

## The Problem

**You cannot send sensitive data to LLMs.**

Patient records, customer information, internal documents—once sent to ChatGPT, Claude, or any cloud-based AI, you lose control. GDPR prohibits this. HIPAA prohibits this. Your security team prohibits this.

**DataAirlock solves this by pseudonymizing data locally before LLM use.**

PII is replaced with reversible semantic tokens (e.g., `PERSON_001`). An encrypted mapping is stored locally. After LLM processing, data can be restored to its original form. This is GDPR-aligned pseudonymization—not irreversible anonymization.

---

## Disclaimer

> **This tool does not guarantee 100% detection or pseudonymization of personal information.**
> Users must verify output data themselves.
> The developers are not responsible for any data leaks or damages resulting from use of this tool.

---

## How It Works

```mermaid
flowchart LR
    subgraph Local["Local Environment (Your PC)"]
        A[("Sensitive Data<br/>John Doe, 555-1234")] --> B["DataAirlock<br/>Pseudonymize"]
        B --> C[("Pseudonymized Data<br/>PERSON_001, PHONE_001")]
        F["DataAirlock<br/>Restore"] --> G[("Restored Results<br/>John Doe, 555-1234")]
    end

    subgraph Cloud["Cloud LLM"]
        D["Claude Code<br/>Codex, GPT..."]
    end

    C -.->|"Safe to send"| D
    D -.->|"Analysis results"| E[("Results<br/>PERSON_001 visit count...")]
    E --> F

    style A fill:#ffe0e0,stroke:#cc0000
    style G fill:#e0ffe0,stroke:#00cc00
    style C fill:#fff3cd,stroke:#cc9900
    style E fill:#fff3cd,stroke:#cc9900
    style D fill:#e0e0ff,stroke:#0000cc
```

1. **Input** — Feed your document or dataset containing PII
2. **Pseudonymize** — DataAirlock detects and replaces PII with semantic tokens
3. **Process** — Send pseudonymized data to any LLM safely
4. **Restore** — Rehydrate the LLM output with original values

---

## Why Pseudonymization, Not Anonymization?

| | Anonymization | Pseudonymization |
|---|---------------|------------------|
| **Reversibility** | Irreversible | Reversible with key |
| **Original data** | Lost forever | Can be restored |
| **GDPR definition** | Art. 26 (outside scope) | Art. 4(5) (risk reduction) |
| **Use case** | Public datasets | Processing workflows |

**DataAirlock performs pseudonymization.** Your data can be restored. This is by design—and exactly what you need for LLM workflows where you want results mapped back to real entities.

---

## Features

- **Local Processing** — All pseudonymization and restoration happens locally; raw data never leaves your machine
- **Semantic Tokens** — Meaningful IDs like `PATIENT_001` preserve context for the LLM
- **Encrypted Mapping** — Token-to-original mapping stored with Fernet (AES-128-CBC) encryption
- **One-Command Restore** — Restore analysis results to original data instantly
- **CLI-First** — Works entirely in terminal, integrates with Claude Code and other CLI tools

---

## Quick Start

### Installation

```bash
pip install dataairlock
```

With optional features:

```bash
# LLM detection (Ollama integration)
pip install dataairlock[ollama]

# Web UI (Streamlit)
pip install dataairlock[streamlit]

# All features
pip install dataairlock[all]
```

### Basic Usage

```bash
# 1. Create workspace (pseudonymize files)
dataairlock workspace ./my_project --add data/patients.csv -p mypassword

# 2. Launch Claude Code (work with pseudonymized data)
dataairlock wrap ./my_project --shell
# or
cd ./my_project/.airlock && claude

# 3. Restore results
dataairlock workspace ./my_project --restore-all -p mypassword
```

### Integration with Claude Code

```bash
# Launch interactive shell (work inside .airlock/)
dataairlock wrap ./my_project --shell

# Launch Claude Code directly
dataairlock wrap ./my_project -c "claude"

# Run script with auto-restore
dataairlock wrap ./my_project -c "python analyze.py" --auto-restore -p mypassword
```

---

## Supported PII Types

| PII Type | Pseudonymized Format | Example |
|----------|---------------------|---------|
| Patient ID | PATIENT_001 | P001 → PATIENT_001 |
| Name | PERSON_001 | John Doe → PERSON_001 |
| Phone Number | PHONE_001 | 555-123-4567 → PHONE_001 |
| Email | EMAIL_001 | test@example.com → EMAIL_001 |
| Address | ADDR_001 | 123 Main St... → ADDR_001 |
| Date of Birth | 1990s (generalized) or BIRTHDATE_001 | 1990/01/15 → 1990s |
| Age | 30s (generalized) or AGE_001 | 34 → 30s |

---

## Commands

| Command | Description |
|---------|-------------|
| `workspace --add` | Pseudonymize and add file to workspace |
| `workspace --add-all` | Batch add all files in folder |
| `workspace --status` | Show workspace status |
| `workspace --restore` | Restore result file |
| `workspace --restore-all` | Batch restore all CSVs in output/ |
| `wrap` | Execute command in pseudonymized environment |
| `chat` | Chat with local LLM (Ollama) |
| `scan` | Detect PII only (no pseudonymization) |
| `pseudonymize` | Pseudonymize single file |
| `restore` | Restore single file |
| `scan-doc` | Detect PII in Word/PPT |
| `pseudonymize-doc` | Pseudonymize Word/PPT |
| `restore-doc` | Restore Word/PPT |
| `profile list` | List saved profiles |
| `profile show` | Show profile details |
| `profile delete` | Delete a profile |
| `profile export` | Export profile to JSON |
| `profile import` | Import profile from JSON |
| `profile create-default` | Create default profile |

---

## Pseudonymization Strategies

| Strategy | Description | Use Case |
|----------|-------------|----------|
| `replace` | Replace with semantic token (restorable) | Names, patient IDs, phone numbers |
| `generalize` | Generalize (decade, region, etc.) | Birth date → decade, address → region |
| `delete` | Delete entire column | Unnecessary PII columns |

---

## PII Detection Modes

DataAirlock supports three detection modes:

| Mode | Description | Features |
|------|-------------|----------|
| `rule` | Rule-based (regex) | Fast, works offline, default |
| `llm` | LLM (Ollama) only | High accuracy, detects ambiguous PII |
| `hybrid` | Rule + LLM combined | Best accuracy, recommended |

### CLI Usage

```bash
# Rule-based (default)
dataairlock scan data.csv

# LLM mode
dataairlock scan data.csv -m llm

# Hybrid mode (recommended)
dataairlock scan data.csv -m hybrid

# Also available for pseudonymize command
dataairlock pseudonymize data.csv -m hybrid -p mypassword
```

### TUI Usage

In TUI, when processing folders, you'll be asked "Use LLM to improve PII detection accuracy?"
Select "Yes" to choose a detection mode.

### Ollama Setup

LLM mode requires Ollama:

```bash
# macOS
brew install ollama

# Linux
curl -fsSL https://ollama.ai/install.sh | sh

# Start server
ollama serve

# Download model
ollama pull llama3.1:8b
```

### Benchmark Results

Detection accuracy on built-in test data (11 columns: 5 clear PII + 2 ambiguous PII + 4 non-PII):

| Mode | Precision | Recall | F1 Score | Time |
|------|-----------|--------|----------|------|
| `rule` | 1.000 | 0.714 | 0.833 | 0.002s |
| `llm` | 1.000 | 0.429 | 0.600 | 15.6s |
| `hybrid` | 1.000 | **0.857** | **0.923** | 10.1s |

**Hybrid mode improves F1 score by +10.8% compared to rule-only**, successfully detecting ambiguous PII like person-in-charge columns containing embedded names.

---

## Profile Feature

Save PII processing settings as profiles to reuse in future work. Eliminates repetitive configuration for routine tasks (e.g., monthly patient data processing).

### TUI Usage

When PII is detected in TUI, you can choose to use a profile:

```
Use a profile?
  > Use existing profile
    New settings (can save as profile)
    One-time settings (don't save)
```

### CLI Usage

```bash
# List saved profiles
dataairlock profile list

# Create default profile
dataairlock profile create-default

# Show profile details
dataairlock profile show medical_data

# Share with team (export/import)
dataairlock profile export medical_data -o ./medical_profile.json
dataairlock profile import ./medical_profile.json
```

### Profile Storage Location

```
~/.config/dataairlock/profiles/
├── default.json
├── medical_data.json
└── hr_data.json
```

---

## Directory Structure

```
my_project/
├── .airlock/                    # Workspace (Git-safe)
│   ├── data/                    # Pseudonymized data
│   │   └── patients.csv         # PATIENT_001, PERSON_001...
│   ├── output/                  # LLM output directory
│   ├── PROMPT.md                # LLM prompt template
│   └── README.md
├── .airlock_mappings/           # Mapping files (NOT Git-safe)
│   └── patients.mapping.enc     # Encrypted mapping
└── results/                     # Restored results
    └── analysis.csv             # John Doe, 555-123-4567...
```

---

## Security

- **Encrypted Mapping Files** — Fernet (AES-128-CBC) encryption
- **Password Required** — Restoration requires password
- **Local Processing** — All pseudonymization and restoration is performed locally. Raw data is never sent to the cloud.
- **Git Exclusion** — `.airlock_mappings/` is automatically added to `.gitignore`

---

## Requirements

- Python 3.10+
- Ollama (only for chat command and LLM detection mode)

---

## Development

```bash
# Clone
git clone https://github.com/akira0907/dataairlock.git
cd dataairlock

# Setup development environment
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Run tests
pytest
```

---

## License

AGPL-3.0

---

## Author

[@akira0907](https://github.com/akira0907)
