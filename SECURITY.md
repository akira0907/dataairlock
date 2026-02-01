# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.3.x   | :white_check_mark: |
| < 0.3   | :x:                |

## Security Design

DataAirlock is designed with security as a core principle:

### Local Processing
- All pseudonymization and restoration happens **locally on your machine**
- Raw data is **never sent to external servers**
- The tool runs entirely offline (except for optional Ollama LLM detection)

### Encryption
- Mapping files are encrypted using **Fernet (AES-128-CBC)**
- Password-based key derivation using PBKDF2 with SHA256
- Salt is randomly generated for each encryption operation

### Data Isolation
- `.airlock_mappings/` directory is automatically added to `.gitignore`
- Mapping files are stored separately from pseudonymized data
- Clear separation between safe-to-share data and sensitive mappings

## Reporting a Vulnerability

If you discover a security vulnerability in DataAirlock, please report it responsibly:

1. **Do NOT** create a public GitHub issue
2. Email the security report to: [akira0907@gmail.com]
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

We will respond within 48 hours and work to address the issue promptly.

## Known Limitations

> **This tool does not guarantee 100% detection or pseudonymization of personal information.**

- PII detection is based on pattern matching and heuristics
- Some edge cases may not be detected
- Users must verify output data themselves
- The developers are not responsible for any data leaks or damages

## Best Practices

1. **Always review pseudonymized output** before sharing with LLMs
2. **Use strong passwords** for mapping file encryption
3. **Keep mapping files secure** - they contain the keys to restore original data
4. **Regularly backup** your mapping files
5. **Do not share** `.airlock_mappings/` directory or mapping files
