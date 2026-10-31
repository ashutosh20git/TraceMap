# SigmaHQ rules (vendored)

- Source: https://github.com/SigmaHQ/sigma, release `r2026-07-01`, asset `sigma_all_rules.zip`
- SHA-256: `5725c91b5813587ad6a4b0b8e0233fa44348b1595f818d8b7fd39d6033385085`
- License: Detection Rule License (DRL) 1.1, https://github.com/SigmaHQ/Detection-Rule-License. Each converted rule keeps its Sigma id, author and source path.
- Converted with `python scripts/sigma_import.py third_party/sigma/sigma_all_rules-r2026-07-01.zip r2026-07-01`, which writes `config/rules/sigma.yaml` and `import_report.json`. The rules are parsed as YAML data only and never executed.
