# SARIF output

The analyzer can emit JSON, HTML, or SARIF 2.1.0. SARIF findings use stable rule IDs, repository-relative source URIs (relative to the working directory), source line/column, and snippets. Findings are marked `warning`: a dangerous-function match is a potential issue, not by itself proof that a vulnerability is exploitable.

## Run locally

From the repository root:

```bash
python analyzer_fixed.py security_cases.c \
  --config config.json \
  --format sarif \
  --out security_report
```

This writes `security_report.sarif`. Validate that it is JSON and inspect the run metadata:

```bash
python - <<'PY'
import json
with open("security_report.sarif", encoding="utf-8") as stream:
    report = json.load(stream)
print("SARIF version:", report["version"])
print("Findings:", len(report["runs"][0]["results"]))
PY
```

## Optional GitHub Code Scanning upload

The included GitHub Actions workflow runs tests and a real Clang smoke scan, then stores the SARIF file as an Actions artifact. If the GitHub repository supports Code Scanning, the workflow can additionally upload the SARIF file by granting `security-events: write` permission and adding this step after report generation:

```yaml
permissions:
  contents: read
  security-events: write

# After the analyzer has generated security_report.sarif:
- name: Upload SARIF to GitHub Code Scanning
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: security_report.sarif
```

Check that Code Scanning is available for the repository before enabling that optional upload. The unit tests use synthetic AST fixtures for deterministic edge-case coverage; the CI smoke scan separately exercises the installed `libclang` against `security_cases.c`.
