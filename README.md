# C/C++ AST Static Security Analyzer

A learning-oriented static security analyzer for C/C++ that uses **Clang's AST** (through `libclang`) to find potentially risky function calls and emit JSON, HTML, or SARIF 2.1.0 reports. It is intended as a small SAST/DevSecOps project—not as a replacement for a production-grade analyzer.

## Features

- Parses C/C++ source with `libclang` instead of relying on text-only `grep` matching.
- Detects configured calls such as `strcpy`, `sprintf`, `gets`, `system`, `alloca`, and `scanf`.
- Normalizes selected fortified Clang builtins (for example, macOS may expose `strcpy` as `__builtin___strcpy_chk`).
- Supports configurable rules and recommendations in `config.json`.
- Supports comment-based suppressions (`// ignore-sec`, `// nosonar` by default) and directory exclusions (`tests/`, `vendor/`, `build/` by default).
- Includes conservative checks for a few narrow, provable cases: string-literal `strcpy` into a fixed-size character array, simple pointer aliases to such arrays, limited `sprintf` calls with literal format/substitution strings, and a restricted `scanf` `%s` format.
- Produces JSON, HTML, and SARIF 2.1.0 reports with file locations and code snippets.
- Can return a non-zero exit status for findings, making it usable in CI.
- Includes unit tests and a GitHub Actions workflow for tests, a real `libclang` smoke scan, SARIF checks, and artifact upload.

## Requirements

- Python 3.10 or newer.
- The Python `libclang` package and a compatible `libclang` library.
- A C/C++ source file that Clang can parse in the current environment.

## Installation

From the repository root, create and activate a virtual environment, then install the binding package:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install libclang
```

Check that Python can load Clang:

```bash
python -c 'from clang.cindex import Index; print(Index.create())'
```

On macOS, the analyzer attempts common Homebrew LLVM library paths as a fallback. If `libclang` cannot be loaded, verify that the installed Python package and LLVM library are compatible and that your shell is using the intended virtual environment.

## Quick start

Scan the included intentionally risky example and create a JSON report:

```bash
python analyzer.py security_cases.c \
  --config config.json \
  --format json \
  --out security_report
```

This creates `security_report.json`. Other report formats:

```bash
python analyzer.py security_cases.c --config config.json --format html --out security_report
python analyzer.py security_cases.c --config config.json --format sarif --out security_report
```

`--out` is the output-file basename; the analyzer adds `.json`, `.html`, or `.sarif` based on `--format`.

Scan a file or a directory:

```bash
python analyzer.py ./src --config config.json --format sarif --out sast_report
```

Use the exit-code option in CI when findings should fail the job:

```bash
python analyzer.py ./src --config config.json --format json --out sast_report --exit-code
```

Exit statuses:

- `0`: completed scan; no findings, or `--exit-code` was not requested.
- `1`: findings were reported and `--exit-code` was supplied.
- `2`: invalid path/configuration, Clang initialization failure, or incomplete scan caused by parse errors.

Clang warnings may be printed to stderr even when the analyzer can produce a report. A Clang warning is not necessarily an analyzer failure.

## Configuration

`config.json` contains three settings:

```json
{
  "dangerous_functions": {
    "strcpy": "Review source length and destination capacity."
  },
  "ignore_paths": ["tests/", "vendor/", "build/"],
  "ignore_comments": ["// ignore-sec", "// nosonar"]
}
```

The actual project config contains several built-in function rules and longer recommendations. `dangerous_functions` maps function names to recommendations. `ignore_paths` lists directory names to exclude. `ignore_comments` defines comment marker strings; a finding on a line with a configured marker in a real C/C++ comment is suppressed. Treat suppressions as explicit risk acceptance and use them sparingly.

## Checks and conservative behavior

The analyzer reports potential issues rather than making a blanket claim that every matched function is exploitable. It suppresses only a few narrow cases when the available AST information supports a simple proof:

- `strcpy`: a direct string literal fits in a fixed-size `char` array; a simple local pointer alias is supported only under restrictive reference checks.
- `sprintf`: a small subset of literal format strings and literal `%s` substitutions can be measured against a fixed-size destination array.
- `scanf`: a restricted format containing a single `%s` conversion with an explicit width smaller than the fixed-size destination array can be treated as fitting.

Unsupported formats, pointer expressions, unknown capacities, or uncertain source lengths should remain warnings. These checks do not constitute general pointer analysis or general format-string interpretation.

## Run tests

```bash
python -m unittest -v test_analyzer.py
```

The unit suite covers configuration validation, directory exclusions, comment suppressions, HTML escaping, Clang builtin-name normalization, limited buffer checks, SARIF rule metadata, and error handling. The GitHub Actions `tests.yml` workflow additionally runs a real `libclang` smoke scan against `security_cases.c` and checks the generated SARIF's basic structure.

## SARIF and GitHub Actions

The analyzer emits SARIF 2.1.0 with stable IDs for built-in checks, line/column locations, source snippets, and relative artifact URIs. The default workflow saves the report as an Actions artifact. See [`SARIF_USAGE.md`](SARIF_USAGE.md) for report inspection and an optional Code Scanning upload workflow.

## Limitations

- This is not a complete C/C++ static analyzer. It does not implement interprocedural analysis, control-flow analysis, or taint/data-flow tracking from sources to sinks.
- Function-name matches alone cannot prove exploitability. For example, `system("ls")` is not automatically command injection.
- Buffer-safety checks cover only a narrow set of literal/fixed-array patterns. A safe result in one supported pattern is not a proof about all uses of that variable elsewhere; complex aliases and pointer arithmetic are intentionally not generalized.
- `scanf` and `sprintf` format handling is deliberately limited. Unknown conversions or unknown values remain potential findings; the analyzer does not model all C variadic argument types or C locale/encoding behavior.
- Compiler flags, project-specific include paths, macros, and build-system configuration may affect parsing. This version does not read `compile_commands.json`.
- Supported source extensions are `.c`, `.cpp`, `.h`, `.hpp`, and `.cc`.
- Reports should be reviewed by a developer/security engineer and combined with compiler diagnostics, tests, code review, and other security tools.

## Project status

This is a portfolio/educational project focused on Clang AST traversal, conservative rule logic, regression testing, report generation, and CI integration. Rule coverage and precision should be evaluated against a labeled test corpus before using it as a security gate for production code.
