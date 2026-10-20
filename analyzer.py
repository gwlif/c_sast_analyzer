import argparse
import ast
import glob
import html
import json
import os
import re
import sys
from urllib.parse import quote
from typing import Any, Dict, List, Optional, Tuple

SUPPORTED_EXTENSIONS = (".c", ".cpp", ".h", ".hpp", ".cc")

# Filled in by main() so the module can be imported even when libclang is absent.
Index = None
CursorKind = None
ClangDiagnostic = None


def init_clang():
    """Load Python bindings and the libclang shared library where possible."""
    try:
        from clang.cindex import Index as ClangIndex, CursorKind as ClangCursorKind
        from clang.cindex import Config as ClangConfig, Diagnostic as ClangDiagnosticClass
    except ImportError:
        # Fallback for common macOS/Homebrew installations.
        llvm_paths = glob.glob("/opt/homebrew/opt/llvm/lib/python*/site-packages")
        if llvm_paths:
            sys.path.insert(0, llvm_paths[0])
        from clang.cindex import Index as ClangIndex, CursorKind as ClangCursorKind
        from clang.cindex import Config as ClangConfig, Diagnostic as ClangDiagnosticClass

    if sys.platform == "darwin":
        if os.path.exists("/opt/homebrew/opt/llvm/lib"):
            ClangConfig.set_library_path("/opt/homebrew/opt/llvm/lib")
        elif os.path.exists("/usr/local/opt/llvm/lib"):
            ClangConfig.set_library_path("/usr/local/opt/llvm/lib")

    return ClangIndex, ClangCursorKind, ClangDiagnosticClass


def load_config(config_path: str) -> Dict[str, Any]:
    """Load and validate the JSON rules file before starting a scan."""
    with open(config_path, "r", encoding="utf-8") as config_file:
        config = json.load(config_file)

    if not isinstance(config, dict):
        raise ValueError("Корень конфигурации должен быть JSON-объектом")

    dangerous_functions = config.get("dangerous_functions", {})
    ignore_paths = config.get("ignore_paths", [])
    ignore_comments = config.get("ignore_comments", [])

    if not isinstance(dangerous_functions, dict) or not all(
        isinstance(name, str) and isinstance(recommendation, str)
        for name, recommendation in dangerous_functions.items()
    ):
        raise ValueError("'dangerous_functions' должен быть объектом: имя функции -> рекомендация")
    if not isinstance(ignore_paths, list) or not all(isinstance(path, str) for path in ignore_paths):
        raise ValueError("'ignore_paths' должен быть списком строк")
    if not isinstance(ignore_comments, list) or not all(isinstance(marker, str) for marker in ignore_comments):
        raise ValueError("'ignore_comments' должен быть списком строк")

    # Normalize the keys so the rest of the program can rely on their types.
    config["dangerous_functions"] = dangerous_functions
    config["ignore_paths"] = ignore_paths
    config["ignore_comments"] = ignore_comments
    return config


def get_line_content(filepath: str, line_number: int, line_cache: Dict[str, List[str]]) -> str:
    """Return a source line, caching file contents to avoid rereading per finding."""
    absolute_path = os.path.realpath(filepath)
    if absolute_path not in line_cache:
        try:
            with open(absolute_path, "r", encoding="utf-8", errors="replace") as source_file:
                line_cache[absolute_path] = source_file.readlines()
        except OSError:
            return "N/A"

    lines = line_cache[absolute_path]
    if 0 < line_number <= len(lines):
        return lines[line_number - 1].strip()
    return ""


def normalize_function_name(func_name: str) -> str:
    """Normalize hardened Clang/GCC builtins back to the source-level function name.

    On macOS, for example, a source call to strcpy may appear in the AST as
    __builtin___strcpy_chk because the SDK applies fortified headers.
    """
    name = func_name
    if name.startswith("__builtin___") and name.endswith("_chk"):
        return name[len("__builtin___") : -len("_chk")]
    if name.startswith("__builtin_"):
        return name[len("__builtin_") :]
    return name


def get_suppressed_comment_lines(translation_unit, filepath: str, markers: List[str]) -> set:
    """Find source lines where a configured marker occurs inside a real C/C++ comment.

    Searching source text alone is not sufficient: a string literal such as
    printf("// ignore-sec") must not suppress a finding.
    """
    markers = [marker for marker in markers if marker]
    if not markers:
        return set()

    suppressed_lines = set()
    target_path = os.path.realpath(filepath)
    try:
        tokens = translation_unit.get_tokens(extent=translation_unit.cursor.extent)
        for token in tokens:
            # TokenKind.COMMENT is named COMMENT in libclang's Python bindings.
            if getattr(token.kind, "name", "") != "COMMENT":
                continue
            token_file = token.location.file
            if not token_file or os.path.realpath(token_file.name) != target_path:
                continue
            for offset, comment_line in enumerate(token.spelling.splitlines() or [token.spelling]):
                if any(marker in comment_line for marker in markers):
                    suppressed_lines.add(token.location.line + offset)
    except Exception as exc:
        # Fail open: if tokenization fails, do not suppress findings based on plain text.
        print(f"[i] Не удалось прочитать комментарии Clang для {filepath}: {exc}", file=sys.stderr)
    return suppressed_lines



def _unwrap_simple_expression(cursor):
    """Unwrap harmless AST wrappers without guessing through complex expressions."""
    while getattr(getattr(cursor, "kind", None), "name", "") in {
        "UNEXPOSED_EXPR", "PAREN_EXPR"
    }:
        children = list(cursor.get_children())
        if len(children) != 1:
            break
        cursor = children[0]
    return cursor


def _constant_char_array_length(type_obj) -> Optional[int]:
    """Return the element count for a fixed-size narrow char array, if known."""
    type_kind = getattr(getattr(type_obj, "kind", None), "name", "")
    if type_kind != "CONSTANTARRAY":
        return None

    try:
        count = type_obj.element_count
        element_kind = getattr(type_obj.get_array_element_type().kind, "name", "")
    except (AttributeError, TypeError, ValueError):
        return None

    # strcpy operates on narrow character strings. Stay conservative for wchar_t,
    # char16_t/char32_t, pointers, variable-length arrays, and unknown types.
    if element_kind not in {"CHAR_S", "CHAR_U", "SCHAR", "UCHAR"}:
        return None
    if not isinstance(count, int) or count < 1:
        return None
    return count


def _walk_cursors(root):
    """Yield an AST cursor and all descendants without requiring cursor parents."""
    stack = [root]
    while stack:
        current = stack.pop()
        yield current
        try:
            stack.extend(reversed(list(current.get_children())))
        except (AttributeError, TypeError, ValueError):
            continue


def _same_source_location(left, right) -> bool:
    """Compare cursor source positions, independent of Python wrapper identity."""
    left_location = getattr(left, "location", None)
    right_location = getattr(right, "location", None)
    if left_location is None or right_location is None:
        return False
    left_file = getattr(left_location, "file", None)
    right_file = getattr(right_location, "file", None)
    if not left_file or not right_file:
        return False
    return (
        os.path.realpath(left_file.name) == os.path.realpath(right_file.name)
        and getattr(left_location, "line", None) == getattr(right_location, "line", None)
        and getattr(left_location, "column", None) == getattr(right_location, "column", None)
    )


def _simple_pointer_array_initializer(pointer_decl):
    """Return the fixed-size array declaration for `char *p = array`, if exact.

    Rejects pointer arithmetic, address-of/subscript expressions, casts, and
    declarations without a simple initializer.
    """
    pointer_type = getattr(getattr(pointer_decl, "type", None), "kind", None)
    if getattr(pointer_type, "name", "") != "POINTER":
        return None

    candidates = []
    try:
        declaration_children = list(pointer_decl.get_children())
    except (AttributeError, TypeError, ValueError):
        return None

    for child in declaration_children:
        kind_name = getattr(getattr(child, "kind", None), "name", "")
        # Type references and attributes are not initializer expressions.
        if not (kind_name.endswith("_EXPR") or kind_name.endswith("_LITERAL")):
            continue
        initializer = _unwrap_simple_expression(child)
        if getattr(getattr(initializer, "kind", None), "name", "") != "DECL_REF_EXPR":
            return None
        target = getattr(initializer, "referenced", None)
        if getattr(getattr(target, "kind", None), "name", "") != "VAR_DECL":
            return None
        if _constant_char_array_length(getattr(target, "type", None)) is None:
            return None
        candidates.append(target)

    return candidates[0] if len(candidates) == 1 else None


def _location_is_within_extent(location, extent) -> bool:
    """Return whether a source location falls inside a cursor's source extent."""
    if location is None or extent is None:
        return False
    start = getattr(extent, "start", None)
    end = getattr(extent, "end", None)
    if start is None or end is None:
        return False
    location_file = getattr(location, "file", None)
    start_file = getattr(start, "file", None)
    end_file = getattr(end, "file", None)
    if not location_file or not start_file or not end_file:
        return False
    location_path = os.path.realpath(location_file.name)
    if location_path != os.path.realpath(start_file.name):
        return False
    if location_path != os.path.realpath(end_file.name):
        return False

    position = (getattr(location, "line", 0), getattr(location, "column", 0))
    start_position = (getattr(start, "line", 0), getattr(start, "column", 0))
    end_position = (getattr(end, "line", 0), getattr(end, "column", 0))
    return start_position <= position <= end_position


def _pointer_alias_has_no_other_references(
    translation_unit, pointer_decl, destination_ref, call_cursor=None
) -> bool:
    """Reject pointer aliases referenced outside this source-level call.

    Fortified libc headers on macOS may expand strcpy to a checked builtin that also
    references the destination in a compiler-generated __builtin_object_size call.
    Those synthetic AST references can share the source call's extent. Accept those
    references only when they all map inside that exact call; a real use or assignment
    elsewhere in the file keeps the finding. This is a narrow local heuristic, not a
    general points-to analysis.
    """
    if translation_unit is None:
        return False
    references = []
    try:
        for node in _walk_cursors(translation_unit.cursor):
            if getattr(getattr(node, "kind", None), "name", "") != "DECL_REF_EXPR":
                continue
            referenced = getattr(node, "referenced", None)
            if referenced == pointer_decl:
                references.append(node)
    except Exception:
        return False

    if not references or not any(
        _same_source_location(reference, destination_ref) for reference in references
    ):
        return False

    extent = getattr(call_cursor, "extent", None)
    if extent is not None and all(
        _location_is_within_extent(getattr(reference, "location", None), extent)
        for reference in references
    ):
        return True

    # Fallback for simplified/mock ASTs that do not expose source extents.
    return len(references) == 1 and _same_source_location(references[0], destination_ref)


def is_provably_safe_literal_strcpy(call_cursor, translation_unit=None) -> bool:
    """Prove a narrow strcpy case fits; return False whenever the proof is uncertain.

    Supports a direct fixed-size char array or a simple `char *p = array` alias whose
    only AST reference is this call, plus a direct string literal as source. The
    literal size includes its NUL byte. General pointer/points-to analysis is not
    attempted; unknown sizes and any additional pointer use remain findings.
    """
    try:
        arguments = list(call_cursor.get_arguments())
    except (AttributeError, TypeError, ValueError):
        return False

    if len(arguments) < 2:
        return False

    destination = _unwrap_simple_expression(arguments[0])
    source = _unwrap_simple_expression(arguments[1])
    if getattr(getattr(destination, "kind", None), "name", "") != "DECL_REF_EXPR":
        return False
    declaration = getattr(destination, "referenced", None)
    if getattr(getattr(declaration, "kind", None), "name", "") != "VAR_DECL":
        return False
    if getattr(getattr(source, "kind", None), "name", "") != "STRING_LITERAL":
        return False

    destination_capacity = _constant_char_array_length(getattr(declaration, "type", None))
    if destination_capacity is None:
        # Narrow alias support for `char *destination = storage;`. If anything else
        # refers to the pointer, do not assume that it still points at this array.
        aliased_array = _simple_pointer_array_initializer(declaration)
        if aliased_array is None or not _pointer_alias_has_no_other_references(
            translation_unit, declaration, destination, call_cursor
        ):
            return False
        destination_capacity = _constant_char_array_length(
            getattr(aliased_array, "type", None)
        )

    source_required = _constant_char_array_length(getattr(source, "type", None))
    if destination_capacity is None or source_required is None:
        return False
    return source_required <= destination_capacity



def _direct_variable_declaration(expression):
    """Return a directly referenced variable declaration, or None if uncertain."""
    expression = _unwrap_simple_expression(expression)
    if getattr(getattr(expression, "kind", None), "name", "") != "DECL_REF_EXPR":
        return None
    declaration = getattr(expression, "referenced", None)
    if getattr(getattr(declaration, "kind", None), "name", "") != "VAR_DECL":
        return None
    return declaration


def _simple_narrow_string_literal(expression) -> Optional[str]:
    """Decode a simple ASCII C string literal; return None for uncertain spellings."""
    expression = _unwrap_simple_expression(expression)
    if getattr(getattr(expression, "kind", None), "name", "") != "STRING_LITERAL":
        return None
    spelling = getattr(expression, "spelling", "")
    if not isinstance(spelling, str):
        return None
    try:
        value = ast.literal_eval(spelling)
    except (SyntaxError, ValueError):
        return None
    if not isinstance(value, str) or not value.isascii() or "\x00" in value:
        # Non-ASCII encodings and embedded NULs need C target/encoding semantics.
        return None
    return value


def _literal_printf_output_length(format_value: str, value_arguments) -> Optional[int]:
    """Compute output length for a deliberately tiny printf subset.

    Supports literal text, %% and %s where each %s argument is a simple ASCII
    string literal. Any other format specifier or unknown argument returns None.
    The returned count excludes the final NUL byte written by sprintf.
    """
    output_length = 0
    argument_index = 0
    i = 0
    while i < len(format_value):
        if format_value[i] != "%":
            output_length += 1
            i += 1
            continue
        if i + 1 >= len(format_value):
            return None
        specifier = format_value[i + 1]
        if specifier == "%":
            output_length += 1
            i += 2
            continue
        if specifier != "s" or argument_index >= len(value_arguments):
            return None
        value = _simple_narrow_string_literal(value_arguments[argument_index])
        if value is None:
            return None
        output_length += len(value)
        argument_index += 1
        i += 2

    if argument_index != len(value_arguments):
        return None
    return output_length


def is_provably_safe_literal_sprintf(call_cursor, source_func_name: str = "sprintf") -> bool:
    """Prove a simple sprintf with literal-only %s arguments fits in a fixed array.

    This intentionally does not attempt general printf semantics. It returns True
    only when the destination capacity, format, and all substitutions are known.
    Fortified Clang calls such as __builtin___sprintf_chk include two extra
    arguments before the format string.
    """
    try:
        arguments = list(call_cursor.get_arguments())
    except (AttributeError, TypeError, ValueError):
        return False

    fortified = "sprintf_chk" in source_func_name or source_func_name in {
        "__sprintf_chk", "__builtin___sprintf_chk"
    }
    format_index = 3 if fortified else 1
    values_index = format_index + 1
    if len(arguments) <= format_index:
        return False

    destination_decl = _direct_variable_declaration(arguments[0])
    if destination_decl is None:
        return False
    capacity = _constant_char_array_length(getattr(destination_decl, "type", None))
    if capacity is None:
        return False

    format_value = _simple_narrow_string_literal(arguments[format_index])
    if format_value is None:
        return False
    output_length = _literal_printf_output_length(format_value, arguments[values_index:])
    if output_length is None:
        return False

    # sprintf appends one NUL byte.
    return output_length + 1 <= capacity


def is_provably_safe_scanf_string_input(call_cursor) -> bool:
    """Prove the narrow case scanf("%Ns", fixed_char_array) fits.

    Suppresses only when there is exactly one conversion, it is %s, the width is
    explicit, and width < array capacity to leave room for the NUL. Anything more
    complex remains a finding rather than being presumed safe.
    """
    try:
        arguments = list(call_cursor.get_arguments())
    except (AttributeError, TypeError, ValueError):
        return False
    if len(arguments) < 2:
        return False

    format_value = _simple_narrow_string_literal(arguments[0])
    if format_value is None:
        return False

    # Parse only %% and exactly one plain %s or %Ns conversion. Flags, positional
    # arguments, scansets, length modifiers and additional conversions are unknown.
    conversions = []
    i = 0
    while i < len(format_value):
        if format_value[i] != "%":
            i += 1
            continue
        if i + 1 < len(format_value) and format_value[i + 1] == "%":
            i += 2
            continue
        j = i + 1
        while j < len(format_value) and format_value[j].isdigit():
            j += 1
        if j >= len(format_value) or format_value[j] != "s":
            return False
        width_text = format_value[i + 1:j]
        conversions.append(int(width_text) if width_text else None)
        i = j + 1

    if len(conversions) != 1:
        return False
    width = conversions[0]
    if width is None or width <= 0:
        return False

    destination_decl = _direct_variable_declaration(arguments[1])
    if destination_decl is None:
        return False
    capacity = _constant_char_array_length(getattr(destination_decl, "type", None))
    if capacity is None:
        return False

    return width < capacity

def analyze_cursor(
    cursor,
    config: Dict[str, Any],
    issues: List[Dict[str, Any]],
    filepath: str,
    line_cache: Dict[str, List[str]],
    suppressed_comment_lines: Optional[set] = None,
    translation_unit=None,
) -> None:
    """Walk the AST and report configured calls originating in the file being scanned."""
    if suppressed_comment_lines is None:
        suppressed_comment_lines = set()

    if cursor.kind == CursorKind.CALL_EXPR:
        location_file = cursor.location.file
        # Do not report calls originating in included headers as if they were in this file.
        if location_file and os.path.realpath(location_file.name) == os.path.realpath(filepath):
            source_func_name = cursor.spelling
            func_name = normalize_function_name(source_func_name)
            dangerous_functions = config.get("dangerous_functions", {})

            if func_name in dangerous_functions:
                line_num = cursor.location.line
                col_num = cursor.location.column
                line_content = get_line_content(filepath, line_num, line_cache)
                ignored = line_num in suppressed_comment_lines
                # Suppress strcpy only when this narrow AST pattern proves the
                # literal (including its NUL byte) fits in a fixed char array.
                proven_safe = (
                    (func_name == "strcpy" and is_provably_safe_literal_strcpy(cursor, translation_unit))
                    or (func_name == "sprintf" and is_provably_safe_literal_sprintf(cursor, source_func_name))
                    or (func_name == "scanf" and is_provably_safe_scanf_string_input(cursor))
                )

                if not ignored and not proven_safe:
                    issues.append({
                        "file": filepath,
                        "line": line_num,
                        "column": col_num,
                        "function": func_name,
                        "code_snippet": line_content,
                        "recommendation": dangerous_functions[func_name],
                    })

    for child in cursor.get_children():
        analyze_cursor(
            child, config, issues, filepath, line_cache, suppressed_comment_lines,
            translation_unit,
        )


def _normalize_ignored_directory(path: str) -> str:
    # Treat both slash styles as separators and compare directory names, not substrings.
    normalized = path.replace("\\", "/").strip("/")
    return os.path.normcase(normalized)


def _should_ignore_directory(dirname: str, ignored_names: List[str]) -> bool:
    normalized_dirname = os.path.normcase(dirname)
    return normalized_dirname in ignored_names


def analyze_file(filepath: str, config: Dict[str, Any], index) -> Tuple[List[Dict[str, Any]], bool]:
    """Analyze one source file. The bool is False if parsing reported errors."""
    issues: List[Dict[str, Any]] = []
    try:
        translation_unit = index.parse(os.path.realpath(filepath))
    except Exception as exc:
        print(f"[!] Не удалось разобрать AST для {filepath}: {exc}", file=sys.stderr)
        return issues, False

    parse_ok = True
    error_severity = getattr(ClangDiagnostic, "Error", 3)
    fatal_severity = getattr(ClangDiagnostic, "Fatal", 4)
    for diagnostic in translation_unit.diagnostics:
        if diagnostic.severity >= error_severity:
            parse_ok = False
            print(f"[!] Ошибка Clang в {filepath}: {diagnostic}", file=sys.stderr)
        elif diagnostic.severity == getattr(ClangDiagnostic, "Warning", 2):
            print(f"[i] Предупреждение Clang в {filepath}: {diagnostic}", file=sys.stderr)
        if diagnostic.severity >= fatal_severity:
            # Continue with any AST Clang produced, but mark scan as incomplete.
            parse_ok = False

    absolute_path = os.path.realpath(filepath)
    suppressed_lines = get_suppressed_comment_lines(
        translation_unit, absolute_path, config.get("ignore_comments", [])
    )
    analyze_cursor(
        translation_unit.cursor, config, issues, absolute_path, {}, suppressed_lines,
        translation_unit,
    )
    return issues, parse_ok


def scan_directory(directory: str, config: Dict[str, Any], index) -> Tuple[List[Dict[str, Any]], bool]:
    issues: List[Dict[str, Any]] = []
    scan_ok = True
    ignored_names = {
        _normalize_ignored_directory(path).split("/")[-1]
        for path in config.get("ignore_paths", [])
        if _normalize_ignored_directory(path)
    }

    for root, dirnames, filenames in os.walk(directory, topdown=True):
        # Prune ignored directories before os.walk descends into them.
        dirnames[:] = sorted(
            dirname for dirname in dirnames
            if not _should_ignore_directory(dirname, ignored_names)
        )

        for filename in filenames:
            if not filename.endswith(SUPPORTED_EXTENSIONS):
                continue
            filepath = os.path.join(root, filename)
            file_issues, file_ok = analyze_file(filepath, config, index)
            issues.extend(file_issues)
            scan_ok = scan_ok and file_ok

    return issues, scan_ok


def generate_html(issues: List[Dict[str, Any]], output_path: str) -> None:
    """Write an HTML report, escaping every value originating from source/config."""
    parts = ["""<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>SAST Security Report</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 40px; background: #f8f9fa; color: #212529; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        h1 { border-bottom: 2px solid #0d6efd; padding-bottom: 10px; color: #0d6efd; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { border: 1px solid #dee2e6; padding: 12px; text-align: left; vertical-align: top; }
        th { background-color: #343a40; color: white; }
        tr:nth-child(even) { background-color: #f8f9fa; }
        .vuln { color: #dc3545; font-weight: bold; font-family: monospace; }
        code { background-color: #e9ecef; padding: 2px 6px; border-radius: 4px; font-family: monospace; white-space: pre-wrap; overflow-wrap: anywhere; }
        .badge-success { background: #198754; color: white; padding: 6px 12px; border-radius: 4px; display: inline-block; }
        .badge-danger { background: #dc3545; color: white; padding: 6px 12px; border-radius: 4px; display: inline-block; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ Static Security Analysis Report</h1>
"""]

    if not issues:
        parts.append(
            "<p class='badge-success'>По настроенным правилам совпадений не обнаружено. "
            "Это не гарантирует отсутствие уязвимостей.</p>"
        )
    else:
        parts.append(
            f"<p class='badge-danger'>Обнаружено потенциальных проблем: <b>{len(issues)}</b></p>"
        )
        parts.append(
            "<table><thead><tr><th>Файл</th><th>Позиция</th><th>Функция</th>"
            "<th>Фрагмент</th><th>Рекомендация</th></tr></thead><tbody>"
        )
        for issue in issues:
            safe_file = html.escape(str(issue.get("file", "")))
            safe_function = html.escape(str(issue.get("function", "")))
            safe_snippet = html.escape(str(issue.get("code_snippet", "")))
            safe_recommendation = html.escape(str(issue.get("recommendation", "")))
            line = html.escape(str(issue.get("line", "")))
            column = html.escape(str(issue.get("column", "")))
            parts.append(
                f"<tr><td>{safe_file}</td><td>{line}:{column}</td>"
                f"<td class='vuln'>{safe_function}</td>"
                f"<td><code>{safe_snippet}</code></td>"
                f"<td>{safe_recommendation}</td></tr>"
            )
        parts.append("</tbody></table>")

    parts.append("</div></body></html>")
    with open(output_path, "w", encoding="utf-8") as output_file:
        output_file.write("".join(parts))



_SARIF_RULES = {
    "strcpy": (
        "SAST-C-STRCPY",
        "Potentially unsafe string copy",
        "The strcpy call may write beyond the destination buffer if the source is too large.",
    ),
    "sprintf": (
        "SAST-C-SPRINTF",
        "Potentially unsafe formatted output",
        "The sprintf call does not accept a destination capacity; verify that the formatted result fits.",
    ),
    "gets": (
        "SAST-C-GETS",
        "Unbounded line input",
        "The gets function cannot limit the number of characters written to the destination.",
    ),
    "system": (
        "SAST-C-SYSTEM",
        "Shell command execution",
        "The system call invokes a command processor; risk depends on how the command is constructed.",
    ),
    "alloca": (
        "SAST-C-ALLOCA",
        "Stack allocation with alloca",
        "Large or uncontrolled stack allocations can exhaust stack space.",
    ),
    "scanf": (
        "SAST-C-SCANF",
        "Formatted input with scanf",
        "Unbounded string conversion or mismatched format arguments can cause memory-safety issues.",
    ),
}


def _rule_metadata(function_name: str, recommendation: str = "") -> Dict[str, str]:
    """Return stable SARIF metadata for configured rules, including custom rules."""
    normalized = normalize_function_name(str(function_name))
    if normalized in _SARIF_RULES:
        rule_id, short_description, full_description = _SARIF_RULES[normalized]
    else:
        safe_name = re.sub(r"[^A-Za-z0-9._-]+", "-", normalized).strip("-.") or "CUSTOM"
        rule_id = f"SAST-C-CUSTOM-{safe_name.upper()}"
        short_description = f"Configured risky call: {normalized}"
        full_description = f"The configured rule matched a call to {normalized}. Review its context."
    return {
        "id": rule_id,
        "name": normalized,
        "short_description": short_description,
        "full_description": full_description,
        "recommendation": str(recommendation),
    }


def _sarif_uri(filepath: str, source_root: str) -> str:
    """Build a repository-relative, URL-escaped URI for a SARIF artifact."""
    absolute_path = os.path.abspath(filepath)
    absolute_root = os.path.abspath(source_root)
    try:
        relative_path = os.path.relpath(absolute_path, absolute_root)
    except ValueError:
        relative_path = os.path.basename(absolute_path)
    return quote(relative_path.replace(os.sep, "/"), safe="/.-_~")


def generate_sarif(
    issues: List[Dict[str, Any]], output_path: str, source_root: Optional[str] = None
) -> None:
    """Write SARIF 2.1.0 so findings can be consumed by compatible CI/code-scanning tools.

    Every finding is still reported as a warning because a dangerous-function match is
    not, by itself, proof of an exploitable vulnerability. Known functions receive stable
    rule identifiers; custom names from config receive deterministic identifiers.
    """
    root = os.path.abspath(source_root or os.getcwd())
    metadata_by_id: Dict[str, Dict[str, str]] = {}
    result_entries = []

    for issue in issues:
        function_name = str(issue.get("function", "unknown"))
        metadata = _rule_metadata(function_name, str(issue.get("recommendation", "")))
        metadata_by_id.setdefault(metadata["id"], metadata)
        try:
            line = max(1, int(issue.get("line", 1)))
        except (TypeError, ValueError):
            line = 1
        try:
            column = max(1, int(issue.get("column", 1)))
        except (TypeError, ValueError):
            column = 1

        result_entries.append({
            "ruleId": metadata["id"],
            "level": "warning",
            "message": {
                "text": (
                    f"Potentially unsafe call to {function_name}. "
                    f"{issue.get('recommendation', 'Review this call in context.')}"
                )
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": _sarif_uri(str(issue.get("file", "")), root),
                        "uriBaseId": "%SRCROOT%",
                    },
                    "region": {
                        "startLine": line,
                        "startColumn": column,
                        "snippet": {"text": str(issue.get("code_snippet", ""))},
                    },
                }
            }],
            "properties": {
                "function": function_name,
                "recommendation": str(issue.get("recommendation", "")),
            },
        })

    sorted_rules = sorted(metadata_by_id.values(), key=lambda item: item["id"])
    sarif_rules = []
    rule_indices = {}
    for index, metadata in enumerate(sorted_rules):
        rule_indices[metadata["id"]] = index
        sarif_rules.append({
            "id": metadata["id"],
            "name": metadata["name"],
            "shortDescription": {"text": metadata["short_description"]},
            "fullDescription": {"text": metadata["full_description"]},
            "defaultConfiguration": {"level": "warning"},
            "help": {"text": metadata["recommendation"] or metadata["full_description"]},
            "properties": {"tags": ["security", "sast"]},
        })

    for entry in result_entries:
        entry["ruleIndex"] = rule_indices[entry["ruleId"]]

    document = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "C/C++ AST Static Security Analyzer",
                    "semanticVersion": "0.5.0",
                    "rules": sarif_rules,
                }
            },
            "originalUriBaseIds": {"%SRCROOT%": {"uri": "./"}},
            "results": result_entries,
        }],
    }
    with open(output_path, "w", encoding="utf-8") as report_file:
        json.dump(document, report_file, indent=2, ensure_ascii=False)

def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="AST-based C/C++ Static Security Analyzer (SDL/SAST)"
    )
    parser.add_argument("path", help="Путь к файлу или папке для сканирования")
    parser.add_argument("--config", default="config.json", help="Путь к JSON-конфигурации правил")
    parser.add_argument("--format", choices=["json", "html", "sarif"], default="html", help="Формат отчёта")
    parser.add_argument("--out", default="sast_report", help="Имя итогового отчёта без расширения")
    parser.add_argument(
        "--exit-code", action="store_true",
        help="Возвращать код 1, если найдены потенциальные проблемы (для CI/CD)"
    )
    args = parser.parse_args(argv)

    if not os.path.exists(args.path):
        print(f"[!] Путь не существует: {args.path}", file=sys.stderr)
        return 2
    if not (os.path.isfile(args.path) or os.path.isdir(args.path)):
        print(f"[!] Путь не является обычным файлом или директорией: {args.path}", file=sys.stderr)
        return 2
    if os.path.isfile(args.path) and not args.path.endswith(SUPPORTED_EXTENSIONS):
        print(
            f"[!] Неподдерживаемое расширение файла: {args.path}. "
            f"Поддерживаются: {', '.join(SUPPORTED_EXTENSIONS)}",
            file=sys.stderr,
        )
        return 2

    try:
        config = load_config(args.config)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"[!] Не удалось загрузить конфигурацию {args.config}: {exc}", file=sys.stderr)
        return 2

    try:
        global Index, CursorKind, ClangDiagnostic
        Index, CursorKind, ClangDiagnostic = init_clang()
        index = Index.create()
    except Exception as exc:
        print(
            "[!] Не удалось загрузить libclang. Проверьте установку пакета clang "
            f"и библиотеки LLVM: {exc}",
            file=sys.stderr,
        )
        return 2

    if os.path.isfile(args.path):
        issues, scan_ok = analyze_file(args.path, config, index)
    else:
        issues, scan_ok = scan_directory(args.path, config, index)

    output_file = f"{args.out}.{args.format}"
    try:
        if args.format == "json":
            with open(output_file, "w", encoding="utf-8") as report_file:
                json.dump(issues, report_file, indent=2, ensure_ascii=False)
        elif args.format == "sarif":
            generate_sarif(issues, output_file)
        else:
            generate_html(issues, output_file)
    except OSError as exc:
        print(f"[!] Не удалось записать отчёт {output_file}: {exc}", file=sys.stderr)
        return 2

    print(f"[+] Сканирование завершено. Найдено потенциальных проблем: {len(issues)}.")
    print(f"[+] Отчёт сохранён: {output_file}")

    # A failed/incomplete parse must fail CI even if --exit-code wasn't requested.
    if not scan_ok:
        print("[!] Анализ завершён не полностью из-за ошибок разбора.", file=sys.stderr)
        return 2
    if args.exit_code and issues:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
