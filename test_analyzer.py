import json
import os
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace

import analyzer


class FakeType:
    def __init__(self, kind_name, element_count=None, element_kind="CHAR_S"):
        self.kind = SimpleNamespace(name=kind_name)
        self.element_count = element_count
        self._element_kind = element_kind

    def get_array_element_type(self):
        return SimpleNamespace(kind=SimpleNamespace(name=self._element_kind))


class FakeCursor:
    def __init__(self, kind_name, *, children=(), type_obj=None, referenced=None,
                 arguments=(), spelling="", location=None, extent=None):
        self.kind = SimpleNamespace(name=kind_name)
        self._children = list(children)
        self.type = type_obj
        self.referenced = referenced
        self._arguments = list(arguments)
        self.spelling = spelling
        self.location = location
        self.extent = extent

    def get_children(self):
        return iter(self._children)

    def get_arguments(self):
        return iter(self._arguments)


def make_fake_strcpy_call(filepath, line, destination_capacity, source_capacity,
                          destination_type="CONSTANTARRAY", source_kind="STRING_LITERAL"):
    destination_decl = FakeCursor(
        "VAR_DECL",
        type_obj=FakeType(destination_type, destination_capacity),
    )
    destination_ref = FakeCursor("DECL_REF_EXPR", referenced=destination_decl)
    destination_arg = FakeCursor("UNEXPOSED_EXPR", children=[destination_ref])

    source_literal = FakeCursor(
        source_kind,
        type_obj=FakeType("CONSTANTARRAY", source_capacity),
    )
    source_arg = FakeCursor("UNEXPOSED_EXPR", children=[source_literal])

    call_kind = SimpleNamespace(name="CALL_EXPR")
    location = SimpleNamespace(
        file=SimpleNamespace(name=filepath), line=line, column=5
    )
    call = FakeCursor(
        "CALL_EXPR", children=[destination_arg, source_arg],
        arguments=[destination_arg, source_arg], spelling="strcpy", location=location,
    )
    call.kind = call_kind
    return call, call_kind


def fake_array_variable(name, capacity, type_kind="CONSTANTARRAY"):
    declaration = FakeCursor(
        "VAR_DECL", type_obj=FakeType(type_kind, capacity), spelling=name
    )
    reference = FakeCursor("DECL_REF_EXPR", referenced=declaration, spelling=name)
    return FakeCursor("UNEXPOSED_EXPR", children=[reference], spelling=name)


def fake_string_literal(value):
    return FakeCursor(
        "UNEXPOSED_EXPR",
        children=[FakeCursor(
            "STRING_LITERAL",
            type_obj=FakeType("CONSTANTARRAY", len(value.encode("ascii")) + 1),
            spelling=json.dumps(value, ensure_ascii=True),
        )],
        spelling=json.dumps(value, ensure_ascii=True),
    )


def fake_integer_literal(value):
    return FakeCursor("INTEGER_LITERAL", spelling=str(value))


def analyze_fake_call(function, arguments, source_text, recommendation="Review buffer size"):
    with tempfile.TemporaryDirectory() as tmp:
        source_path = os.path.realpath(os.path.join(tmp, "fixture.c"))
        with open(source_path, "w", encoding="utf-8") as source_file:
            source_file.write(source_text + "\n")
        call_kind = SimpleNamespace(name="CALL_EXPR")
        call = FakeCursor(
            "CALL_EXPR", children=arguments, arguments=arguments,
            spelling=function,
            location=SimpleNamespace(
                file=SimpleNamespace(name=source_path), line=1, column=1
            ),
        )
        call.kind = call_kind
        previous_cursor_kind = analyzer.CursorKind
        try:
            analyzer.CursorKind = SimpleNamespace(CALL_EXPR=call_kind)
            issues = []
            analyzer.analyze_cursor(
                call,
                {"dangerous_functions": {analyzer.normalize_function_name(function): recommendation}},
                issues,
                source_path,
                {},
                set(),
            )
            return issues
        finally:
            analyzer.CursorKind = previous_cursor_kind


class AnalyzerFixedTests(unittest.TestCase):
    def test_html_escapes_untrusted_source_text(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = os.path.join(tmp, "report.html")
            analyzer.generate_html(
                [{
                    "file": "<img src=x>",
                    "line": 1,
                    "column": 2,
                    "function": "strcpy",
                    "code_snippet": '<script>alert("x")</script>',
                    "recommendation": "Use <safe> handling",
                }],
                report,
            )
            with open(report, encoding="utf-8") as f:
                content = f.read()

        self.assertIn("&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;", content)
        self.assertNotIn('<script>alert("x")</script>', content)
        self.assertIn("&lt;img src=x&gt;", content)

    def test_sarif_report_contains_stable_rules_and_relative_locations(self):
        with tempfile.TemporaryDirectory() as tmp:
            source_dir = os.path.join(tmp, "src")
            os.makedirs(source_dir)
            report = os.path.join(tmp, "report.sarif")
            issues = [
                {
                    "file": os.path.join(source_dir, "a b.c"),
                    "line": 7,
                    "column": 3,
                    "function": "strcpy",
                    "code_snippet": "strcpy(buffer, input);",
                    "recommendation": "Check the buffer capacity.",
                },
                {
                    "file": os.path.join(source_dir, "worker.c"),
                    "line": 12,
                    "column": 5,
                    "function": "system",
                    "code_snippet": 'system("ls");',
                    "recommendation": "Avoid shell interpretation of untrusted input.",
                },
                {
                    "file": os.path.join(source_dir, "other.c"),
                    "line": 19,
                    "column": 1,
                    "function": "strcpy",
                    "code_snippet": "strcpy(dst, src);",
                    "recommendation": "Check the buffer capacity.",
                },
            ]
            analyzer.generate_sarif(issues, report, source_root=tmp)
            with open(report, encoding="utf-8") as report_file:
                document = json.load(report_file)

        self.assertEqual(document["version"], "2.1.0")
        self.assertIn("$schema", document)
        run = document["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "C/C++ AST Static Security Analyzer")
        self.assertEqual(len(run["tool"]["driver"]["rules"]), 2)
        self.assertEqual(len(run["results"]), 3)
        first = run["results"][0]
        self.assertEqual(first["ruleId"], "SAST-C-STRCPY")
        self.assertEqual(first["level"], "warning")
        location = first["locations"][0]["physicalLocation"]
        self.assertEqual(location["artifactLocation"]["uri"], "src/a%20b.c")
        self.assertEqual(location["region"]["startLine"], 7)
        self.assertEqual(location["region"]["startColumn"], 3)
        self.assertEqual(location["region"]["snippet"]["text"], "strcpy(buffer, input);")
        self.assertEqual(run["results"][2]["ruleId"], "SAST-C-STRCPY")

    def test_sarif_custom_rule_identifier_is_deterministic(self):
        metadata = analyzer._rule_metadata("unsafe call!?", "Review this call")
        self.assertEqual(metadata["id"], "SAST-C-CUSTOM-UNSAFE-CALL")
        self.assertEqual(metadata["name"], "unsafe call!?")

    def test_empty_sarif_report_is_valid_with_no_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = os.path.join(tmp, "empty.sarif")
            analyzer.generate_sarif([], report, source_root=tmp)
            with open(report, encoding="utf-8") as report_file:
                document = json.load(report_file)
        self.assertEqual(document["runs"][0]["results"], [])
        self.assertEqual(document["runs"][0]["tool"]["driver"]["rules"], [])

    def test_ignore_directories_match_names_not_substrings(self):
        ignored = {"tests", "vendor", "build"}
        self.assertEqual(analyzer._normalize_ignored_directory("tests/"), "tests")
        self.assertTrue(analyzer._should_ignore_directory("tests", ignored))
        self.assertFalse(analyzer._should_ignore_directory("mytests", ignored))

    def test_macos_fortified_strcpy_name_is_normalized(self):
        self.assertEqual(analyzer.normalize_function_name("__builtin___strcpy_chk"), "strcpy")
        self.assertEqual(analyzer.normalize_function_name("__builtin___sprintf_chk"), "sprintf")
        self.assertEqual(analyzer.normalize_function_name("system"), "system")

    def test_plain_builtin_name_is_normalized(self):
        self.assertEqual(analyzer.normalize_function_name("__builtin_strcpy"), "strcpy")
        self.assertEqual(analyzer.normalize_function_name("__builtin_object_size"), "object_size")

    def test_suppression_marker_only_counts_inside_a_comment_token(self):
        source = os.path.realpath("fixture.c")
        def token(kind, spelling, line):
            return SimpleNamespace(
                kind=SimpleNamespace(name=kind),
                spelling=spelling,
                location=SimpleNamespace(
                    file=SimpleNamespace(name=source), line=line
                ),
            )

        tokens = [
            token("STRING_LITERAL", '"// ignore-sec"', 10),
            token("COMMENT", "// ignore-sec", 11),
        ]
        translation_unit = SimpleNamespace(
            cursor=SimpleNamespace(extent=object()),
            get_tokens=lambda extent: iter(tokens),
        )
        suppressed = analyzer.get_suppressed_comment_lines(
            translation_unit, source, ["// ignore-sec"]
        )
        self.assertEqual(suppressed, {11})

    def test_comment_marker_on_multiline_comment_uses_marker_line(self):
        source = os.path.realpath("fixture.c")
        token = SimpleNamespace(
            kind=SimpleNamespace(name="COMMENT"),
            spelling="/* note\n * ignore-sec\n */",
            location=SimpleNamespace(file=SimpleNamespace(name=source), line=20),
        )
        translation_unit = SimpleNamespace(
            cursor=SimpleNamespace(extent=object()),
            get_tokens=lambda extent: iter([token]),
        )
        suppressed = analyzer.get_suppressed_comment_lines(
            translation_unit, source, ["ignore-sec"]
        )
        self.assertEqual(suppressed, {21})

    def test_config_recommendation_does_not_prescribe_blanket_strncpy(self):
        config_path = os.path.join(os.path.dirname(analyzer.__file__), "config.json")
        config = analyzer.load_config(config_path)
        recommendation = config["dangerous_functions"]["strcpy"].lower()
        self.assertIn("проверьте", recommendation)
        self.assertIn("размер", recommendation)
        self.assertIn("не заменяйте strcpy механически на strncpy", recommendation)

    def _analyze_fake_strcpy(self, destination_capacity, source_capacity,
                            destination_type="CONSTANTARRAY", source_kind="STRING_LITERAL"):
        with tempfile.TemporaryDirectory() as tmp:
            source_path = os.path.realpath(os.path.join(tmp, "fixture.c"))
            with open(source_path, "w", encoding="utf-8") as source_file:
                source_file.write('strcpy(buffer, "literal");\n')

            call, call_kind = make_fake_strcpy_call(
                source_path, 1, destination_capacity, source_capacity,
                destination_type=destination_type, source_kind=source_kind,
            )
            issues = []
            previous_cursor_kind = analyzer.CursorKind
            try:
                analyzer.CursorKind = SimpleNamespace(CALL_EXPR=call_kind)
                analyzer.analyze_cursor(
                    call,
                    {"dangerous_functions": {"strcpy": "Review buffer size"}},
                    issues,
                    source_path,
                    {},
                    set(),
                )
            finally:
                analyzer.CursorKind = previous_cursor_kind
            return issues

    def test_safe_literal_strcpy_is_not_reported(self):
        # Both sizes include the terminating NUL: 6 bytes fit in char[16].
        self.assertEqual(self._analyze_fake_strcpy(16, 6), [])

    def test_literal_strcpy_overflow_is_reported(self):
        # Nine bytes are required for "too long\0", but only four are available.
        issues = self._analyze_fake_strcpy(4, 9)
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]["function"], "strcpy")

    def test_pointer_destination_is_not_assumed_safe(self):
        issues = self._analyze_fake_strcpy(16, 6, destination_type="POINTER")
        self.assertEqual(len(issues), 1)

    def test_non_literal_source_is_not_assumed_safe(self):
        issues = self._analyze_fake_strcpy(16, 6, source_kind="DECL_REF_EXPR")
        self.assertEqual(len(issues), 1)


    def _analyze_pointer_alias_strcpy(
        self, add_extra_reference=False, add_macro_expansion_reference=False
    ):
        with tempfile.TemporaryDirectory() as tmp:
            source_path = os.path.realpath(os.path.join(tmp, "fixture.c"))
            with open(source_path, "w", encoding="utf-8") as source_file:
                source_file.write(
                    "char storage[16];\n"
                    "char *destination = storage;\n"
                    'strcpy(destination, "hello");\n'
                    + ("destination = storage;\n" if add_extra_reference else "")
                )

            storage_decl = FakeCursor(
                "VAR_DECL", type_obj=FakeType("CONSTANTARRAY", 16), spelling="storage"
            )
            storage_ref = FakeCursor(
                "DECL_REF_EXPR", referenced=storage_decl, spelling="storage",
                location=SimpleNamespace(file=SimpleNamespace(name=source_path), line=2, column=21),
            )
            initializer = FakeCursor("UNEXPOSED_EXPR", children=[storage_ref])
            pointer_decl = FakeCursor(
                "VAR_DECL", children=[initializer], type_obj=FakeType("POINTER"),
                spelling="destination",
            )
            pointer_ref = FakeCursor(
                "DECL_REF_EXPR", referenced=pointer_decl, spelling="destination",
                location=SimpleNamespace(file=SimpleNamespace(name=source_path), line=3, column=8),
            )
            destination_arg = FakeCursor("UNEXPOSED_EXPR", children=[pointer_ref])
            source_literal = fake_string_literal("hello")
            # Add source locations to the literal subtree so all test nodes look AST-like.
            source_literal.location = SimpleNamespace(
                file=SimpleNamespace(name=source_path), line=3, column=20
            )
            call_kind = SimpleNamespace(name="CALL_EXPR")
            call_location = SimpleNamespace(
                file=SimpleNamespace(name=source_path), line=3, column=1
            )
            call_extent = SimpleNamespace(
                start=call_location,
                end=SimpleNamespace(
                    file=SimpleNamespace(name=source_path), line=3, column=33
                ),
            )
            call_children = [destination_arg, source_literal]
            if add_macro_expansion_reference:
                # Simulates a fortified-header AST reference generated for
                # __builtin_object_size(destination, 0) within the same call.
                call_children.append(FakeCursor(
                    "DECL_REF_EXPR", referenced=pointer_decl, spelling="destination",
                    location=SimpleNamespace(
                        file=SimpleNamespace(name=source_path), line=3, column=25
                    ),
                ))
            call = FakeCursor(
                "CALL_EXPR", arguments=[destination_arg, source_literal],
                children=call_children, spelling="strcpy", location=call_location,
                extent=call_extent,
            )
            call.kind = call_kind
            root_children = [storage_decl, pointer_decl, call]
            if add_extra_reference:
                extra_reference = FakeCursor(
                    "DECL_REF_EXPR", referenced=pointer_decl, spelling="destination",
                    location=SimpleNamespace(
                        file=SimpleNamespace(name=source_path), line=4, column=1
                    ),
                )
                root_children.append(extra_reference)
            root = FakeCursor("TRANSLATION_UNIT", children=root_children)
            translation_unit = SimpleNamespace(cursor=root)

            issues = []
            previous_cursor_kind = analyzer.CursorKind
            try:
                analyzer.CursorKind = SimpleNamespace(CALL_EXPR=call_kind)
                analyzer.analyze_cursor(
                    root,
                    {"dangerous_functions": {"strcpy": "Review buffer size"}},
                    issues,
                    source_path,
                    {},
                    set(),
                    translation_unit,
                )
            finally:
                analyzer.CursorKind = previous_cursor_kind
            return issues

    def test_safe_literal_strcpy_through_unmodified_simple_pointer_alias_is_not_reported(self):
        self.assertEqual(self._analyze_pointer_alias_strcpy(), [])

    def test_pointer_alias_with_another_reference_is_not_assumed_safe(self):
        issues = self._analyze_pointer_alias_strcpy(add_extra_reference=True)
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]["function"], "strcpy")

    def test_fortified_header_reference_inside_same_call_does_not_block_safe_proof(self):
        self.assertEqual(
            self._analyze_pointer_alias_strcpy(add_macro_expansion_reference=True), []
        )

    def test_scanf_string_with_fitting_width_is_not_reported(self):
        # scanf width counts input characters; capacity must leave room for NUL.
        args = [fake_string_literal("%15s"), fake_array_variable("username", 16)]
        self.assertEqual(analyze_fake_call("scanf", args, 'scanf("%15s", username);'), [])

    def test_scanf_string_without_width_is_reported(self):
        args = [fake_string_literal("%s"), fake_array_variable("username", 16)]
        issues = analyze_fake_call("scanf", args, 'scanf("%s", username);')
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]["function"], "scanf")

    def test_scanf_width_equal_to_capacity_is_reported(self):
        args = [fake_string_literal("%16s"), fake_array_variable("username", 16)]
        issues = analyze_fake_call("scanf", args, 'scanf("%16s", username);')
        self.assertEqual(len(issues), 1)

    def test_sprintf_literal_result_that_fits_is_not_reported(self):
        args = [
            fake_array_variable("message", 16),
            fake_string_literal("user=%s"),
            fake_string_literal("admin"),
        ]
        self.assertEqual(
            analyze_fake_call("sprintf", args, 'sprintf(message, "user=%s", "admin");'),
            [],
        )

    def test_sprintf_literal_overflow_is_reported(self):
        args = [
            fake_array_variable("message", 4),
            fake_string_literal("user=%s"),
            fake_string_literal("admin"),
        ]
        issues = analyze_fake_call("sprintf", args, 'sprintf(message, "user=%s", "admin");')
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]["function"], "sprintf")

    def test_fortified_sprintf_literal_overflow_is_reported(self):
        args = [
            fake_array_variable("message", 4),
            fake_integer_literal(0),
            fake_integer_literal(4),
            fake_string_literal("user=%s"),
            fake_string_literal("admin"),
        ]
        issues = analyze_fake_call(
            "__builtin___sprintf_chk", args,
            'sprintf(message, "user=%s", "admin");',
        )
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]["function"], "sprintf")

    def test_sprintf_unknown_format_is_not_assumed_safe(self):
        args = [
            fake_array_variable("message", 64),
            fake_string_literal("value=%d"),
            fake_integer_literal(12),
        ]
        issues = analyze_fake_call("sprintf", args, 'sprintf(message, "value=%d", 12);')
        self.assertEqual(len(issues), 1)

    def test_valid_config_loads(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "config.json")
            with open(path, "w", encoding="utf-8") as f:
                json.dump({
                    "dangerous_functions": {"strcpy": "Review buffer size"},
                    "ignore_paths": ["tests/"],
                    "ignore_comments": ["// ignore-sec"],
                }, f)
            config = analyzer.load_config(path)
        self.assertEqual(config["dangerous_functions"]["strcpy"], "Review buffer size")

    def test_invalid_config_shape_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "config.json")
            with open(path, "w", encoding="utf-8") as f:
                json.dump({"dangerous_functions": []}, f)
            with self.assertRaises(ValueError):
                analyzer.load_config(path)

    def test_missing_scan_path_returns_error_code_2(self):
        result = subprocess.run(
            [sys.executable, analyzer.__file__, os.path.join(tempfile.gettempdir(), "does-not-exist-sast-test")],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("Путь не существует", result.stderr)


if __name__ == "__main__":
    unittest.main()
