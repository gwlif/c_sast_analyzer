import os
import json
import tempfile
import pytest
from src.analyzer import scan_path
from src.reporter import Reporter

@pytest.fixture
def mock_config():
    return {
        "dangerous_functions": {
            "strcpy": "Use strncpy",
            "system": "Avoid shell calls"
        },
        "ignore_paths": ["tests/"],
        "ignore_comments": ["// ignore-sec"]
    }

def test_vulnerable_code_detection(mock_config):
    test_c_code = """
    #include <string.h>
    void test() {
        char buf[10];
        strcpy(buf, "hello");
        strcpy(buf, "ignored"); // ignore-sec
    }
    """
    with tempfile.NamedTemporaryFile(suffix=".c", mode="w+", delete=False) as tf:
        tf.write(test_c_code)
        tf_path = tf.name

    try:
        issues = scan_path(tf_path, mock_config)
        assert len(issues) == 1
        assert issues[0]["function"] == "strcpy"
        assert issues[0]["line"] == 5
    finally:
        if os.path.exists(tf_path):
            os.remove(tf_path)

def test_json_report_generation():
    issues = [
        {
            "file": "test.c",
            "line": 10,
            "column": 5,
            "function": "strcpy",
            "code_snippet": "strcpy(a, b);",
            "recommendation": "Use strncpy"
        }
    ]
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
        out_path = tf.name

    try:
        Reporter.save_json(issues, out_path)
        assert os.path.exists(out_path)
        with open(out_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            assert len(data) == 1
            assert data[0]["function"] == "strcpy"
    finally:
        if os.path.exists(out_path):
            os.remove(out_path)
