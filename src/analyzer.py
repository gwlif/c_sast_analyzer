import os
import json
import argparse
import sys
import glob
from typing import List, Dict, Any

try:
    from src.reporter import Reporter
except ImportError:
    from reporter import Reporter


def init_clang():
    """Кроссплатформенная инициализация libclang."""
    try:
        from clang.cindex import Index, CursorKind, Config
        return Index, CursorKind, Config
    except Exception:
        llvm_paths = glob.glob('/opt/homebrew/opt/llvm/lib/python*/site-packages')
        if llvm_paths:
            sys.path.insert(0, llvm_paths[0])
        from clang.cindex import Index, CursorKind, Config
        
        if sys.platform == "darwin":
            if os.path.exists('/opt/homebrew/opt/llvm/lib'):
                Config.set_library_path('/opt/homebrew/opt/llvm/lib')
            elif os.path.exists('/usr/local/opt/llvm/lib'):
                Config.set_library_path('/usr/local/opt/llvm/lib')
        return Index, CursorKind, Config

Index, CursorKind, Config = init_clang()


def load_config(config_path: str) -> Dict[str, Any]:
    """Загрузка конфигурационного файла с правилами и исключениями."""
    with open(config_path, 'r', encoding='utf-8') as f:
        return json.load(f)


def get_line_content(filepath: str, line_number: int) -> str:
    """Получение текста конкретной строки файла."""
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
            if 0 < line_number <= len(lines):
                return lines[line_number - 1].strip()
    except Exception:
        return "N/A"
    return ""


def analyze_cursor(cursor, config: Dict[str, Any], issues: List[Dict[str, Any]], filepath: str):
    """Рекурсивный анализ узлов AST-дерева."""
    if cursor.kind == CursorKind.CALL_EXPR:
        func_name = cursor.spelling
        
        if func_name in config.get("dangerous_functions", {}):
            line_num = cursor.location.line
            col_num = cursor.location.column
            line_content = get_line_content(filepath, line_num)
            
            # Проверка маркеров подавления False Positives
            ignored = any(marker in line_content for marker in config.get("ignore_comments", []))
            
            if not ignored:
                issues.append({
                    "file": filepath,
                    "line": line_num,
                    "column": col_num,
                    "function": func_name,
                    "code_snippet": line_content,
                    "recommendation": config["dangerous_functions"][func_name]
                })
                
    for child in cursor.get_children():
        analyze_cursor(child, config, issues, filepath)


def scan_path(target_path: str, config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Сканирует выбранный файл или рекурсивно обходит директорию."""
    issues = []
    index = Index.create()
    
    if os.path.isfile(target_path):
        try:
            tu = index.parse(target_path)
            analyze_cursor(tu.cursor, config, issues, target_path)
        except Exception as e:
            print(f"[!] Ошибка анализа AST {target_path}: {e}", file=sys.stderr)
        return issues

    for root, _, files in os.walk(target_path):
        if any(ignore_dir in root for ignore_dir in config.get("ignore_paths", [])):
            continue
            
        for file in files:
            if file.endswith(('.c', '.cpp', '.h', '.hpp', '.cc')):
                filepath = os.path.join(root, file)
                try:
                    tu = index.parse(filepath)
                    analyze_cursor(tu.cursor, config, issues, filepath)
                except Exception as e:
                    print(f"[!] Ошибка анализа AST {filepath}: {e}", file=sys.stderr)
                    
    return issues


def main():
    parser = argparse.ArgumentParser(description="AST-based C/C++ Static Security Analyzer (SDL/SAST)")
    parser.add_argument("path", help="Путь к файлу или директории для сканирования")
    parser.add_argument("--config", default="config/rules.json", help="Путь к файлу правил")
    parser.add_argument("--format", choices=["json", "html"], default="html", help="Формат итогового отчета")
    parser.add_argument("--out", default="sast_report", help="Имя итогового отчета (без расширения)")
    parser.add_argument("--exit-code", action="store_true", help="Завершать с кодом 1 при наличии уязвимостей (для CI/CD)")
    
    args = parser.parse_args()

    if not os.path.exists(args.config):
        print(f"[!] Конфигурационный файл не найден: {args.config}", file=sys.stderr)
        sys.exit(1)

    config = load_config(args.config)
    print(f"[*] Старт сканирования SAST: {args.path}")
    
    issues = scan_path(args.path, config)

    output_file = f"{args.out}.{args.format}"
    if args.format == "json":
        Reporter.save_json(issues, output_file)
    else:
        Reporter.save_html(issues, output_file)

    print(f"[+] Сканирование завершено. Обнаружено уязвимостей: {len(issues)}.")
    print(f"[+] Отчет сохранен в: {output_file}")

    if args.exit_code and len(issues) > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
