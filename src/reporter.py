import json
from typing import List, Dict, Any

class Reporter:
    @staticmethod
    def save_json(issues: List[Dict[str, Any]], output_path: str) -> None:
        """Сохраняет результаты анализа в формате JSON."""
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(issues, f, indent=4, ensure_ascii=False)

    @staticmethod
    def save_html(issues: List[Dict[str, Any]], output_path: str) -> None:
        """Генерирует автономный и наглядный HTML-отчет по уязвимостям."""
        html = """<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset='utf-8'>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SAST Security Scan Report</title>
    <style>
        :root {
            --bg-color: #f8f9fa;
            --card-bg: #ffffff;
            --text-color: #212529;
            --border-color: #dee2e6;
            --primary: #0d6efd;
            --danger: #dc3545;
            --success: #198754;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            margin: 0;
            padding: 40px 20px;
            background-color: var(--bg-color);
            color: var(--text-color);
        }
        .container {
            max-width: 1100px;
            margin: 0 auto;
            background: var(--card-bg);
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.08);
        }
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 2px solid var(--border-color);
            padding-bottom: 15px;
            margin-bottom: 25px;
        }
        h1 { margin: 0; font-size: 24px; color: #1a252f; }
        .badge {
            padding: 8px 16px;
            border-radius: 20px;
            font-weight: 600;
            font-size: 14px;
        }
        .badge-success { background-color: #d1e7dd; color: #0f5132; }
        .badge-danger { background-color: #f8d7da; color: #842029; }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }
        th, td {
            border: 1px solid var(--border-color);
            padding: 12px 15px;
            text-align: left;
        }
        th {
            background-color: #2c3e50;
            color: #ffffff;
            font-weight: 600;
        }
        tr:nth-child(even) { background-color: #f8f9fa; }
        .func-name {
            color: var(--danger);
            font-weight: bold;
            font-family: "SFMono-Regular", Consolas, monospace;
        }
        code {
            background-color: #e9ecef;
            padding: 3px 6px;
            border-radius: 4px;
            font-family: "SFMono-Regular", Consolas, monospace;
            font-size: 13px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Static Application Security Testing (SAST) Report</h1>
"""
        if not issues:
            html += '            <span class="badge badge-success">0 Vulnerabilities Found</span>\n'
            html += '        </div>\n        <p style="color: #0f5132; font-size: 16px;">Уязвимостей не обнаружено. Код соответствует требованиям базового статического анализа.</p>\n'
        else:
            html += f'            <span class="badge badge-danger">{len(issues)} Issues Detected</span>\n'
            html += '        </div>\n'
            html += '        <table>\n'
            html += '            <thead>\n'
            html += '                <tr>\n'
            html += '                    <th>Файл</th>\n'
            html += '                    <th>Позиция</th>\n'
            html += '                    <th>Функция</th>\n'
            html += '                    <th>Фрагмент кода</th>\n'
            html += '                    <th>Рекомендация по исправлению</th>\n'
            html += '                </tr>\n'
            html += '            </thead>\n'
            html += '            <tbody>\n'
            for issue in issues:
                html += '                <tr>\n'
                html += f'                    <td><code>{issue["file"]}</code></td>\n'
                html += f'                    <td>{issue["line"]}:{issue["column"]}</td>\n'
                html += f'                    <td class="func-name">{issue["function"]}</td>\n'
                html += f'                    <td><code>{issue["code_snippet"]}</code></td>\n'
                html += f'                    <td>{issue["recommendation"]}</td>\n'
                html += '                </tr>\n'
            html += '            </tbody>\n        </table>\n'

        html += """    </div>
</body>
</html>"""

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)
