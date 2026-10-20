# Формат SARIF и интеграция с CI

Анализатор может создавать отчёты JSON, HTML и SARIF 2.1.0. SARIF-результаты содержат стабильные идентификаторы правил, относительные пути к исходникам, координаты (строка и столбец) и фрагменты кода. Все результаты имеют уровень `warning`: срабатывание на опасной функции указывает на потенциальную проблему, но само по себе не доказывает наличие эксплуатируемой уязвимости.

## Локальный запуск

Из корня репозитория выполни:

```bash
python analyzer.py security_cases.c \
  --config config.json \
  --format sarif \
  --out security_report
```

Команда создаст `security_report.sarif`. Убедись, что файл является корректным JSON, и выведи основные метаданные:

```bash
python - <<'PY'
import json
with open("security_report.sarif", encoding="utf-8") as stream:
    report = json.load(stream)
print("Версия SARIF:", report["version"])
print("Количество находок:", len(report["runs"][0]["results"]))
PY
```

## Загрузка результатов в GitHub Code Scanning (необязательно)

Workflow `.github/workflows/tests.yml` запускает тесты и реальное пробное сканирование с `libclang`, а затем сохраняет SARIF-файл как артефакт GitHub Actions. Само сохранение артефакта **не публикует результаты в Code Scanning**.

Если репозиторий поддерживает GitHub Code Scanning, можно отдельно загрузить SARIF. Для этого предоставь разрешение `security-events: write` и добавь шаг после генерации `security_report.sarif`:

```yaml
permissions:
  contents: read
  security-events: write

# После генерации security_report.sarif:
- name: Загрузить SARIF в GitHub Code Scanning
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: security_report.sarif
```

Перед включением шага проверь доступность Code Scanning для репозитория и настройки разрешений. Набор unit-тестов использует синтетические AST-объекты для детерминированной проверки пограничных случаев; отдельный CI smoke test проверяет работу установленного `libclang` на `security_cases.c`.
