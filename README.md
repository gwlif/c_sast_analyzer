#  C/C++ AST Static Security Analyzer (SAST)

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![LLVM Clang](https://img.shields.io/badge/LLVM-libclang-red)
![License](https://img.shields.io/badge/license-MIT-green)
![CI](https://img.shields.io/badge/CI-GitHub_Actions-brightgreen)

Легковесный статический анализатор защищенности исходного кода C/C++, построенный на базе **Clang Abstract Syntax Tree (AST)**. Предназначен для интеграции в процессы **SDL / DevSecOps** на ранних этапах разработки (Shift-Left Security).

В отличие от регулярок (`grep`), инструмент парсит синтаксическое дерево через `libclang`, что предотвращает ложные срабатывания в закомментированном коде, строковых литералах и переменных.

## ✨ Возможности

-  **Clang AST Analysis**: Парсинг синтаксического дерева C/C++ через `libclang`.
-  **База правил**: Поиск вызовов `strcpy`, `sprintf`, `gets`, `system`, `alloca`, `scanf`.
-  **False Positives Handling**: Поддержка маркерных комментариев (`// ignore-sec`) и список исключаемых директорий (`tests/`, `vendor/`).
-  **Отчетность**: Генерация стилизованных HTML и JSON отчетов.
-  **DevSecOps Ready**: Флаг `--exit-code` для интеграции в CI/CD билд-пайплайны.

##  Быстрый старт

### 1. Установка зависимостей

#### macOS
```bash
brew install llvm
pip install -r requirements.txt
```

#### Ubuntu / Debian
```bash
sudo apt-get update && sudo apt-get install -y libclang-dev
pip install -r requirements.txt
```

### 2. Запуск сканирования

Запуск анализа на тестовом примере с генерацией HTML-отчета:

```bash
python src/analyzer.py samples/ --config config/rules.json --format html --out sast_report
```

Для использования в CI/CD (завершение с кодом ошибки `1` при обнаружении проблем):

```bash
python src/analyzer.py src/ --exit-code
```

### 3. Запуск Unit-тестов

```bash
pytest tests/
```

## 📄 Лицензия

Распространяется под лицензией [MIT](LICENSE).
