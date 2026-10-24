# Mini SOC Lab 🔎

[![CI](https://img.shields.io/badge/CI-ruff%20%C3%97%20mypy%20%C3%97%20pytest%20%C3%97%20Sigma-3ecfb2)](.github/workflows/ci.yml)
![Python](https://img.shields.io/badge/Python-3.10%2B-6db3f2)
![Code style](https://img.shields.io/badge/code%20style-ruff-ffb454)
![Type checking](https://img.shields.io/badge/mypy-strict-9aa7b6)

Учебный проект по **детектированию атак и первичному расследованию
инцидентов** в духе работы SOC-аналитика L1/L2. Мультиформатный анализатор
с MITRE ATT&CK маппингом, Sigma-правилами и playbook по реагированию.

> ⚠️ Все события синтетические (резервные IP, домены `.test`, маркеры
> `REDACTED_DEMO`). Проект не подключается к SIEM и не ведёт мониторинг
> реальной инфраструктуры.

## Что анализирует проект

| Источник | Формат | Детекции |
|---|---|---|
| 🪟 **Windows** | JSONL Security/Sysmon | brute force (4625) → успешный вход, PowerShell `-EncodedCommand`, LOLBins (`certutil`, `bitsadmin`, `mshta`, `rundll32`), запуск из Temp/Public/AppData,.office-процесс → script interpreter (макродроппер), C2-подобные соединения |
| 🌐 **Web** | nginx `access.log` combined | SQLi-маркеры в URL, path traversal, сканирование (масс-404 + scanner UA), brute force логина |
| 🐧 **Linux** | syslog `auth.log` | sshd password brute force, success-after-failures, отказы sudo |

Каждая находка содержит: severity, техники MITRE ATT&CK, evidence-обоснование,
временной интервал и пометку, что требуется валидация аналитиком.

## Quick start

```bash
# установка
python -m pip install -e ".[dev]"

# анализ всех трёх источников (JSON в stdout)
mini-soc-lab analyze

# самодостаточный HTML-отчёт (дашборд: карточки, timeline, bar-charts,
# переключатели темы и языка EN/РУ — встроенные, без внешних зависимостей)
mini-soc-lab analyze --format html --output analysis/generated-report.html

# один источник или свой порог
mini-soc-lab analyze --only windows --threshold 2

# тесты (32 теста, включая false-positive корпус)
python -m pytest
```

## MITRE ATT&CK Coverage

| Technique | Name | Tactic |
|---|---|---|
| T1110 / T1110.001 | Brute Force / Password Guessing | Credential Access |
| T1078 / T1078.003 | Valid Accounts / Local Accounts | Defense Evasion |
| T1059 / T1059.001 | Command and Scripting Interpreter / PowerShell | Execution |
| T1204 | User Execution | Execution |
| T1105 | Ingress Tool Transfer | Command and Control |
| T1218 | System Binary Proxy Execution | Defense Evasion |
| T1036 | Masquerading | Defense Evasion |
| T1027 | Obfuscated Files or Information | Defense Evasion |
| T1071 | Application Layer Protocol | Command and Control |
| T1485 / T1490 | Data Destruction / Inhibit System Recovery | Impact |
| T1190 | Exploit Public-Facing Application | Initial Access |
| T1595.002 | Vulnerability Scanning | Reconnaissance |
| T1548 | Abuse Elevation Control Mechanism | Privilege Escalation |

## Sigma-правила

6 правил в `sigma-rules/` покрывают ключевые детекции и проходят валидацию
pySigma в CI (`sigma check`). Правила — прототипы для конвертации в целевой
SIEM-бэкенд через `sigma-cli`.

## Структура проекта

```text
mini-soc-lab/
├── pyproject.toml                # пакет, конфиги ruff/mypy/pytest
├── src/mini_soc_lab/
│   ├── cli.py                    # команда analyze
│   ├── loaders.py                # JSONL + nginx + syslog парсеры
│   ├── models.py                 # Finding / MitreRef
│   ├── mitre.py                  # MITRE ATT&CK справочник
│   ├── detectors/                # windows.py / web.py / linux.py
│   └── report.py                 # JSON + HTML отчёты
├── tests/                        # позитивные тесты + false-positive корпус
├── logs/                         # синтетические данные
├── sigma-rules/                  # 6 правил (проверены sigma check)
├── analysis/
│   ├── incident-report.md        # учебный отчёт об инциденте
│   └── playbook-brute-force.md   # playbook реагирования
├── scripts/
│   └── generate_datasets.py      # детерминированный генератор данных
└── .github/workflows/ci.yml      # ruff + mypy + pytest + sigma check
```

## Тесты на ложные срабатывания

Значимая часть тестового набора — **FP-корпус**: легитимная административная
активность, единичные ошибки пароля, успешные входы с других IP, обычные пути
и команды не дают находок. Это показывает, что детекции сбалансированы между
чувствительностью и шумом.

## Воспроизводимость и безопасность

- Данные детерминированно генерируются `scripts/generate_datasets.py`.
- Нет эксплуатации уязвимостей, сканирования внешних адресов, вредоносных файлов.
- Ограничения детектирования зафиксированы в отчёте (`limitations`) и в README.

## Возможные улучшения

- Парсер EVTX на основе проверенной библиотеки;
- Подключение учебного стенда Wazuh/Elastic;
- Анализ учебного PCAP (tshark/Wireshark) — место подготовлено в `pcaps/`;
- Проверка Sigma-правил на целевом бэкенде (Elasticsearch / Splunk / Loki).
