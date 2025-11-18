# P06 Secure Coding — Evidence Pack

Этот отчёт собирает данные для чек-листа P06 (C1–C5) и описания PR `p06-secure-coding → main`.

## 1. Контроли и связи с NFR/TM

| Контроль | Файл(ы) | NFR / TM | Описание проверки |
|----------|---------|----------|-------------------|
| Строгая валидация платежей (Decimal, UTC, schema) | `src/services/payment_service.py`, `src/app/api.py` | NFR-02, NFR-10, TM R2/R8 | JSON парсится без float, типы/границы проверяются через Pydantic, даты нормализуются в UTC, ошибки маскируются. |
| RFC 7807 + correlation_id | `src/app/api.py` | NFR-02, NFR-06, NFR-10 | Все HTTP ошибки идут через `_problem_response`, логируются с `correlation_id`, security middleware добавляет заголовки. |
| Безопасные загрузки файлов (magic bytes, лимит, UUID) | `src/security/uploads.py`, `src/app/api.py` | TM R5/R6 | Эндпоинт `/api/v1/uploads` использует `secure_store` (лимит 5 МБ, PNG/JPEG сигнатуры, UUID, канонизация пути, запрет symlink). |

Дополнительно см. ADR-004 (`docs/adr/ADR-004-secure-coding-controls.md`).

## 2. Чек-лист

### C1. Исправление уязвимости
- ✅ Валидация входных данных и безопасные загрузки интегрированы в основной API (`src/app/api.py`).
- ✅ Диффы зафиксированы в ADR-004.

### C2. Тесты (позитив + негатив)
- ✅ `tests/test_payments.py` — позитив (нормализация) + 3 негативных сценария (валюта, JSON, отрицательная сумма).
- ✅ `tests/test_src_uploads.py` — позитивная загрузка + большие данные и неверная сигнатура.
- ✅ Бонус: уже существующие тесты (`tests/test_mvp.py`, `tests/test_problem_details.py`, `tests/test_rate_limiting.py`) покрывают обновлённые ответы.
- Команда:
  ```bash
  pytest
  ```
  Результат: `69 passed`.

### C3. Валидация / ошибки / логирование
- ✅ `_problem_response` добавляет `code`, `correlation_id`, маскирует PII в `detail/extras` (`_mask_pii` в `src/app/api.py`).
- ✅ Платёжный сервис сериализует ошибки без поля `input`, чтобы не показывать исходный payload (`src/services/payment_service.py`).
- ✅ Audit logger (`security_service.audit_logger`) получает события `payment_recorded` и `file_uploaded`.

### C4. Линт/формат/quality gate
- ✅ Обновлённый `.github/workflows/ci.yml` запускает:
  - `ruff check`
  - `black --check`
  - `isort --check-only`
  - `pytest -q`
  - `pre-commit run --all-files`
  на Python 3.11 и 3.12. CI блокирует merge при ошибке любого шага.
- ✅ Конфиги лежат в `pyproject.toml`, `.ruff.toml`, `.pre-commit-config.yaml`.

### C5. Интеграция
- ✅ Контроли встроены в `src/app/api.py` (боевой сервис), а не в учебные примеры.
- ✅ Связаны с NFR/TM и задокументированы (ADR-004 + этот отчёт).

## 3. Что приложить в PR

1. Список контролей и ссылки на НФТ/Threat Model (можно копировать таблицу из раздела 1).
2. Ссылка на этот отчёт и ADR-004 как «доказательства».
3. Логи локального прогона:
   ```bash
   ruff check .
   black --check .
   isort --check-only .
   pytest
   pre-commit run --all-files
   ```
4. Скрин/ссылка на успешный GitHub Actions `CI`.

## 4. Пример описания PR (по шаблону)

```
## Описание изменений
**Что сделано:**
- добавлен PaymentService c валидацией Decimal/UTC и интеграция в /api/v1/payments;
- унифицирован RFC 7807-ответ для всех исключений + correlation_id;
- расширены secure uploads и добавлены негативные тесты;
- обновлён CI workflow (python 3.11/3.12, pytest, ruff, black, isort, pre-commit);
- ADR-004 и отчёт docs/reports/p06-secure-coding.md.

**Почему это нужно:**
- закрываем риски TM R2/R5/R6 и требования NFR-02/06/10.

**Связанная задача/Issue:** P06 Secure Coding

## Как тестировал
```bash
ruff check .
black --check .
isort --check-only .
pytest
pre-commit run --all-files
```
```

Чек-боксы шаблона отметить по результатам локальных прогонов и CI.
