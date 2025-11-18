# SecDev Course Project

Курсовой проект по безопасной разработке (HSE SecDev 2025).

## Быстрый старт

### Установка и запуск
```bash
# Создание виртуального окружения
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\Activate.ps1

# Установка зависимостей
pip install -r requirements.txt -r requirements-dev.txt

# Настройка pre-commit хуков
pre-commit install

# Запуск приложения
uvicorn app.main:app --reload
```

Приложение будет доступно по адресу: http://localhost:8000

## Ритуал перед PR
```bash
ruff check --fix .
black .
isort .
pytest -q
pre-commit run --all-files
```

## Тесты
```bash
pytest -q
```

## CI
В репозитории настроен workflow **CI** (GitHub Actions) — required check для `main`.
Badge добавится автоматически после загрузки шаблона в GitHub.

## Контейнеры
```bash
# Хардненый образ с многостадийной сборкой
docker build --target runtime -t secdev-app:local .
docker run --rm -p 8000:8000 secdev-app:local

# Локальный стек с Docker Compose (healthcheck + read-only FS)
IMAGE_NAME=secdev-app APP_PORT=8000 docker compose up --build

# Быстрая проверка хардненга/healthcheckов
scripts/test_container.sh
```

## Эндпойнты
- `GET /health` → `{"status": "ok"}`
- `POST /items?name=...` — демо-сущность
- `GET /items/{id}`

## Формат ошибок
Все ошибки — JSON-обёртка:
```json
{
  "error": {"code": "not_found", "message": "item not found"}
}
```

См. также: `SECURITY.md`, `.pre-commit-config.yaml`, `.github/workflows/ci.yml`.
