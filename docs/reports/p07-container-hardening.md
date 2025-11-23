# P07 — Отчёт по контейнеризации и харднингу

## Образ
- **База:** `python:3.12.8-slim` (патченный Debian 12) + пин `pip==24.2`/`setuptools==78.1.1` для воспроизводимых сборок.
- **Сборка:** многостадийный Dockerfile — builder ставит dev-зависимости, гоняет `pytest` и собирает wheels; runtime использует только колёса.
- **Рантайм:** в финальный слой попадают только `app/`, `src/`, `main.py`, `var/`; процесс работает под пользователем `app`.
- **Health-check:** каждые 30 секунд обращаемся к `/health` с таймаутом 5 секунд.
- **Защита уровня приложения:** все запросы с заголовком `Range` получают ответ 416 (`code=range_header_blocked`), что нивелирует DoS из CVE-2025-62727.

## Контейнерный харднинг
- В `docker-compose.yml` корневая ФС read-only, для `var/uploads` выделен отдельный bind-монтаж.
- Сбрасываем все capabilities, задаём `no-new-privileges`, `/tmp` выносим на ограниченный `tmpfs`.
- Зависимости ставятся из wheels, поэтому во время рантайма нет компиляторов и вспомогательных утилит.

## Инструменты и политики
- `hadolint.yml` описывает правила линтера (`hadolint-report.txt` в CI) и задаёт политику `failure-threshold: warning`: предупреждения фиксируются, но не ломают пайплайн.
- GitHub Actions собирает образ, запускает Hadolint и Trivy (`trivy-report.json`). При HIGH/CRITICAL Trivy возвращает `exit-code 1`, и джоб падает.
- `.trivyignore` документирует исключение для CVE-2025-62727 (Range-заголовки блокируются приложением, риск закрыт на нашем уровне).

## Локальный сценарий
```bash
# Быстрая проверка контейнера и харднинга
scripts/test_container.sh

# Ручной запуск через Docker
docker build --target runtime -t secdev-app:local .
docker run --rm -p 8000:8000 secdev-app:local
```
Скрипт ждёт, пока контейнер станет `healthy`, проверяет UID процесса и пингует `/health`, после чего делает `docker compose down`.

## Что приложить к PR
- `reports/p07/docker-history.txt` и `reports/p07/docker-images.txt`.
- Лог `reports/p07/test-container.log` (или `docker compose up`) с подтверждением статуса Healthy и non-root.
- Артефакты CI: `hadolint-report.txt`, `trivy-report.json`.
