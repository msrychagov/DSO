#!/usr/bin/env bash
set -euo pipefail

COMPOSE_FILE=${COMPOSE_FILE:-docker-compose.yml}
SERVICE_NAME=${SERVICE_NAME:-app}
WAIT_RETRIES=${WAIT_RETRIES:-20}
SLEEP_BETWEEN=${SLEEP_BETWEEN:-3}

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker CLI is required to run this script" >&2
  exit 1
fi

cleanup() {
  docker compose -f "$COMPOSE_FILE" down --remove-orphans >/dev/null 2>&1 || true
}

trap cleanup EXIT

echo "[+] Building container image"
docker compose -f "$COMPOSE_FILE" build --pull

echo "[+] Starting stack"
docker compose -f "$COMPOSE_FILE" up -d

container_id=$(docker compose -f "$COMPOSE_FILE" ps -q "$SERVICE_NAME")
if [[ -z "$container_id" ]]; then
  echo "Failed to start service $SERVICE_NAME" >&2
  exit 1
fi

echo "[+] Waiting for container to become healthy"
for _ in $(seq 1 "$WAIT_RETRIES"); do
  status=$(docker inspect --format='{{.State.Health.Status}}' "$container_id" 2>/dev/null || echo "starting")
  if [[ "$status" == "healthy" ]]; then
    break
  fi
  if [[ "$status" == "unhealthy" ]]; then
    docker compose -f "$COMPOSE_FILE" logs "$SERVICE_NAME"
    echo "Container became unhealthy" >&2
    exit 1
  fi
  sleep "$SLEEP_BETWEEN"
done

status=$(docker inspect --format='{{.State.Health.Status}}' "$container_id" 2>/dev/null || echo "starting")
if [[ "$status" != "healthy" ]]; then
  echo "Container did not become healthy in time (status: $status)" >&2
  exit 1
fi

echo "[+] Verifying the process user"
container_uid=$(docker compose -f "$COMPOSE_FILE" exec -T "$SERVICE_NAME" id -u)
if [[ "$container_uid" == "0" ]]; then
  echo "Service is running as root" >&2
  exit 1
fi

echo "[+] Health endpoint response"
docker compose -f "$COMPOSE_FILE" exec -T "$SERVICE_NAME" python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health'); print('Service healthy')"

echo "[+] Container hardened and verified"
