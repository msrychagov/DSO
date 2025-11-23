# syntax=docker/dockerfile:1.7-labs
ARG PIP_VERSION=24.2
ARG SETUPTOOLS_VERSION=78.1.1
FROM python:3.12.8-slim AS base
ARG PIP_VERSION
ARG SETUPTOOLS_VERSION
RUN apt-get update \
    && apt-get upgrade -y \
    && rm -rf /var/lib/apt/lists/* \
    && python -m pip install --no-cache-dir --upgrade pip==${PIP_VERSION} setuptools==${SETUPTOOLS_VERSION}
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

FROM base AS builder
WORKDIR /app

COPY requirements.txt ./
RUN --mount=type=cache,target=/root/.cache/pip \
    pip wheel --wheel-dir=/wheels -r requirements.txt

COPY requirements-dev.txt ./
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --no-cache-dir /wheels/* && \
    pip install --no-cache-dir -r requirements-dev.txt

COPY . .
ARG SKIP_TESTS=false
RUN if [ "$SKIP_TESTS" != "true" ]; then pytest -q --maxfail=1 --disable-warnings; fi

FROM base AS runtime
WORKDIR /app
RUN addgroup --system app && adduser --system --ingroup app app

COPY --from=builder /wheels /wheels
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install /wheels/* && \
    rm -rf /wheels

COPY --from=builder /app/app ./app
COPY --from=builder /app/src ./src
COPY --from=builder /app/main.py ./main.py
COPY --from=builder /app/var ./var

RUN chown -R app:app /app
USER app

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health')"]

ENTRYPOINT ["uvicorn", "app.main:app"]
CMD ["--host", "0.0.0.0", "--port", "8000"]
