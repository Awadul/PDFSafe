# syntax=docker/dockerfile:1.7
# ---------------------------------------------------------------------------
# Stage 1 - builder: compile wheels (pikepdf / yara-python need toolchain)
# ---------------------------------------------------------------------------
FROM python:3.12-slim-bookworm AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        libqpdf-dev \
        libssl-dev \
        libjpeg-dev \
        zlib1g-dev \
        libmagic1 \
        automake libtool make gcc pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY pyproject.toml README.md ./
COPY src ./src

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
# The server extra brings FastAPI, Celery, Postgres drivers and boto3. The
# desktop build deliberately installs none of these.
RUN pip install --upgrade pip setuptools wheel && pip install ".[server]"

# ---------------------------------------------------------------------------
# Stage 2 - runtime
# ---------------------------------------------------------------------------
FROM python:3.12-slim-bookworm AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/opt/venv/bin:$PATH"

RUN apt-get update && apt-get install -y --no-install-recommends \
        libqpdf29 \
        libmagic1 \
        curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 1001 pdfsafe \
    && useradd --system --uid 1001 --gid pdfsafe --create-home pdfsafe

COPY --from=builder /opt/venv /opt/venv

WORKDIR /app
COPY --chown=pdfsafe:pdfsafe src ./src
COPY --chown=pdfsafe:pdfsafe migrations ./migrations
COPY --chown=pdfsafe:pdfsafe alembic.ini ./alembic.ini

RUN mkdir -p /app/var/uploads /app/var/watch && chown -R pdfsafe:pdfsafe /app/var

USER pdfsafe
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://localhost:8000/health/live || exit 1

CMD ["uvicorn", "pdfsafe.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
