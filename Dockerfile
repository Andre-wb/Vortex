# ══════════════════════════════════════════════════════════════════════════════
# VORTEX Chat — Multi-stage Production Dockerfile
# ══════════════════════════════════════════════════════════════════════════════

# ── Stage 1: Builder ─────────────────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

# System deps for cryptography and Pillow
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    libmagic1 \
    libjpeg62-turbo-dev \
    libwebp-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


# ── Stage 2: Production ─────────────────────────────────────────────────────
FROM python:3.12-slim AS production

# Labels
LABEL maintainer="Vortex Team"
LABEL description="Vortex Chat — 100% decentralized P2P messenger"
LABEL version="5.0.0"

# Non-root user for security
RUN groupadd -r vortex && useradd -r -g vortex -d /app -s /sbin/nologin vortex

# Runtime deps only
RUN apt-get update && apt-get install -y --no-install-recommends \
    libmagic1 \
    libjpeg62-turbo \
    libwebp7 \
    curl \
    tini \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy installed Python packages from builder
COPY --from=builder /install /usr/local

# Copy application code
COPY app/ ./app/
COPY static/ ./static/
COPY templates/ ./templates/
COPY node_setup/ ./node_setup/
COPY run.py .
COPY requirements.txt .
COPY alembic.ini .
COPY alembic/ ./alembic/

# Create directories with correct permissions
RUN mkdir -p uploads/avatars uploads/room_avatars uploads/space_avatars uploads/stickers \
    keys certs logs \
    && chown -R vortex:vortex /app

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:${PORT:-9000}/health || exit 1

# Switch to non-root user
USER vortex

# Environment defaults
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    ENVIRONMENT=production \
    HOST=0.0.0.0 \
    PORT=9000 \
    LOG_FORMAT=json \
    LOG_LEVEL=INFO

EXPOSE ${PORT:-9000}

# Use tini as init system for proper signal handling
ENTRYPOINT ["tini", "--"]

# Default command: run with gunicorn for production
CMD ["python", "-m", "gunicorn", \
     "app.main:app", \
     "--worker-class", "uvicorn.workers.UvicornWorker", \
     "--workers", "1", \
     "--bind", "0.0.0.0:9000", \
     "--timeout", "120", \
     "--graceful-timeout", "30", \
     "--access-logfile", "-", \
     "--error-logfile", "-"]


# ── Stage 3: Development ────────────────────────────────────────────────────
FROM production AS development

USER root

# Dev dependencies
RUN pip install --no-cache-dir \
    pytest pytest-asyncio pytest-cov pytest-timeout \
    ruff bandit pre-commit mypy

USER vortex

ENV ENVIRONMENT=development \
    LOG_FORMAT=console \
    LOG_LEVEL=DEBUG

CMD ["python", "run.py"]
