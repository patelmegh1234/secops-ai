# Production-ready FastAPI backend Docker image
# Multi-stage build to minimize final image size

# ─── Stage 1: Dependency builder ─────────────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /app

# Install Poetry
RUN pip install --no-cache-dir poetry==1.8.3

# Copy dependency files first (layer caching)
COPY pyproject.toml poetry.lock* ./

# Install deps into a virtual env (no-dev)
RUN poetry config virtualenvs.in-project true \
    && poetry install --only=main --no-root --no-interaction --no-ansi

# ─── Stage 2: Production image ────────────────────────────────────────────────
FROM python:3.11-slim AS production

# Security: non-root user
RUN groupadd --system app && useradd --system --gid app --no-create-home app

WORKDIR /app

# Copy virtual environment from builder
COPY --from=builder /app/.venv /app/.venv

# Copy application code
COPY src/ ./src/
COPY alembic/ ./alembic/
COPY alembic.ini ./

# Set virtualenv on PATH
ENV PATH="/app/.venv/bin:$PATH"
ENV PYTHONPATH="/app"
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Run as non-root
USER app

EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import httpx; httpx.get('http://localhost:8000/health', timeout=3)"

# Uvicorn with production settings
CMD ["uvicorn", "src.api.main:app", \
     "--host", "0.0.0.0", \
     "--port", "8000", \
     "--workers", "2", \
     "--loop", "uvloop", \
     "--http", "httptools", \
     "--no-access-log", \
     "--timeout-keep-alive", "30"]
