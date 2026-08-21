# Production-ready FastAPI backend Docker image
# Multi-stage build to minimize final image size

# ─── Stage 1: Dependency builder ─────────────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /app

# Install build tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libpq-dev && \
    rm -rf /var/lib/apt/lists/*

# Install pip packages directly — avoids poetry version-solver issues on Railway
# This is equivalent to what poetry would install but uses pip directly
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt --target /app/deps

# ─── Stage 2: Production image ────────────────────────────────────────────────
FROM python:3.11-slim AS production

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq-dev && \
    rm -rf /var/lib/apt/lists/*

# Security: non-root user
RUN groupadd --system app && useradd --system --gid app --no-create-home app

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /app/deps /app/deps

# Copy application code
COPY src/ ./src/
COPY alembic/ ./alembic/
COPY alembic.ini ./

# Set deps on path
ENV PYTHONPATH="/app/deps:/app"
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Run as non-root
USER app

EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD python -c "import httpx; httpx.get('http://localhost:8000/health', timeout=3)"

# Uvicorn with production settings
CMD ["python", "-m", "uvicorn", "src.api.main:app", \
     "--host", "0.0.0.0", \
     "--port", "8000", \
     "--workers", "2", \
     "--loop", "uvloop", \
     "--http", "httptools", \
     "--no-access-log", \
     "--timeout-keep-alive", "30"]
