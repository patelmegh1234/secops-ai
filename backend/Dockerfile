# GuardMind Backend — Production Docker Image
# Pure pip-based build. NO POETRY. Uses requirements.txt directly.
#
# This intentionally avoids Poetry to bypass the crewai Python version
# constraint resolution issue that fails on Railway.
#
# Issue #1 fix: https://github.com/patelmegh1234/secops-ai/issues/1

# ─── Stage 1: Dependency builder ──────────────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /app

# Install build tools needed for native extensions (asyncpg, etc.)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Upgrade pip first
RUN pip install --no-cache-dir --upgrade pip

# Copy ONLY requirements.txt — do NOT copy pyproject.toml or poetry.lock
# This prevents any Poetry auto-detection by downstream tools
COPY requirements.txt ./

# Install all dependencies with pip directly into /app/deps
# No Poetry involved anywhere in this step
RUN pip install --no-cache-dir -r requirements.txt --target /app/deps

# ─── Stage 2: Production image ────────────────────────────────────────────────
FROM python:3.11-slim AS production

# Only runtime native library needed
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Security: run as non-root
RUN groupadd --system app && useradd --system --gid app --no-create-home app

WORKDIR /app

# Copy installed packages from builder stage
COPY --from=builder /app/deps /app/deps

# Copy application source code
COPY src/ ./src/
COPY alembic/ ./alembic/
COPY alembic.ini ./

# Python path: check /app/deps first, then /app (for src/ imports)
ENV PYTHONPATH="/app/deps:/app"
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Run as non-root user
USER app

EXPOSE 8000

# Docker-native health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=45s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health', timeout=3)" || exit 1

# Start uvicorn with production settings
CMD ["python", "-m", "uvicorn", "src.api.main:app", \
     "--host", "0.0.0.0", \
     "--port", "8000", \
     "--workers", "2", \
     "--loop", "uvloop", \
     "--http", "httptools", \
     "--no-access-log", \
     "--timeout-keep-alive", "30"]
