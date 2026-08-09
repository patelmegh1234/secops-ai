"""
Phase 3.6 — Celery Flower configuration.

Flower is the real-time web monitor for Celery.
It shows active/failed/scheduled tasks, worker status, and queue depths.

Usage (local dev):
    cd backend
    poetry run celery -A src.workers.celery_app.celery_app flower \
        --port=5555 --basic-auth=admin:change_in_prod

Usage (Railway / Docker):
    Add FLOWER_BASIC_AUTH=admin:your_password to Railway env vars.
    Flower starts automatically from Dockerfile (see target: flower).

Endpoints:
    http://localhost:5555/          — Task monitor dashboard
    http://localhost:5555/api/tasks — JSON API for tasks
    http://localhost:5555/api/workers — JSON API for workers

Security:
    Basic auth is REQUIRED in production. Do NOT expose Flower publicly
    without authentication — it can trigger task retries and purge queues.
"""

# This file is documentation only.
# Actual Flower config is passed via CLI flags and environment variables:
#
# FLOWER_BASIC_AUTH        - "username:password" for HTTP basic auth
# FLOWER_MAX_TASKS         - Max tasks to keep in memory (default: 10000)
# FLOWER_PORT              - HTTP port (default: 5555)
# FLOWER_BROKER_API        - URL for broker API inspection
# FLOWER_PURGE_OFFLINE_WORKERS - Remove offline workers after N minutes

FLOWER_CONFIG = {
    "broker": "redis://localhost:6379/1",
    "result_backend": "redis://localhost:6379/2",
    "port": 5555,
    "basic_auth": ["admin:change_in_prod"],
    "max_tasks": 10000,
    "purge_offline_workers": 60,  # minutes
    "natural_time": True,
    "enable_events": True,
}
