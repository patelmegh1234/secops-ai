"""
Celery application configuration.
Uses Redis as both the broker and result backend.
"""

from celery import Celery

from src.core.config import get_settings

settings = get_settings()

celery_app = Celery(
    "secops_ai",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
    include=["src.workers.tasks"],
)

celery_app.conf.update(
    # ── Serialization ─────────────────────────────────────────────────────
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    # ── Timezone ──────────────────────────────────────────────────────────
    timezone="UTC",
    enable_utc=True,
    # ── Task execution ────────────────────────────────────────────────────
    task_acks_late=True,           # Ack after task completes (not before)
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,  # One task at a time per worker thread
    task_time_limit=300,           # Hard kill after 5 minutes
    task_soft_time_limit=240,      # Soft warning after 4 minutes
    # ── Retry policy ──────────────────────────────────────────────────────
    task_max_retries=settings.celery_task_max_retries,
    task_default_retry_delay=settings.celery_task_retry_delay_seconds,
    # ── Result expiry ─────────────────────────────────────────────────────
    result_expires=86400,          # 24 hours
    # ── Routing ───────────────────────────────────────────────────────────
    task_routes={
        "src.workers.tasks.process_vulnerability": {"queue": "vulnerability"},
        "src.workers.tasks.create_pull_request": {"queue": "github"},
        "src.workers.tasks.record_rejection": {"queue": "github"},
    },
    task_queues={
        "vulnerability": {"exchange": "vulnerability", "routing_key": "vulnerability"},
        "github": {"exchange": "github", "routing_key": "github"},
    },
    # ── Monitoring ────────────────────────────────────────────────────────
    worker_send_task_events=True,
    task_send_sent_event=True,
)
