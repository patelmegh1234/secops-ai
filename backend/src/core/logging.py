"""
Structured JSON logging using structlog.
Configured for Railway/cloud environments (JSON) and local dev (colourised console).
"""

import logging
import sys
from typing import Any

import structlog
from structlog.types import EventDict, WrappedLogger

from src.core.config import get_settings

settings = get_settings()


def _add_app_context(
    logger: WrappedLogger, method_name: str, event_dict: EventDict
) -> EventDict:
    """Inject app-level metadata into every log record."""
    event_dict["app"] = settings.app_name
    event_dict["env"] = settings.app_env
    return event_dict


def _drop_color_message_key(
    logger: WrappedLogger, method_name: str, event_dict: EventDict
) -> EventDict:
    """Remove uvicorn's color_message to keep logs clean."""
    event_dict.pop("color_message", None)
    return event_dict

# Fields that may contain source code or raw payloads.
# Values longer than REDACT_THRESHOLD chars are replaced with a safe token.
_REDACT_KEYS: frozenset[str] = frozenset({
    "original_code",
    "patched_code",
    "diff",
    "diff_unified",
    "stdout",
    "stderr",
    "raw_payload",
    "vulnerable_code",
    "repatch_context",
})
_REDACT_THRESHOLD = 100


def redact_sensitive_fields(
    logger: WrappedLogger, method_name: str, event_dict: EventDict
) -> EventDict:
    """
    Strip source code and raw payloads from structured log output.

    Railway (and most cloud log aggregators) retain log data indefinitely.
    Emitting raw source code into logs is a privacy and security risk —
    it may contain secrets, proprietary algorithms, or PII embedded in
    variable names and comments.

    This processor replaces any value in _REDACT_KEYS that exceeds
    _REDACT_THRESHOLD characters with "[REDACTED: N chars]".
    """
    for key in _REDACT_KEYS:
        if key in event_dict:
            value = event_dict[key]
            if isinstance(value, str) and len(value) > _REDACT_THRESHOLD:
                event_dict[key] = f"[REDACTED: {len(value)} chars]"
            elif isinstance(value, bytes) and len(value) > _REDACT_THRESHOLD:
                event_dict[key] = f"[REDACTED: {len(value)} bytes]"
    return event_dict


def configure_logging() -> None:
    """
    Call once at application startup (in FastAPI lifespan).
    Sets up structlog with appropriate renderer based on LOG_FORMAT env var.
    """
    shared_processors: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso"),
        _add_app_context,
        _drop_color_message_key,
        redact_sensitive_fields,          # Strip source code from logs
        structlog.stdlib.ExtraAdder(),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]

    if settings.log_format == "json":
        renderer: Any = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer(colors=True)

    structlog.configure(
        processors=shared_processors + [renderer],
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, settings.log_level)
        ),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(file=sys.stdout),
        cache_logger_on_first_use=True,
    )

    # Also configure stdlib logging so uvicorn/sqlalchemy logs flow through structlog
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=getattr(logging, settings.log_level),
    )
    for noisy_logger in ("uvicorn.access", "sqlalchemy.engine"):
        logging.getLogger(noisy_logger).setLevel(logging.WARNING)


def get_logger(name: str = __name__) -> structlog.BoundLogger:
    """Return a bound structlog logger for the given module name."""
    return structlog.get_logger(name)
