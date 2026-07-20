"""CORS middleware with strict origin allowlist from settings."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from src.core.config import get_settings

settings = get_settings()


def add_cors_middleware(app: FastAPI) -> None:
    """
    Attach CORSMiddleware with strict origin allowlist.
    Origins are read from ALLOWED_ORIGINS env var (comma-separated).
    Wildcards (*) are never permitted.
    """
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
        allow_headers=[
            "Authorization",
            "Content-Type",
            "X-Hub-Signature-256",
            "X-Slack-Signature",
            "X-Slack-Request-Timestamp",
        ],
        expose_headers=["X-Request-ID"],
        max_age=600,  # preflight cache 10 min
    )
