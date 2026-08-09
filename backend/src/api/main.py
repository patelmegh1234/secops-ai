"""
FastAPI application factory with lifespan management, middleware stack,
and WebSocket endpoint for real-time dashboard feed.
"""

import asyncio
import json
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Any

import redis.asyncio as aioredis
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from src.api.middleware.cors import add_cors_middleware
from src.api.middleware.rate_limiter import limiter
from src.api.routers import approvals, dashboard, health, webhooks
from src.core.config import get_settings
from src.core.logging import configure_logging, get_logger
from src.database.connection import dispose_db, init_db

settings = get_settings()
logger = get_logger(__name__)

# ── Payload Size Guard ────────────────────────────────────────────────────────
# Reject webhook bodies larger than 1MB before JSON parsing.
# Prevents memory exhaustion via crafted large payloads.
_MAX_BODY_BYTES = 1 * 1024 * 1024  # 1 MB


class MaxBodySizeMiddleware:
    """ASGI middleware that enforces a hard cap on incoming request body size."""

    def __init__(self, app: FastAPI, max_bytes: int = _MAX_BODY_BYTES) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        if scope["type"] == "http":
            # Wrap receive to count bytes as they stream in
            bytes_read = 0

            async def checked_receive() -> dict:
                nonlocal bytes_read
                message = await receive()
                body_chunk = message.get("body", b"")
                bytes_read += len(body_chunk)
                if bytes_read > self.max_bytes:
                    logger.warning(
                        "webhook_payload_too_large",
                        bytes_received=bytes_read,
                        max_bytes=self.max_bytes,
                    )
                    response = JSONResponse(
                        status_code=413,
                        content={
                            "detail": (
                                f"Request body exceeds the {self.max_bytes // 1024}KB limit. "
                                "Split the payload into smaller batches."
                            )
                        },
                    )
                    await response(scope, receive, send)
                    raise RuntimeError("body_too_large")  # Abort further processing
                return message

            try:
                await self.app(scope, checked_receive, send)
            except RuntimeError as exc:
                if str(exc) != "body_too_large":
                    raise
        else:
            await self.app(scope, receive, send)


# ── WebSocket Connection Manager ──────────────────────────────────────────────
class ConnectionManager:
    """Manages active WebSocket connections for real-time dashboard feed."""

    def __init__(self) -> None:
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info("ws_client_connected", total=len(self.active_connections))

    def disconnect(self, websocket: WebSocket) -> None:
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        logger.info("ws_client_disconnected", total=len(self.active_connections))

    async def broadcast(self, message: dict[str, Any]) -> None:
        """Broadcast a JSON message to all connected dashboard clients."""
        dead: list[WebSocket] = []
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                dead.append(connection)
        for conn in dead:
            self.disconnect(conn)


ws_manager = ConnectionManager()


# ── Lifespan ──────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application startup and shutdown lifecycle."""
    configure_logging()
    logger.info(
        "secops_ai_starting",
        env=settings.app_env,
        version="0.1.0",
    )

    # Initialize database (create tables in dev; use Alembic in prod)
    if settings.is_development:
        await init_db()

    # Attach shared resources to app state
    app.state.ws_manager = ws_manager
    app.state.redis = aioredis.from_url(settings.redis_url, decode_responses=True)

    logger.info("secops_ai_ready", port=settings.app_port)
    yield

    # Shutdown
    await dispose_db()
    await app.state.redis.aclose()
    logger.info("secops_ai_shutdown")


# ── App Factory ───────────────────────────────────────────────────────────────
def create_app() -> FastAPI:
    app = FastAPI(
        title="SecOps-AI API",
        description=(
            "Autonomous event-driven security operations agent. "
            "Ingests vulnerability alerts, generates verified patches, "
            "and orchestrates human-in-the-loop GitHub PR creation."
        ),
        version="0.1.0",
        docs_url="/docs" if not settings.is_production else None,
        redoc_url="/redoc" if not settings.is_production else None,
        openapi_url="/openapi.json" if not settings.is_production else None,
        lifespan=lifespan,
    )

    # ── Middleware (order matters — outermost first) ───────────────────────
    add_cors_middleware(app)
    app.add_middleware(GZipMiddleware, minimum_size=1000)
    # Reject payloads > 1MB before JSON parsing (prevents memory exhaustion)
    app.add_middleware(MaxBodySizeMiddleware, max_bytes=_MAX_BODY_BYTES)  # type: ignore

    # ── Rate Limiter ──────────────────────────────────────────────────────
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)  # type: ignore

    # ── Routers ───────────────────────────────────────────────────────────
    app.include_router(health.router, tags=["Health"])
    app.include_router(webhooks.router, prefix="/webhooks", tags=["Webhooks"])
    app.include_router(approvals.router, prefix="/slack", tags=["Slack"])
    app.include_router(dashboard.router, prefix="/api", tags=["Dashboard"])

    # ── WebSocket Feed ────────────────────────────────────────────────────
    @app.websocket("/ws/feed")
    async def websocket_feed(websocket: WebSocket) -> None:
        """
        Real-time event stream for the dashboard.
        Clients connect here to receive live vulnerability status updates.
        """
        await ws_manager.connect(websocket)
        try:
            # Subscribe to Redis pub/sub channel
            redis: aioredis.Redis = websocket.app.state.redis
            pubsub = redis.pubsub()
            await pubsub.subscribe("secops:events")

            async def redis_reader() -> None:
                async for message in pubsub.listen():
                    if message["type"] == "message":
                        try:
                            data = json.loads(message["data"])
                            await websocket.send_json(data)
                        except Exception:
                            pass

            reader_task = asyncio.create_task(redis_reader())

            # Keep connection alive; client can send ping messages
            while True:
                try:
                    await asyncio.wait_for(websocket.receive_text(), timeout=30.0)
                except asyncio.TimeoutError:
                    await websocket.send_json({"type": "ping"})

        except WebSocketDisconnect:
            pass
        finally:
            ws_manager.disconnect(websocket)
            try:
                await pubsub.unsubscribe("secops:events")
                await pubsub.aclose()
            except Exception:
                pass

    return app


app = create_app()
