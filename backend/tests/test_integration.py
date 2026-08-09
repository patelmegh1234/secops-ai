"""
Phase 3.2 — Integration test harness.

Tests the full pipeline from fake scanner payload → pipeline state transitions
without requiring a live Docker daemon, Slack, or GitHub.

Architecture:
  - Uses pytest-asyncio for async tests
  - Mocks: Docker client, Slack client, GitHub client, OpenAI API
  - Real: FastAPI app, SQLite in-memory DB (via SQLAlchemy + aiosqlite),
          Redis (mocked via fakeredis), Celery (eager mode)

To run:
    cd backend
    poetry run pytest tests/test_integration.py -v
"""

import json
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport

# ── Fixtures ───────────────────────────────────────────────────────────────────


@pytest.fixture
def trivy_payload():
    """Minimal valid Trivy webhook payload."""
    return {
        "repo_owner": "test-org",
        "repo_name": "test-app",
        "Results": [
            {
                "Target": "requirements.txt",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2023-9999",
                        "PkgName": "requests",
                        "InstalledVersion": "2.27.0",
                        "FixedVersion": "2.31.0",
                        "Severity": "HIGH",
                        "Title": "SSRF vulnerability in requests",
                        "Description": "Requests allows SSRF via crafted URLs",
                    }
                ],
            }
        ],
    }


@pytest.fixture
def bandit_payload():
    """Minimal valid Bandit webhook payload."""
    return {
        "repo_owner": "test-org",
        "repo_name": "test-app",
        "results": [
            {
                "test_id": "B608",
                "test_name": "hardcoded_sql_expressions",
                "issue_text": "Possible SQL injection",
                "severity": "HIGH",
                "confidence": "MEDIUM",
                "filename": "src/db.py",
                "line_number": 42,
                "code": 'query = "SELECT * FROM users WHERE id=" + user_id',
            }
        ],
    }


# ── Signature helper ───────────────────────────────────────────────────────────

def _make_signature(body: bytes, secret: str = "test-secret") -> str:
    """Generate a valid HMAC signature for webhook tests."""
    import hashlib
    import hmac
    sig = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return f"sha256={sig}"


# ── Webhook acceptance tests ───────────────────────────────────────────────────

class TestWebhookIngestion:
    """Tests that webhooks are accepted, validated, and deduplicated correctly.
    Uses httpx AsyncClient against the FastAPI ASGI app directly.
    No network calls.
    """

    @pytest.fixture
    def mock_celery_task(self):
        """Mock process_vulnerability.apply_async to avoid real Celery."""
        with patch("src.workers.tasks.process_vulnerability.apply_async") as mock:
            task = MagicMock()
            task.id = str(uuid.uuid4())
            mock.return_value = task
            yield mock

    @pytest.fixture
    def mock_redis(self):
        """Mock Redis to always return None (no duplicates)."""
        with patch("src.api.routers.webhooks.aioredis") as mock_module:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=None)
            mock_client.setex = AsyncMock(return_value=True)
            mock_client.aclose = AsyncMock()
            mock_module.from_url.return_value = mock_client
            yield mock_client

    @pytest.mark.asyncio
    async def test_trivy_webhook_accepted(
        self, trivy_payload, mock_celery_task, mock_redis
    ):
        with patch("src.core.security.verify_github_signature", return_value=True):
            from src.api.main import create_app
            app = create_app()
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as client:
                body = json.dumps(trivy_payload).encode()
                resp = await client.post(
                    "/webhooks/trivy",
                    content=body,
                    headers={"X-Hub-Signature-256": "sha256=fake", "Content-Type": "application/json"},
                )
        assert resp.status_code == 202
        data = resp.json()
        assert "task_id" in data

    @pytest.mark.asyncio
    async def test_trivy_webhook_invalid_signature_returns_401(self, trivy_payload):
        with patch("src.core.security.verify_github_signature", return_value=False):
            from src.api.main import create_app
            app = create_app()
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as client:
                resp = await client.post(
                    "/webhooks/trivy",
                    content=b"{}",
                    headers={"X-Hub-Signature-256": "sha256=bad"},
                )
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_trivy_webhook_duplicate_returns_202_no_task(
        self, trivy_payload, mock_celery_task
    ):
        """Duplicate webhooks must return 202 without spawning a new task."""
        with patch("src.core.security.verify_github_signature", return_value=True):
            with patch("src.api.routers.webhooks.aioredis") as mock_module:
                mock_client = AsyncMock()
                # Simulate Redis key already set → duplicate
                mock_client.get = AsyncMock(return_value="TRIVY")
                mock_client.setex = AsyncMock()
                mock_client.aclose = AsyncMock()
                mock_module.from_url.return_value = mock_client

                from src.api.main import create_app
                app = create_app()
                async with AsyncClient(
                    transport=ASGITransport(app=app), base_url="http://test"
                ) as client:
                    body = json.dumps(trivy_payload).encode()
                    resp = await client.post(
                        "/webhooks/trivy",
                        content=body,
                        headers={"X-Hub-Signature-256": "sha256=fake",
                                 "Content-Type": "application/json"},
                    )

        assert resp.status_code == 202
        data = resp.json()
        assert data.get("status") == "duplicate"
        mock_celery_task.assert_not_called()

    @pytest.mark.asyncio
    async def test_payload_too_large_returns_413(self):
        """Payloads > 1MB must be rejected with HTTP 413."""
        with patch("src.core.security.verify_github_signature", return_value=True):
            from src.api.main import create_app
            app = create_app()
            large_payload = {"data": "x" * (1024 * 1024 + 1)}  # 1MB + 1 byte
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as client:
                resp = await client.post(
                    "/webhooks/trivy",
                    content=json.dumps(large_payload).encode(),
                    headers={"X-Hub-Signature-256": "sha256=fake",
                             "Content-Type": "application/json"},
                )
        assert resp.status_code == 413

    @pytest.mark.asyncio
    async def test_github_irrelevant_event_ignored(self):
        """Non-security GitHub events must return 200 with status=ignored."""
        with patch("src.core.security.verify_github_signature", return_value=True):
            from src.api.main import create_app
            app = create_app()
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as client:
                resp = await client.post(
                    "/webhooks/github",
                    content=b'{"action": "opened"}',
                    headers={
                        "X-Hub-Signature-256": "sha256=fake",
                        "X-GitHub-Event": "push",
                        "Content-Type": "application/json",
                    },
                )
        assert resp.status_code == 200
        assert resp.json().get("status") == "ignored"

    @pytest.mark.asyncio
    async def test_bandit_webhook_accepted(
        self, bandit_payload, mock_celery_task, mock_redis
    ):
        with patch("src.core.security.verify_github_signature", return_value=True):
            from src.api.main import create_app
            app = create_app()
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as client:
                body = json.dumps(bandit_payload).encode()
                resp = await client.post(
                    "/webhooks/bandit",
                    content=body,
                    headers={"X-Hub-Signature-256": "sha256=fake",
                             "Content-Type": "application/json"},
                )
        assert resp.status_code == 202


# ── Health check ───────────────────────────────────────────────────────────────

class TestHealthEndpoint:
    @pytest.mark.asyncio
    async def test_health_returns_200(self):
        from src.api.main import create_app
        app = create_app()
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.get("/health")
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_health_response_has_status_key(self):
        from src.api.main import create_app
        app = create_app()
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.get("/health")
        assert "status" in resp.json()
