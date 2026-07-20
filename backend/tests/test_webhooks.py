"""
Tests for webhook ingestion endpoints.
Uses httpx.AsyncClient for async test requests.
"""

import json
import hashlib
import hmac
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import AsyncClient, ASGITransport

from src.api.main import app


def sign_payload(payload: bytes, secret: str) -> str:
    """Generate X-Hub-Signature-256 header."""
    sig = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    return f"sha256={sig}"


@pytest.fixture
def trivy_payload():
    with open("tests/fixtures/trivy_payload.json") as f:
        return json.load(f)


@pytest.fixture
def bandit_payload():
    with open("tests/fixtures/bandit_payload.json") as f:
        return json.load(f)


@pytest.fixture
async def client():
    """Async test client with mocked dependencies."""
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as c:
        yield c


class TestHealthEndpoints:
    async def test_health_returns_200(self, client: AsyncClient):
        response = await client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert "uptime_seconds" in data


class TestWebhookEndpoints:
    @patch("src.api.routers.webhooks.process_vulnerability")
    async def test_trivy_webhook_valid_signature(
        self, mock_task, client: AsyncClient, trivy_payload
    ):
        """Test that a valid HMAC signature is accepted and returns 202."""
        from src.core.config import get_settings
        settings = get_settings()

        body = json.dumps(trivy_payload).encode()
        sig = sign_payload(body, settings.github_webhook_secret)

        mock_task.apply_async = MagicMock(return_value=MagicMock(id="test-task-id"))

        response = await client.post(
            "/webhooks/trivy",
            content=body,
            headers={
                "Content-Type": "application/json",
                "X-Hub-Signature-256": sig,
            },
        )

        assert response.status_code == 202
        data = response.json()
        assert data["status"] == "accepted"
        assert "task_id" in data

    async def test_trivy_webhook_missing_signature_returns_401(
        self, client: AsyncClient, trivy_payload
    ):
        """Test that missing signature returns 401."""
        response = await client.post(
            "/webhooks/trivy",
            json=trivy_payload,
        )
        assert response.status_code == 401

    async def test_trivy_webhook_invalid_signature_returns_401(
        self, client: AsyncClient, trivy_payload
    ):
        """Test that wrong signature returns 401."""
        response = await client.post(
            "/webhooks/trivy",
            json=trivy_payload,
            headers={"X-Hub-Signature-256": "sha256=invalid"},
        )
        assert response.status_code == 401

    async def test_trivy_webhook_invalid_json_returns_400(
        self, client: AsyncClient
    ):
        """Test that invalid JSON body returns 400."""
        from src.core.config import get_settings
        settings = get_settings()

        body = b"not valid json {{{"
        sig = sign_payload(body, settings.github_webhook_secret)

        response = await client.post(
            "/webhooks/trivy",
            content=body,
            headers={
                "Content-Type": "application/json",
                "X-Hub-Signature-256": sig,
            },
        )
        assert response.status_code == 400

    async def test_github_webhook_ignores_non_security_events(
        self, client: AsyncClient
    ):
        """Test that non-security GitHub events are ignored (200, not 202)."""
        from src.core.config import get_settings
        settings = get_settings()

        body = json.dumps({"action": "push"}).encode()
        sig = sign_payload(body, settings.github_webhook_secret)

        response = await client.post(
            "/webhooks/github",
            content=body,
            headers={
                "Content-Type": "application/json",
                "X-Hub-Signature-256": sig,
                "X-GitHub-Event": "push",
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ignored"
