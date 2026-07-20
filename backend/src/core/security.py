"""
Security utilities: HMAC webhook validation, JWT token creation/verification,
and Slack request signature verification.
"""

import hashlib
import hmac
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from jose import JWTError, jwt
from passlib.context import CryptContext

from src.core.config import get_settings
from src.core.logging import get_logger

settings = get_settings()
logger = get_logger(__name__)

# ── Password hashing ──────────────────────────────────────────────────────────
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


# ── JWT ───────────────────────────────────────────────────────────────────────
def create_access_token(
    subject: str,
    extra_claims: dict[str, Any] | None = None,
    expires_delta: timedelta | None = None,
) -> str:
    """Create a signed JWT access token."""
    expire = datetime.now(tz=timezone.utc) + (
        expires_delta or timedelta(minutes=settings.jwt_access_token_expire_minutes)
    )
    payload: dict[str, Any] = {
        "sub": subject,
        "exp": expire,
        "iat": datetime.now(tz=timezone.utc),
        "type": "access",
    }
    if extra_claims:
        payload.update(extra_claims)

    return jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)


def decode_access_token(token: str) -> dict[str, Any]:
    """
    Decode and validate a JWT.
    Raises jose.JWTError if invalid or expired.
    """
    return jwt.decode(
        token,
        settings.jwt_secret_key,
        algorithms=[settings.jwt_algorithm],
    )


# ── GitHub Webhook HMAC Validation ────────────────────────────────────────────
def verify_github_signature(
    payload_body: bytes,
    signature_header: str | None,
) -> bool:
    """
    Verify the X-Hub-Signature-256 header sent by GitHub.
    Uses constant-time comparison to prevent timing attacks.

    Args:
        payload_body: Raw request body bytes.
        signature_header: Value of X-Hub-Signature-256 header (e.g. 'sha256=abc...')

    Returns:
        True if valid, False otherwise.
    """
    if not signature_header:
        logger.warning("missing_github_signature_header")
        return False

    if not signature_header.startswith("sha256="):
        logger.warning("invalid_github_signature_prefix")
        return False

    expected = hmac.new(
        key=settings.github_webhook_secret.encode("utf-8"),
        msg=payload_body,
        digestmod=hashlib.sha256,
    ).hexdigest()

    received = signature_header[len("sha256="):]

    is_valid = hmac.compare_digest(expected, received)
    if not is_valid:
        logger.warning("github_signature_mismatch")
    return is_valid


# ── Slack Request Signature Verification ──────────────────────────────────────
def verify_slack_signature(
    payload_body: bytes,
    timestamp_header: str | None,
    signature_header: str | None,
    max_age_seconds: int = 300,
) -> bool:
    """
    Verify Slack's X-Slack-Signature header (v0 signing scheme).

    Args:
        payload_body: Raw request body bytes.
        timestamp_header: Value of X-Slack-Request-Timestamp header.
        signature_header: Value of X-Slack-Signature header.
        max_age_seconds: Reject requests older than this (replay protection).

    Returns:
        True if valid, False otherwise.
    """
    if not timestamp_header or not signature_header:
        logger.warning("missing_slack_signature_headers")
        return False

    try:
        req_timestamp = int(timestamp_header)
    except ValueError:
        logger.warning("invalid_slack_timestamp")
        return False

    # Replay attack protection
    if abs(time.time() - req_timestamp) > max_age_seconds:
        logger.warning("slack_request_too_old", age=abs(time.time() - req_timestamp))
        return False

    sig_basestring = f"v0:{req_timestamp}:{payload_body.decode('utf-8')}"
    expected = (
        "v0="
        + hmac.new(
            key=settings.slack_signing_secret.encode("utf-8"),
            msg=sig_basestring.encode("utf-8"),
            digestmod=hashlib.sha256,
        ).hexdigest()
    )

    is_valid = hmac.compare_digest(expected, signature_header)
    if not is_valid:
        logger.warning("slack_signature_mismatch")
    return is_valid
