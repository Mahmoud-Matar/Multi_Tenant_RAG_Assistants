"""Authentication security primitives shared by the FastAPI routes."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import secrets
import smtplib
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from urllib.parse import urlencode
from uuid import uuid4

import jwt
from fastapi import HTTPException, Request, status

from .database import connect


LOGGER = logging.getLogger(__name__)
AUTH_ISSUER = os.getenv("AUTH_JWT_ISSUER", "atlas-auth")
AUTH_AUDIENCE = os.getenv("AUTH_JWT_AUDIENCE", "atlas-web")
AUTH_KEY_ID = os.getenv("AUTH_KEY_ID", "primary")
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "http://127.0.0.1:8000").rstrip("/")
KNOWN_SECRET_MARKERS = (
    "replace-with",
    "change-me",
    "changeme",
    "your-secret",
    "example-secret",
    "dev-secret",
)


def validate_signing_secret(value: str | None, *, name: str = "AUTH_SECRET_KEY") -> str:
    if not value:
        raise RuntimeError(f"{name} is not configured in .env")
    lowered = value.casefold().strip()
    if len(value.encode("utf-8")) < 32:
        raise RuntimeError(f"{name} must contain at least 32 bytes.")
    if any(marker in lowered for marker in KNOWN_SECRET_MARKERS):
        raise RuntimeError(f"{name} contains a known placeholder value.")
    if len(set(value)) < 12:
        raise RuntimeError(f"{name} does not contain enough character diversity.")
    return value


AUTH_SECRET = validate_signing_secret(os.getenv("AUTH_SECRET_KEY"))


def _load_key_ring() -> dict[str, str]:
    keys = {AUTH_KEY_ID: AUTH_SECRET}
    raw = os.getenv("AUTH_PREVIOUS_KEYS", "").strip()
    if not raw:
        return keys
    try:
        previous = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError("AUTH_PREVIOUS_KEYS must be a JSON object of key IDs to secrets.") from exc
    if not isinstance(previous, dict):
        raise RuntimeError("AUTH_PREVIOUS_KEYS must be a JSON object.")
    for key_id, secret in previous.items():
        if not isinstance(key_id, str) or not key_id.strip() or not isinstance(secret, str):
            raise RuntimeError("AUTH_PREVIOUS_KEYS contains an invalid key entry.")
        keys[key_id] = validate_signing_secret(secret, name=f"AUTH_PREVIOUS_KEYS[{key_id}]")
    return keys


AUTH_KEYS = _load_key_ring()


def request_ip(request: Request) -> str:
    if os.getenv("AUTH_TRUST_PROXY", "false").lower() == "true":
        forwarded = request.headers.get("x-forwarded-for", "").split(",", 1)[0].strip()
        if forwarded:
            return forwarded[:64]
    return (request.client.host if request.client else "unknown")[:64]


def _subject_hash(value: str) -> str:
    return hmac.new(
        AUTH_SECRET.encode("utf-8"), value.casefold().encode("utf-8"), hashlib.sha256
    ).hexdigest()


def enforce_rate_limit(
    *, action: str, subject: str, limit: int, window_seconds: int, block_seconds: int
) -> None:
    """Consume one persistent rate-limit attempt or raise HTTP 429."""
    now = datetime.now(timezone.utc)
    subject_hash = _subject_hash(subject)
    with connect() as connection:
        row = connection.execute(
            """
            SELECT action, subject_hash, window_started_at, attempt_count, blocked_until
            FROM auth_rate_limits
            WHERE action = %s AND subject_hash = %s
            FOR UPDATE
            """,
            (action, subject_hash),
        ).fetchone()
        if row and row["blocked_until"] and row["blocked_until"] > now:
            retry_after = max(1, int((row["blocked_until"] - now).total_seconds()))
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many attempts. Try again later.",
                headers={"Retry-After": str(retry_after)},
            )
        if row is None:
            connection.execute(
                """
                INSERT INTO auth_rate_limits
                    (action, subject_hash, window_started_at, attempt_count)
                VALUES (%s, %s, %s, 1)
                """,
                (action, subject_hash, now),
            )
            return
        if row["window_started_at"] + timedelta(seconds=window_seconds) <= now:
            connection.execute(
                """
                UPDATE auth_rate_limits
                SET window_started_at = %s, attempt_count = 1, blocked_until = NULL,
                    updated_at = CURRENT_TIMESTAMP
                WHERE action = %s AND subject_hash = %s
                """,
                (now, action, subject_hash),
            )
            return
        attempts = row["attempt_count"] + 1
        blocked_until = now + timedelta(seconds=block_seconds) if attempts > limit else None
        connection.execute(
            """
            UPDATE auth_rate_limits
            SET attempt_count = %s, blocked_until = %s, updated_at = CURRENT_TIMESTAMP
            WHERE action = %s AND subject_hash = %s
            """,
            (attempts, blocked_until, action, subject_hash),
        )
        if blocked_until:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many attempts. Try again later.",
                headers={"Retry-After": str(block_seconds)},
            )


def issue_session_token(
    *, user_id: int, tenant_id: int | None, request: Request, remember: bool
) -> tuple[str, int, str]:
    now = datetime.now(timezone.utc)
    expires_in = 30 * 24 * 3600 if remember else 3600
    expires_at = now + timedelta(seconds=expires_in)
    session_id = uuid4().hex
    token = jwt.encode(
        {
            "sub": str(user_id),
            "tenant_id": tenant_id,
            "iss": AUTH_ISSUER,
            "aud": AUTH_AUDIENCE,
            "jti": session_id,
            "iat": now,
            "nbf": now,
            "exp": expires_at,
        },
        AUTH_SECRET,
        algorithm="HS256",
        headers={"kid": AUTH_KEY_ID},
    )
    with connect() as connection:
        connection.execute(
            """
            INSERT INTO auth_sessions
                (id, user_id, tenant_id, issued_at, expires_at, ip_address, user_agent)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            """,
            (
                session_id,
                user_id,
                tenant_id,
                now,
                expires_at,
                request_ip(request),
                request.headers.get("user-agent", "")[:512],
            ),
        )
    return token, expires_in, session_id


def decode_session_token(token: str) -> dict:
    try:
        header = jwt.get_unverified_header(token)
        key_id = header.get("kid")
        secret = AUTH_KEYS.get(key_id)
        if not secret:
            raise jwt.InvalidTokenError("Unknown signing key.")
        return jwt.decode(
            token,
            secret,
            algorithms=["HS256"],
            audience=AUTH_AUDIENCE,
            issuer=AUTH_ISSUER,
            options={"require": ["sub", "iss", "aud", "jti", "iat", "exp"]},
        )
    except jwt.InvalidTokenError as exc:
        raise HTTPException(status_code=401, detail="Invalid or expired session.") from exc


def create_action_token(
    *, user_id: int, purpose: str, ttl_seconds: int, requested_ip: str
) -> str:
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    with connect() as connection:
        connection.execute(
            """
            UPDATE auth_action_tokens SET used_at = CURRENT_TIMESTAMP
            WHERE user_id = %s AND purpose = %s AND used_at IS NULL
            """,
            (user_id, purpose),
        )
        connection.execute(
            """
            INSERT INTO auth_action_tokens
                (token_hash, user_id, purpose, expires_at, requested_ip)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (
                token_hash,
                user_id,
                purpose,
                datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds),
                requested_ip,
            ),
        )
    return token


def consume_action_token(token: str, purpose: str) -> dict:
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    now = datetime.now(timezone.utc)
    with connect() as connection:
        row = connection.execute(
            """
            SELECT token_hash, user_id, purpose, expires_at, used_at
            FROM auth_action_tokens WHERE token_hash = %s FOR UPDATE
            """,
            (token_hash,),
        ).fetchone()
        if (
            row is None
            or row["purpose"] != purpose
            or row["used_at"] is not None
            or row["expires_at"] <= now
        ):
            raise HTTPException(status_code=400, detail="The token is invalid or expired.")
        connection.execute(
            "UPDATE auth_action_tokens SET used_at = CURRENT_TIMESTAMP WHERE token_hash = %s",
            (token_hash,),
        )
        return row


def deliver_auth_email(*, recipient: str, subject: str, body: str) -> None:
    """Deliver through SMTP, explicitly log in console mode, or safely do nothing."""
    mode = os.getenv("AUTH_EMAIL_MODE", "disabled").lower()
    if mode == "disabled":
        LOGGER.warning("Authentication email delivery is disabled for %s.", recipient)
        return
    if mode == "console":
        LOGGER.warning("Authentication email for %s: %s\n%s", recipient, subject, body)
        return
    if mode != "smtp":
        raise RuntimeError("AUTH_EMAIL_MODE must be disabled, console, or smtp.")
    host = os.getenv("SMTP_HOST")
    sender = os.getenv("SMTP_FROM")
    if not host or not sender:
        raise RuntimeError("SMTP_HOST and SMTP_FROM are required in smtp mode.")
    message = EmailMessage()
    message["From"] = sender
    message["To"] = recipient
    message["Subject"] = subject
    message.set_content(body)
    port = int(os.getenv("SMTP_PORT", "587"))
    with smtplib.SMTP(host, port, timeout=10) as client:
        if os.getenv("SMTP_STARTTLS", "true").lower() == "true":
            client.starttls()
        username = os.getenv("SMTP_USERNAME")
        password = os.getenv("SMTP_PASSWORD")
        if username and password:
            client.login(username, password)
        client.send_message(message)


def action_url(path: str, token: str) -> str:
    return f"{PUBLIC_BASE_URL}{path}?{urlencode({'token': token})}"
