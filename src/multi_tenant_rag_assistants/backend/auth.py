"""FastAPI application for tenant discovery and user authentication."""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from fastapi import Cookie, FastAPI, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from psycopg import errors
from pydantic import BaseModel, EmailStr, Field

from multi_tenant_rag_assistants.RAG.api import create_rag_router

from .database import connect, initialize_database
from .admin import create_admin_router
from .documents import create_document_router
from .manager import create_manager_router
from .incidents import create_incident_router
from .auth_security import (
    action_url,
    consume_action_token,
    create_action_token,
    decode_session_token,
    deliver_auth_email,
    enforce_rate_limit,
    issue_session_token,
    request_ip,
)


password_hasher = PasswordHasher()
LOGGER = logging.getLogger(__name__)
dummy_password_hash = password_hasher.hash("not-a-real-password")
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "false").lower() == "true"
ALLOWED_ORIGINS = {
    origin.strip().rstrip("/")
    for origin in os.getenv(
        "AUTH_ALLOWED_ORIGINS",
        "http://127.0.0.1:8000,http://localhost:8000,http://127.0.0.1:4173,http://localhost:4173,http://testserver",
    ).split(",")
    if origin.strip()
}


class RegistrationRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12, max_length=128)
    tenant_id: int = Field(gt=0)


class LoginRequest(BaseModel):
    identifier: str = Field(min_length=1, max_length=320)
    password: str = Field(min_length=1, max_length=128)
    remember: bool = False


class EmailRequest(BaseModel):
    email: EmailStr


class TokenRequest(BaseModel):
    token: str = Field(min_length=20, max_length=512)


class PasswordResetRequest(TokenRequest):
    new_password: str = Field(min_length=12, max_length=128)


@asynccontextmanager
async def lifespan(_: FastAPI):
    initialize_database()
    yield


app = FastAPI(title="Atlas Authentication API", version="0.1.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=sorted(ALLOWED_ORIGINS),
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["Content-Type", "Authorization"],
)


@app.middleware("http")
async def prevent_stale_frontend_assets(request: Request, call_next):
    """Enforce same-origin mutations and attach browser security headers."""
    response = None
    if request.url.path.startswith("/api/") and request.method in {
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
    }:
        origin = request.headers.get("origin", "").rstrip("/")
        if not origin or origin not in ALLOWED_ORIGINS:
            response = Response(
                content='{"detail":"The request origin is not allowed."}',
                status_code=status.HTTP_403_FORBIDDEN,
                media_type="application/json",
            )
    if response is None:
        response = await call_next(request)
    path = request.url.path
    frontend_path = (
        path in {"/", "/admin", "/admin/", "/chat", "/chat/", "/manager", "/manager/"}
        or path.startswith("/admin-assets/")
        or path.startswith("/chat-assets/")
        or path.startswith("/manager-assets/")
        or path.startswith("/styles/")
        or path.startswith("/scripts/")
    )
    if frontend_path:
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self' https://fonts.googleapis.com; "
        "img-src 'self' data:; connect-src 'self'; font-src 'self' https://fonts.gstatic.com; "
        "object-src 'none'; base-uri 'self'; "
        "form-action 'self'; frame-ancestors 'none'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if COOKIE_SECURE:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


def normalize_email(email: str) -> str:
    return email.strip().lower()


def available_username(connection, email: str) -> str:
    """Return a unique username based on the email's local part."""
    base = email.split("@", 1)[0]
    candidate = base
    suffix = 2
    while connection.execute(
        "SELECT 1 FROM rag_users WHERE LOWER(username) = LOWER(%s)",
        (candidate,),
    ).fetchone():
        candidate = f"{base}-{suffix}"
        suffix += 1
    return candidate


def tenant_payload(row: dict) -> dict:
    initials = "".join(word[0] for word in row["name"].split() if word).upper()[:3]
    return {
        "id": row["id"],
        "name": row["name"],
        "slug": row["slug"],
        "initials": initials,
        "meta": row["description"],
    }


def user_payload(row: dict) -> dict:
    tenant = None
    if row.get("tenant_id") is not None:
        tenant = tenant_payload(
            {
                "id": row["tenant_id"],
                "name": row["name"],
                "slug": row["slug"],
                "description": row["description"],
            }
        )
    return {
        "id": row["id"],
        "username": row.get("username"),
        "email": row.get("email"),
        "role": row["role"],
        "tenant": tenant,
    }


def authenticated_user(session_token: str | None) -> dict:
    """Validate a session token and return its active user and tenant."""
    if not session_token:
        raise HTTPException(status_code=401, detail="Authentication required.")

    try:
        claims = decode_session_token(session_token)
        user_id = int(claims["sub"])
        tenant_claim = claims["tenant_id"]
        tenant_id = int(tenant_claim) if tenant_claim is not None else None
        session_id = str(claims["jti"])
    except (HTTPException, KeyError, TypeError, ValueError) as exc:
        if isinstance(exc, HTTPException):
            raise
        raise HTTPException(status_code=401, detail="Invalid or expired session.") from exc

    with connect() as connection:
        user = connection.execute(
            """
            SELECT u.id, u.username, u.email, u.tenant_id, u.role,
                   t.name, t.slug, t.description
            FROM rag_users AS u
            LEFT JOIN rag_tenants AS t ON t.id = u.tenant_id
            JOIN auth_sessions s ON s.user_id = u.id
            WHERE u.id = %s AND u.tenant_id IS NOT DISTINCT FROM %s
              AND s.id = %s AND s.tenant_id IS NOT DISTINCT FROM %s
              AND s.revoked_at IS NULL AND s.expires_at > CURRENT_TIMESTAMP
              AND u.is_active = TRUE
              AND (u.role = 'admin' OR t.is_active = TRUE)
            """,
            (user_id, tenant_id, session_id, tenant_id),
        ).fetchone()
        if user is not None:
            connection.execute(
                "UPDATE auth_sessions SET last_seen_at = CURRENT_TIMESTAMP WHERE id = %s",
                (session_id,),
            )

    if user is None:
        raise HTTPException(status_code=401, detail="Session user is unavailable.")
    user["session_id"] = session_id
    return user


def authenticated_admin(atlas_session: str | None = Cookie(default=None)) -> dict:
    user = authenticated_user(atlas_session)
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Administrator access required.")
    return user


def authenticated_manager(atlas_session: str | None = Cookie(default=None)) -> dict:
    user = authenticated_user(atlas_session)
    if user["role"] != "tenant_manager":
        raise HTTPException(status_code=403, detail="Tenant manager access required.")
    return user


def authenticated_rag_request(atlas_session: str | None = Cookie(default=None)) -> dict:
    """Authenticate first; the RAG policy module performs role and tenant authorization."""
    return authenticated_user(atlas_session)


def landing_path_for(user: dict) -> str:
    if user["role"] == "admin":
        return "/admin"
    if user["role"] == "tenant_manager":
        return "/manager"
    return "/chat"


@app.get("/api/health")
def health() -> dict:
    with connect() as connection:
        connection.execute("SELECT 1")
    return {"status": "ok"}


@app.get("/api/tenants")
def list_tenants() -> list[dict]:
    with connect() as connection:
        rows = connection.execute(
            """
            SELECT id, name, slug, description
            FROM rag_tenants
            WHERE is_active = TRUE
            ORDER BY name
            """
        ).fetchall()
    return [tenant_payload(row) for row in rows]


@app.post("/api/auth/register", status_code=status.HTTP_201_CREATED)
def register(payload: RegistrationRequest, request: Request) -> dict:
    email = normalize_email(str(payload.email))
    ip = request_ip(request)
    enforce_rate_limit(
        action="registration_ip", subject=ip, limit=10, window_seconds=3600, block_seconds=3600
    )
    enforce_rate_limit(
        action="registration_email",
        subject=email,
        limit=3,
        window_seconds=3600,
        block_seconds=3600,
    )
    password_hash = password_hasher.hash(payload.password)

    try:
        with connect() as connection:
            tenant = connection.execute(
                """
                SELECT id, name, slug, description
                FROM rag_tenants
                WHERE id = %s AND is_active = TRUE
                """,
                (payload.tenant_id,),
            ).fetchone()
            if tenant is None:
                raise HTTPException(status_code=400, detail="Selected tenant is unavailable.")

            username = available_username(connection, email)
            user = connection.execute(
                """
                INSERT INTO rag_users
                    (username, email, password_hash, tenant_id, role, email_verified_at)
                VALUES (%s, %s, %s, %s, 'pending', NULL)
                RETURNING id, username, email, role, created_at
                """,
                (username, email, password_hash, payload.tenant_id),
            ).fetchone()
    except errors.UniqueViolation as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email already exists.",
        ) from exc

    verification_token = create_action_token(
        user_id=user["id"],
        purpose="email_verification",
        ttl_seconds=24 * 3600,
        requested_ip=ip,
    )
    try:
        deliver_auth_email(
            recipient=email,
            subject="Verify your Atlas account",
            body=(
                "Verify your email address using this link within 24 hours:\n\n"
                f"{action_url('/verify-email', verification_token)}"
            ),
        )
    except Exception:
        LOGGER.exception("Unable to deliver an email-verification message.")

    return {
        "user": {
            **user,
            "tenant": tenant_payload(tenant),
        },
        "verification_required": True,
    }


@app.post("/api/auth/login")
def login(payload: LoginRequest, response: Response, request: Request) -> dict:
    identifier = payload.identifier.strip().lower()
    ip = request_ip(request)
    enforce_rate_limit(
        action="login_ip", subject=ip, limit=100, window_seconds=900, block_seconds=900
    )
    enforce_rate_limit(
        action="login_identifier",
        subject=identifier,
        limit=20,
        window_seconds=900,
        block_seconds=900,
    )
    with connect() as connection:
        user = connection.execute(
            """
            SELECT u.id, u.username, u.email, u.password_hash, u.tenant_id, u.role,
                   u.email_verified_at, u.failed_login_count, u.locked_until,
                   t.name, t.slug, t.description
            FROM rag_users AS u
            LEFT JOIN rag_tenants AS t ON t.id = u.tenant_id
            WHERE (u.email = %s OR LOWER(u.username) = %s)
              AND u.is_active = TRUE
              AND u.role <> 'pending'
              AND (u.role = 'admin' OR t.is_active = TRUE)
            """,
            (identifier, identifier),
        ).fetchone()

    now = datetime.now(timezone.utc)
    if user is not None and user["locked_until"] and user["locked_until"] > now:
        retry_after = max(1, int((user["locked_until"] - now).total_seconds()))
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="This account is temporarily locked. Try again later.",
            headers={"Retry-After": str(retry_after)},
        )

    try:
        if user is None:
            password_hasher.verify(dummy_password_hash, payload.password)
            raise VerifyMismatchError
        password_hasher.verify(user["password_hash"], payload.password)
    except (VerifyMismatchError, InvalidHashError) as exc:
        if user is not None:
            failures = user["failed_login_count"] + 1
            lock_seconds = 0
            if failures >= 8:
                lock_seconds = 3600
            elif failures == 7:
                lock_seconds = 900
            elif failures == 6:
                lock_seconds = 300
            elif failures == 5:
                lock_seconds = 60
            with connect() as connection:
                connection.execute(
                    """
                    UPDATE rag_users
                    SET failed_login_count = %s,
                        locked_until = CASE WHEN %s > 0
                            THEN CURRENT_TIMESTAMP + (%s * INTERVAL '1 second')
                            ELSE locked_until END,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE id = %s
                    """,
                    (failures, lock_seconds, lock_seconds, user["id"]),
                )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        ) from exc

    if user["email"] is not None and user["email_verified_at"] is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Verify your email address before signing in.",
        )

    with connect() as connection:
        connection.execute(
            """
            UPDATE rag_users
            SET failed_login_count = 0, locked_until = NULL, updated_at = CURRENT_TIMESTAMP
            WHERE id = %s
            """,
            (user["id"],),
        )
        if password_hasher.check_needs_rehash(user["password_hash"]):
            connection.execute(
                "UPDATE rag_users SET password_hash = %s, updated_at = CURRENT_TIMESTAMP WHERE id = %s",
                (password_hasher.hash(payload.password), user["id"]),
            )

    token, expires_in, _ = issue_session_token(
        user_id=user["id"],
        tenant_id=user["tenant_id"],
        request=request,
        remember=payload.remember,
    )
    response.set_cookie(
        key="atlas_session",
        value=token,
        max_age=expires_in if payload.remember else None,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="lax",
        path="/",
    )
    return {
        "expires_in": expires_in,
        "landing_path": landing_path_for(user),
        "user": user_payload(user),
    }


@app.get("/api/auth/me")
def current_user(atlas_session: str | None = Cookie(default=None)) -> dict:
    user = authenticated_user(atlas_session)
    return {"user": user_payload(user)}


@app.post("/api/auth/verify-email")
def verify_email(payload: TokenRequest) -> dict:
    token = consume_action_token(payload.token, "email_verification")
    with connect() as connection:
        connection.execute(
            """
            UPDATE rag_users
            SET email_verified_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
            WHERE id = %s
            """,
            (token["user_id"],),
        )
    return {"message": "Email address verified."}


@app.post("/api/auth/verification/request", status_code=status.HTTP_202_ACCEPTED)
def request_verification(payload: EmailRequest, request: Request) -> dict:
    email = normalize_email(str(payload.email))
    ip = request_ip(request)
    enforce_rate_limit(
        action="verification_ip", subject=ip, limit=10, window_seconds=3600, block_seconds=3600
    )
    enforce_rate_limit(
        action="verification_email", subject=email, limit=3, window_seconds=3600, block_seconds=3600
    )
    with connect() as connection:
        user = connection.execute(
            "SELECT id, email, email_verified_at FROM rag_users WHERE email = %s AND is_active = TRUE",
            (email,),
        ).fetchone()
    if user is not None and user["email_verified_at"] is None:
        token = create_action_token(
            user_id=user["id"],
            purpose="email_verification",
            ttl_seconds=24 * 3600,
            requested_ip=ip,
        )
        try:
            deliver_auth_email(
                recipient=email,
                subject="Verify your Atlas account",
                body=(
                    "Verify your email address using this link within 24 hours:\n\n"
                    f"{action_url('/verify-email', token)}"
                ),
            )
        except Exception:
            LOGGER.exception("Unable to redeliver an email-verification message.")
    return {"message": "If verification is required, a new link has been sent."}


@app.post("/api/auth/password-reset/request", status_code=status.HTTP_202_ACCEPTED)
def request_password_reset(payload: EmailRequest, request: Request) -> dict:
    email = normalize_email(str(payload.email))
    ip = request_ip(request)
    enforce_rate_limit(
        action="reset_ip", subject=ip, limit=10, window_seconds=3600, block_seconds=3600
    )
    enforce_rate_limit(
        action="reset_email", subject=email, limit=3, window_seconds=3600, block_seconds=3600
    )
    with connect() as connection:
        user = connection.execute(
            """
            SELECT id, email FROM rag_users
            WHERE email = %s AND is_active = TRUE AND email_verified_at IS NOT NULL
            """,
            (email,),
        ).fetchone()
    if user is not None:
        token = create_action_token(
            user_id=user["id"],
            purpose="password_reset",
            ttl_seconds=3600,
            requested_ip=ip,
        )
        try:
            deliver_auth_email(
                recipient=email,
                subject="Reset your Atlas password",
                body=(
                    "Reset your password using this link within one hour:\n\n"
                    f"{action_url('/reset-password', token)}"
                ),
            )
        except Exception:
            LOGGER.exception("Unable to deliver a password-reset message.")
    return {"message": "If that account exists, a reset link has been sent."}


@app.post("/api/auth/password-reset/confirm")
def confirm_password_reset(payload: PasswordResetRequest) -> dict:
    token = consume_action_token(payload.token, "password_reset")
    with connect() as connection:
        connection.execute(
            """
            UPDATE rag_users
            SET password_hash = %s, password_changed_at = CURRENT_TIMESTAMP,
                failed_login_count = 0, locked_until = NULL,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = %s
            """,
            (password_hasher.hash(payload.new_password), token["user_id"]),
        )
        connection.execute(
            """
            UPDATE auth_sessions SET revoked_at = CURRENT_TIMESTAMP
            WHERE user_id = %s AND revoked_at IS NULL
            """,
            (token["user_id"],),
        )
    return {"message": "Password updated. Sign in again on your devices."}


@app.get("/api/auth/sessions")
def list_sessions(atlas_session: str | None = Cookie(default=None)) -> dict:
    user = authenticated_user(atlas_session)
    with connect() as connection:
        sessions = connection.execute(
            """
            SELECT id, issued_at, expires_at, last_seen_at, ip_address, user_agent,
                   revoked_at
            FROM auth_sessions
            WHERE user_id = %s AND revoked_at IS NULL
              AND expires_at > CURRENT_TIMESTAMP
            ORDER BY issued_at DESC
            """,
            (user["id"],),
        ).fetchall()
    return {
        "sessions": [
            {**session, "is_current": session["id"] == user["session_id"]}
            for session in sessions
        ]
    }


@app.delete("/api/auth/sessions/{session_id}", status_code=status.HTTP_204_NO_CONTENT)
def revoke_session(
    session_id: str,
    response: Response,
    atlas_session: str | None = Cookie(default=None),
) -> Response:
    user = authenticated_user(atlas_session)
    with connect() as connection:
        revoked = connection.execute(
            """
            UPDATE auth_sessions SET revoked_at = CURRENT_TIMESTAMP
            WHERE id = %s AND user_id = %s AND revoked_at IS NULL
            RETURNING id
            """,
            (session_id, user["id"]),
        ).fetchone()
    if revoked is None:
        raise HTTPException(status_code=404, detail="Active session not found.")
    if session_id == user["session_id"]:
        response.delete_cookie(key="atlas_session", path="/", samesite="lax", secure=COOKIE_SECURE)
    response.status_code = status.HTTP_204_NO_CONTENT
    return response


@app.post("/api/auth/logout-all", status_code=status.HTTP_204_NO_CONTENT)
def logout_all(
    response: Response, atlas_session: str | None = Cookie(default=None)
) -> Response:
    user = authenticated_user(atlas_session)
    with connect() as connection:
        connection.execute(
            """
            UPDATE auth_sessions SET revoked_at = CURRENT_TIMESTAMP
            WHERE user_id = %s AND revoked_at IS NULL
            """,
            (user["id"],),
        )
    response.delete_cookie(key="atlas_session", path="/", samesite="lax", secure=COOKIE_SECURE)
    response.status_code = status.HTTP_204_NO_CONTENT
    return response


@app.post("/api/auth/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    response: Response, atlas_session: str | None = Cookie(default=None)
) -> Response:
    if atlas_session:
        try:
            claims = decode_session_token(atlas_session)
            with connect() as connection:
                connection.execute(
                    """
                    UPDATE auth_sessions SET revoked_at = CURRENT_TIMESTAMP
                    WHERE id = %s AND revoked_at IS NULL
                    """,
                    (claims["jti"],),
                )
        except HTTPException:
            pass
    response.delete_cookie(key="atlas_session", path="/", samesite="lax", secure=COOKIE_SECURE)
    response.status_code = status.HTTP_204_NO_CONTENT
    return response


app.include_router(create_admin_router(authenticated_admin))
app.include_router(create_manager_router(authenticated_manager))
app.include_router(create_document_router(authenticated_admin, authenticated_manager))
app.include_router(create_rag_router(authenticated_rag_request))
app.include_router(create_incident_router(authenticated_admin, authenticated_manager))


authentication_frontend_directory = (
    Path(__file__).resolve().parents[1] / "frontend" / "authentication_frontend"
)
chat_frontend_directory = (
    Path(__file__).resolve().parents[1] / "frontend" / "chat_frontend"
)
admin_frontend_directory = (
    Path(__file__).resolve().parents[1] / "frontend" / "admin_frontend"
)
manager_frontend_directory = (
    Path(__file__).resolve().parents[1] / "frontend" / "tenant_manager_frontend"
)

if chat_frontend_directory.exists():
    app.mount(
        "/chat-assets",
        StaticFiles(directory=chat_frontend_directory),
        name="chat-assets",
    )

    @app.get("/chat", include_in_schema=False)
    @app.get("/chat/", include_in_schema=False)
    def chat_page(atlas_session: str | None = Cookie(default=None)) -> Response:
        try:
            user = authenticated_user(atlas_session)
        except HTTPException:
            return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
        if user["role"] != "user":
            return RedirectResponse(
                url=landing_path_for(user), status_code=status.HTTP_303_SEE_OTHER
            )
        return FileResponse(chat_frontend_directory / "index.html")

if admin_frontend_directory.exists():
    app.mount(
        "/admin-assets",
        StaticFiles(directory=admin_frontend_directory),
        name="admin-assets",
    )

    @app.get("/admin", include_in_schema=False)
    @app.get("/admin/", include_in_schema=False)
    def admin_page(atlas_session: str | None = Cookie(default=None)) -> Response:
        try:
            user = authenticated_user(atlas_session)
        except HTTPException:
            return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
        if user["role"] != "admin":
            return RedirectResponse(
                url=landing_path_for(user), status_code=status.HTTP_303_SEE_OTHER
            )
        return FileResponse(admin_frontend_directory / "index.html")

if manager_frontend_directory.exists():
    app.mount(
        "/manager-assets",
        StaticFiles(directory=manager_frontend_directory),
        name="manager-assets",
    )

    @app.get("/manager", include_in_schema=False)
    @app.get("/manager/", include_in_schema=False)
    def manager_page(atlas_session: str | None = Cookie(default=None)) -> Response:
        try:
            user = authenticated_user(atlas_session)
        except HTTPException:
            return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
        if user["role"] != "tenant_manager":
            return RedirectResponse(
                url=landing_path_for(user), status_code=status.HTTP_303_SEE_OTHER
            )
        return FileResponse(manager_frontend_directory / "index.html")

if authentication_frontend_directory.exists():
    @app.get("/verify-email", include_in_schema=False)
    @app.get("/reset-password", include_in_schema=False)
    def auth_action_page() -> Response:
        return FileResponse(authentication_frontend_directory / "auth-action.html")

    @app.get("/account-security", include_in_schema=False)
    def account_security_page(
        atlas_session: str | None = Cookie(default=None),
    ) -> Response:
        try:
            authenticated_user(atlas_session)
        except HTTPException:
            return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
        return FileResponse(authentication_frontend_directory / "account-security.html")

    app.mount(
        "/",
        StaticFiles(directory=authentication_frontend_directory, html=True),
        name="authentication-frontend",
    )
