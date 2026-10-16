"""FastAPI application for tenant discovery and user authentication."""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from fastapi import Cookie, FastAPI, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from psycopg import errors
from pydantic import BaseModel, EmailStr, Field

from .database import connect, initialize_database
from .admin import create_admin_router
from .manager import create_manager_router


password_hasher = PasswordHasher()
dummy_password_hash = password_hasher.hash("not-a-real-password")
auth_secret = os.getenv("AUTH_SECRET_KEY")
if not auth_secret:
    raise RuntimeError("AUTH_SECRET_KEY is not configured in .env")


class RegistrationRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    tenant_id: int = Field(gt=0)


class LoginRequest(BaseModel):
    identifier: str = Field(min_length=1, max_length=320)
    password: str = Field(min_length=1, max_length=128)
    remember: bool = False


@asynccontextmanager
async def lifespan(_: FastAPI):
    initialize_database()
    yield


app = FastAPI(title="Atlas Authentication API", version="0.1.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:4173", "http://localhost:4173"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["Content-Type", "Authorization"],
)


@app.middleware("http")
async def prevent_stale_frontend_assets(request: Request, call_next):
    """Disable browser caching for local frontend bundles during development."""
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


def issue_access_token(user_id: int, tenant_id: int | None) -> tuple[str, int]:
    expires_in = 3600
    now = datetime.now(timezone.utc)
    token = jwt.encode(
        {
            "sub": str(user_id),
            "tenant_id": tenant_id,
            "iat": now,
            "exp": now + timedelta(seconds=expires_in),
        },
        auth_secret,
        algorithm="HS256",
    )
    return token, expires_in


def authenticated_user(session_token: str | None) -> dict:
    """Validate a session token and return its active user and tenant."""
    if not session_token:
        raise HTTPException(status_code=401, detail="Authentication required.")

    try:
        claims = jwt.decode(session_token, auth_secret, algorithms=["HS256"])
        user_id = int(claims["sub"])
        tenant_claim = claims["tenant_id"]
        tenant_id = int(tenant_claim) if tenant_claim is not None else None
    except (jwt.InvalidTokenError, KeyError, TypeError, ValueError) as exc:
        raise HTTPException(status_code=401, detail="Invalid or expired session.") from exc

    with connect() as connection:
        user = connection.execute(
            """
            SELECT u.id, u.username, u.email, u.tenant_id, u.role,
                   t.name, t.slug, t.description
            FROM rag_users AS u
            LEFT JOIN rag_tenants AS t ON t.id = u.tenant_id
            WHERE u.id = %s AND u.tenant_id IS NOT DISTINCT FROM %s
              AND u.is_active = TRUE
              AND (u.role = 'admin' OR t.is_active = TRUE)
            """,
            (user_id, tenant_id),
        ).fetchone()

    if user is None:
        raise HTTPException(status_code=401, detail="Session user is unavailable.")
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
def register(payload: RegistrationRequest) -> dict:
    email = normalize_email(str(payload.email))
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
                INSERT INTO rag_users (username, email, password_hash, tenant_id, role)
                VALUES (%s, %s, %s, %s, 'pending')
                RETURNING id, username, email, role, created_at
                """,
                (username, email, password_hash, payload.tenant_id),
            ).fetchone()
    except errors.UniqueViolation as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email already exists.",
        ) from exc

    return {
        "user": {
            **user,
            "tenant": tenant_payload(tenant),
        }
    }


@app.post("/api/auth/login")
def login(payload: LoginRequest, response: Response) -> dict:
    identifier = payload.identifier.strip().lower()
    with connect() as connection:
        user = connection.execute(
            """
            SELECT u.id, u.username, u.email, u.password_hash, u.tenant_id, u.role,
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

    try:
        if user is None:
            password_hasher.verify(dummy_password_hash, payload.password)
            raise VerifyMismatchError
        password_hasher.verify(user["password_hash"], payload.password)
    except (VerifyMismatchError, InvalidHashError) as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        ) from exc

    if password_hasher.check_needs_rehash(user["password_hash"]):
        with connect() as connection:
            connection.execute(
                "UPDATE rag_users SET password_hash = %s, updated_at = CURRENT_TIMESTAMP WHERE id = %s",
                (password_hasher.hash(payload.password), user["id"]),
            )

    token, expires_in = issue_access_token(user["id"], user["tenant_id"])
    response.set_cookie(
        key="atlas_session",
        value=token,
        max_age=expires_in if payload.remember else None,
        httponly=True,
        secure=os.getenv("COOKIE_SECURE", "false").lower() == "true",
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


@app.post("/api/auth/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(response: Response) -> Response:
    response.delete_cookie(key="atlas_session", path="/", samesite="lax")
    response.status_code = status.HTTP_204_NO_CONTENT
    return response


app.include_router(create_admin_router(authenticated_admin))
app.include_router(create_manager_router(authenticated_manager))


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
    app.mount(
        "/",
        StaticFiles(directory=authentication_frontend_directory, html=True),
        name="authentication-frontend",
    )
