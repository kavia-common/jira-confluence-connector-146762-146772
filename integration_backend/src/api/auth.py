import os
import secrets
import hmac
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple, Dict, Any

import jwt  # PyJWT
from fastapi import APIRouter, Depends, Header, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from src.api.errors import http_error, ErrorCode
from src.db.config import get_db
from src.db.service import get_user_by_email
from src.db.models import User

try:
    import bcrypt  # type: ignore
except Exception as e:
    raise RuntimeError("bcrypt is required for password hashing. Add to requirements.txt") from e

# Constants and env-driven configuration
CSRF_COOKIE_NAME = os.getenv("CSRF_COOKIE_NAME", "csrftoken")
CSRF_COOKIE_TTL = int(os.getenv("CSRF_COOKIE_TTL_SEC", "600"))
CSRF_SECRET = os.getenv("CSRF_SECRET") or os.getenv("APP_SECRET_KEY") or os.getenv("SECRET_KEY") or "dev-insecure-secret"

JWT_SECRET = os.getenv("SECRET_KEY") or os.getenv("APP_SECRET_KEY") or "dev-insecure-secret"
JWT_ALG = os.getenv("ALGORITHM", "HS256")
ACCESS_MIN = int(os.getenv("ACCESS_TOKEN_EXPIRES_MIN", "15"))
REFRESH_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRES_DAYS", "7"))

DEV_MODE = str(os.getenv("DEV_MODE", "false")).lower() in ("1", "true", "yes")


# PUBLIC_INTERFACE
def hash_password(plain: str) -> str:
    """Hash a password using bcrypt."""
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(plain.encode("utf-8"), salt).decode("utf-8")


# PUBLIC_INTERFACE
def verify_password(plain: str, password_hash: str) -> bool:
    """Verify a plaintext password with a bcrypt hash."""
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), password_hash.encode("utf-8"))
    except Exception:
        return False


def _issue_token_pair(subject: str, extra_claims: Optional[Dict[str, Any]] = None) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    now = datetime.now(timezone.utc)
    access_exp = now + timedelta(minutes=ACCESS_MIN)
    refresh_exp = now + timedelta(days=REFRESH_DAYS)

    base = {"sub": subject, "iat": int(now.timestamp())}
    if extra_claims:
        base.update(extra_claims)

    access_claims = dict(base)
    access_claims["type"] = "access"
    access_claims["exp"] = int(access_exp.timestamp())

    refresh_claims = dict(base)
    refresh_claims["type"] = "refresh"
    refresh_claims["exp"] = int(refresh_exp.timestamp())

    access_token = jwt.encode(access_claims, JWT_SECRET, algorithm=JWT_ALG)
    refresh_token = jwt.encode(refresh_claims, JWT_SECRET, algorithm=JWT_ALG)

    return (
        {
            "access_token": access_token,
            "token_type": "bearer",
            "expires_in": ACCESS_MIN * 60,
        },
        {
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "expires_in": REFRESH_DAYS * 24 * 3600,
        },
    )


def _sign_csrf(value: str) -> str:
    mac = hmac.new(CSRF_SECRET.encode("utf-8"), msg=value.encode("utf-8"), digestmod=hashlib.sha256)
    return f"{value}.{mac.hexdigest()}"


def _verify_signed_csrf(signed: str) -> bool:
    if not signed or "." not in signed:
        return False
    raw, sig = signed.rsplit(".", 1)
    mac = hmac.new(CSRF_SECRET.encode("utf-8"), msg=raw.encode("utf-8"), digestmod=hashlib.sha256)
    return hmac.compare_digest(mac.hexdigest(), sig)


router = APIRouter(tags=["Auth"])


class LoginRequest(BaseModel):
    """Request body for credential login."""
    username: Optional[str] = Field(None, description="Username or email")
    email: Optional[str] = Field(None, description="Email address")
    password: str = Field(..., description="Plaintext password")


class LoginResponse(BaseModel):
    """Successful login response with token pair."""
    access_token: str = Field(..., description="JWT access token")
    refresh_token: str = Field(..., description="JWT refresh token")
    token_type: str = Field(default="bearer", description="Token type")
    expires_in: int = Field(..., description="Access token expiry in seconds")


# PUBLIC_INTERFACE
@router.get("/auth/csrf", summary="Issue CSRF token", description="Generates a CSRF token, sets HttpOnly SameSite=Lax cookie and returns token in JSON for header echo.")
def get_csrf_token() -> JSONResponse:
    """Issue a CSRF token cookie and return token in body."""
    raw = secrets.token_urlsafe(24)
    signed = _sign_csrf(raw)

    response = JSONResponse(
        status_code=status.HTTP_200_OK,
        content={"status": "success", "token": signed},
    )
    response.set_cookie(
        key=CSRF_COOKIE_NAME,
        value=signed,
        max_age=CSRF_COOKIE_TTL,
        httponly=True,
        secure=True,
        samesite="lax",
        path="/",
    )
    return response


def _ensure_demo_user(db: Session) -> Optional[User]:
    """Create a demo user if none exists and DEV_MODE=true."""
    if not DEV_MODE:
        return None
    # reuse service.list_users via query
    from sqlalchemy import select
    from src.db.models import User as U
    existing = db.execute(select(U).limit(1)).scalar_one_or_none()
    if existing:
        return existing
    demo_email = os.getenv("DEMO_EMAIL", "demo@example.com")
    demo_password = os.getenv("DEMO_PASSWORD", "demo1234")
    user = U(email=demo_email, display_name="Demo User")
    user.password_hash = hash_password(demo_password)
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


# PUBLIC_INTERFACE
@router.post("/login", response_model=LoginResponse, summary="Login with credentials + CSRF", description="Validates CSRF and credentials. Returns access and refresh tokens.")
def login(
    request: Request,
    payload: LoginRequest,
    db: Session = Depends(get_db),
    x_csrf_token: Optional[str] = Header(default=None, convert_underscores=False, alias="X-CSRF-Token"),
) -> JSONResponse:
    """
    Validate CSRF (cookie vs header) and user credentials by email/username.
    Returns access and refresh tokens or standardized errors.
    """
    # CSRF validation
    cookie_csrf = request.cookies.get(CSRF_COOKIE_NAME)
    if not x_csrf_token or not cookie_csrf:
        # Standardized error format
        return JSONResponse(status_code=400, content={"status": "error", "code": "INVALID_CSRF", "message": "CSRF token invalid"})
    if not _verify_signed_csrf(x_csrf_token) or not hmac.compare_digest(x_csrf_token, cookie_csrf):
        return JSONResponse(status_code=400, content={"status": "error", "code": "INVALID_CSRF", "message": "CSRF token invalid"})

    # Credentials
    _ensure_demo_user(db)
    identifier = payload.email or payload.username
    if not identifier:
        raise http_error(422, ErrorCode.VALIDATION, "Email or username is required")

    # For now username maps to email field as system doesn't have separate username
    user = get_user_by_email(db, identifier)
    if not user or not user.password_hash or not verify_password(payload.password, user.password_hash):
        # Standardized error format
        return JSONResponse(status_code=401, content={"status": "error", "code": "INVALID_CREDENTIALS", "message": "Invalid username/password"})

    access, refresh = _issue_token_pair(subject=str(user.id), extra_claims={"email": user.email})
    body = {
        "access_token": access["access_token"],
        "refresh_token": refresh["refresh_token"],
        "token_type": "bearer",
        "expires_in": access["expires_in"],
    }
    # Rotate CSRF after login success
    response = JSONResponse(status_code=200, content=body)
    response.delete_cookie(CSRF_COOKIE_NAME, path="/")
    return response


class RefreshRequest(BaseModel):
    """Request body to refresh access token."""
    refresh_token: str = Field(..., description="Refresh token JWT")


# PUBLIC_INTERFACE
@router.post("/auth/refresh", summary="Refresh access token", description="Exchange refresh token for a new access token.")
def refresh_token(payload: RefreshRequest) -> JSONResponse:
    """Validate refresh token and issue new access token."""
    try:
        claims = jwt.decode(payload.refresh_token, JWT_SECRET, algorithms=[JWT_ALG])
        if claims.get("type") != "refresh":
            raise ValueError("invalid token type")
        sub = claims.get("sub")
        access, _ = _issue_token_pair(subject=str(sub))
        return JSONResponse(
            status_code=200,
            content={
                "access_token": access["access_token"],
                "token_type": "bearer",
                "expires_in": access["expires_in"],
            },
        )
    except jwt.ExpiredSignatureError:
        raise http_error(401, ErrorCode.UNAUTHORIZED, "Refresh token expired")
    except Exception:
        raise http_error(400, ErrorCode.VALIDATION, "Invalid refresh token")


# PUBLIC_INTERFACE
@router.get("/auth/session", summary="Session check", description="Returns authenticated status and user claims if the access token is valid.")
def session_check(authorization: Optional[str] = Header(default=None)) -> JSONResponse:
    """
    Validate access token from Authorization header (Bearer) and return authenticated state.
    """
    token = None
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1]
    if not token:
        return JSONResponse(status_code=200, content={"authenticated": False})

    try:
        claims = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        if claims.get("type") != "access":
            return JSONResponse(status_code=200, content={"authenticated": False})
        sub = claims.get("sub")
        email = claims.get("email")
        return JSONResponse(status_code=200, content={"authenticated": True, "user": {"id": int(sub) if sub is not None else None, "email": email}})
    except Exception:
        return JSONResponse(status_code=200, content={"authenticated": False})


class LogoutRequest(BaseModel):
    """Logout request body (optional future enhancements)."""
    pass


# PUBLIC_INTERFACE
@router.post("/auth/logout", summary="Logout", description="Client-initiated logout. For stateless JWTs, instruct clients to discard tokens.")
def logout() -> JSONResponse:
    """
    Stateless logout: client should discard tokens. If using refresh token store, revoke it here.
    """
    return JSONResponse(status_code=200, content={"ok": True})
