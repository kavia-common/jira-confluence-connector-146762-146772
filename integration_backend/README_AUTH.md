Credentials login and CSRF

Endpoints:
- GET /auth/csrf
  Issues CSRF token, sets HttpOnly SameSite=Lax cookie (csrftoken) and returns the token in JSON for header echo (X-CSRF-Token).

- POST /login
  Body: { "email" or "username", "password" }
  Headers: X-CSRF-Token: <token from /auth/csrf>
  Validates CSRF (matches cookie) and verifies credentials (bcrypt).
  On success: { access_token, refresh_token, token_type: "bearer", expires_in }

- POST /auth/refresh
  Body: { "refresh_token": "<refresh JWT>" }
  Returns a new access_token.

Environment variables:
- SECRET_KEY (required in non-dev)
- ACCESS_TOKEN_EXPIRES_MIN (default 15)
- REFRESH_TOKEN_EXPIRES_DAYS (default 7)
- CSRF_COOKIE_NAME (default csrftoken)
- CSRF_COOKIE_TTL_SEC (default 600)
- CSRF_SECRET (defaults to SECRET_KEY)
- DEV_MODE, DEMO_EMAIL, DEMO_PASSWORD for demo bootstrap

User model:
- password_hash (bcrypt) added. For demo, a user is created when DEV_MODE=true and no users exist.

Frontend usage:
- Call GET /auth/csrf with credentials: "include"
- Submit POST /login with JSON body and header X-CSRF-Token echoing the token. On success store tokens or set cookies as needed and redirect.
