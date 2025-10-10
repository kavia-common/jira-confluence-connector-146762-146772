# Authentication and CSRF Flow (Finalized)

This backend implements a minimal credential-based login with JWT tokens, a CSRF mechanism for state-changing requests, and helper endpoints for session, refresh, and logout.

Endpoints:
- GET /auth/csrf
  - Issues a CSRF token cookie (HttpOnly, SameSite=Lax) and returns { status: "success", token }.
  - Include the token in the X-CSRF-Token header for POST/PUT/PATCH/DELETE requests.
  - Not required for GET.

- GET /auth/session
  - Validates access token provided in Authorization: Bearer <token>.
  - Returns { authenticated: true, user: { id, email } } when valid; otherwise { authenticated: false }.

- POST /login
  - Body: { email or username, password }
  - Requires X-CSRF-Token matching the CSRF cookie.
  - On success: { access_token, refresh_token, token_type: "bearer", expires_in }.
  - Errors (standardized):
    - { "status": "error", "code": "INVALID_CSRF", "message": "CSRF token invalid" }
    - { "status": "error", "code": "INVALID_CREDENTIALS", "message": "Invalid username/password" }

- POST /auth/refresh
  - Body: { refresh_token }
  - Returns new access token: { access_token, token_type: "bearer", expires_in }.
  - In production, implement refresh token rotation and revocation tracking.

- POST /auth/logout
  - Stateless JWT demo: returns { ok: true } and the client should discard tokens.
  - If using server-side refresh token store, revoke invalidates tokens here.

CSRF:
- Required for POST/PUT/PATCH/DELETE; not required for GET.
- Retrieve via GET /auth/csrf, then echo in X-CSRF-Token header.

Frontend (summary):
- On login page load, call GET /auth/session; if authenticated, redirect to /.
- Login flow:
  1) GET /auth/csrf (with credentials)
  2) POST /login with JSON body and X-CSRF-Token
  3) On success, store tokens (e.g., httpOnly cookies or memory/LocalStorage per environment) and redirect to /
- Sensitive actions should include X-CSRF-Token. A helper wrapper can fetch /auth/csrf and attach the header automatically.

Environment vars:
- SECRET_KEY (required in non-dev)
- ACCESS_TOKEN_EXPIRES_MIN (default 15)
- REFRESH_TOKEN_EXPIRES_DAYS (default 7)
- CSRF_COOKIE_NAME (default csrftoken)
- CSRF_COOKIE_TTL_SEC (default 600)
- CSRF_SECRET (defaults to SECRET_KEY)
- DEV_MODE, DEMO_EMAIL, DEMO_PASSWORD (bootstrap demo user)

Notes:
- This scaffold uses stateless JWTs and a demo refresh flow. For production:
  - Use signed JWTs and persistent refresh token storage with rotation.
  - Consider storing access token in httpOnly cookies and using Authorization headers where applicable.
  - Enforce secure cookies and appropriate SameSite settings based on deployment.
