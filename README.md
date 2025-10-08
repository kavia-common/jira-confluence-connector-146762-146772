# jira-confluence-connector-146762-146772

## Integration Backend - Persistence Layer

This backend includes a lightweight SQLAlchemy-based persistence layer using SQLite by default.
- Configure DB via INTEGRATION_DB_URL in an `.env` file (see `integration_backend/.env.example`).
- Default: `sqlite:///./integration.db` created in the backend working directory.
- Tables are auto-created at startup for demo/demo purposes.

Now supports OAuth 2.0 (3LO) for Atlassian (Jira/Confluence):
- Configure OAuth via environment variables (see `integration_backend/.env.example`).
- New endpoints:
  - GET /auth/jira/login -> returns JSON {"url": "<authorize>"} by default; if ?redirect=true responds with 307 redirect (Cache-Control: no-store) to Atlassian authorization
  - GET /auth/jira/callback -> handles token exchange and stores tokens on the user
  - GET /auth/confluence/login
  - GET /auth/confluence/callback
- Existing connect endpoints now guide the UI to start the OAuth flow instead of storing tokens directly.
  - POST /integrations/jira/connect -> returns redirect_url "/auth/jira/login"
  - POST /integrations/confluence/connect -> returns redirect_url "/auth/confluence/login"

### Quick start (dev)
1. Create and activate your environment.
2. Install dependencies:
   - `pip install -r integration_backend/requirements.txt`
3. Create `.env` from example and fill in your values:
   - `cp integration_backend/.env.example integration_backend/.env`
   - Set ATLASSIAN_CLOUD_BASE_URL, JIRA_OAUTH_CLIENT_ID/SECRET/REDIRECT_URI, APP_FRONTEND_URL, etc.
   - For local development, keep `APP_ENV=development` and `DEV_MODE=true` to enable safe mocks.
4. Run API:
   - `uvicorn src.api.main:app --reload --port 3001 --app-dir integration_backend`
5. Generate OpenAPI spec (optional, while API is running is not required):
   - `python -m src.api.generate_openapi` (run from `integration_backend` directory)

### Health and Docs
- Health: `GET /` and readiness: `GET /healthz` return quick status checks.
- OpenAPI/Swagger: `GET /docs` and OpenAPI schema at `/openapi.json`.

### Configuration and error handling improvements
- Centralized settings via environment variables; see `.env.example`.
- When Jira OAuth is not configured:
  - In production: `/auth/jira/login` returns 400 with a clear message and granular "missing" flags for client_id, client_secret, and redirect_uri (no 500s).
  - In development (`APP_ENV=development` or `DEV_MODE=true`): `/auth/jira/login` returns 200 with a mock redirect URL and includes the "missing" flags to keep previews working while signaling misconfiguration.
- CORS can be controlled via `BACKEND_CORS_ORIGINS` (comma separated). Defaults to allowing all in dev.
- Global exception handler sanitizes unhandled errors and includes `X-Request-ID` in responses and logs.


### API Highlights (public, no authentication)
- Health:
  - GET / -> service healthy
- Users:
  - POST /users -> create/idempotent user
  - GET /users -> list users (public)
  - GET /users/{user_id} -> fetch user (public)
- Integrations (placeholders with OAuth guidance):
  - POST /integrations/jira/connect -> returns base_url and redirect_url to start Jira OAuth
  - POST /integrations/confluence/connect -> returns base_url and redirect_url to start Confluence OAuth
  - GET /integrations/jira/projects/fetch -> returns stored JIRA projects (owner_id optional; defaults to first user)
  - GET /integrations/confluence/pages/fetch -> returns stored Confluence pages (owner_id optional; defaults to first user)
- Data operations:
  - POST /jira/projects, GET /jira/projects/{owner_id}
  - POST /confluence/pages, GET /confluence/pages/{owner_id}
- OAuth:
  - GET /auth/jira/login -> JSON authorize URL by default; ?redirect=true issues HTTP 307 redirect (Cache-Control: no-store)
  - GET /auth/jira/callback -> exchange code; persists tokens on a resolved user (state > first user > auto-created placeholder)
  - GET /auth/confluence/login
  - GET /auth/confluence/callback

### OAuth 2.0 Configuration (Atlassian)
Set the following environment variables (see `integration_backend/.env.example`):
- ATLASSIAN_CLOUD_BASE_URL: e.g., https://your-team.atlassian.net
- JIRA_OAUTH_CLIENT_ID, JIRA_OAUTH_CLIENT_SECRET
- JIRA_OAUTH_REDIRECT_URI: e.g., https://yourapp.com/api/auth/jira/callback
  IMPORTANT: Must exactly match what's registered in Atlassian. For this deployment it must be:
  https://vscode-internal-14727-beta.beta01.cloud.kavia.ai:3001/auth/jira/callback

Required Jira OAuth variables:
- JIRA_OAUTH_CLIENT_ID
- JIRA_OAUTH_CLIENT_SECRET
- JIRA_OAUTH_REDIRECT_URI

If any of these are missing, /auth/jira/login will return 400 with a granular "missing" flags payload:
{"missing":{"client_id":false,"client_secret":true,"redirect_uri":true}}
- Optional for Confluence if using separate app:
  - CONFLUENCE_OAUTH_CLIENT_ID, CONFLUENCE_OAUTH_CLIENT_SECRET
  - CONFLUENCE_OAUTH_REDIRECT_URI
- APP_FRONTEND_URL: e.g., http://localhost:3000 — used to redirect users after successful auth

Scopes:
- Jira example: read:jira-work read:jira-user offline_access
- Confluence example: read:confluence-content.all read:confluence-space.summary offline_access
Configure scopes on Atlassian Developer Console for your app.

### Proxy routing and callback aliases
Some deployments forward requests through a reverse proxy with an `/api` prefix that is not stripped before reaching the backend. To avoid 502s due to path mismatches, the backend now exposes compatibility aliases:

- GET /api/auth/jira/login -> alias of /auth/jira/login
- GET /api/auth/jira/callback -> alias of /auth/jira/callback
- GET /api/auth/confluence/login -> alias of /auth/confluence/login
- GET /api/auth/confluence/callback -> alias of /auth/confluence/callback
- GET /api/oauth/atlassian/callback -> generic alias that delegates to Jira callback (use Jira/Confluence-specific callbacks when possible)

Recommended Redirect URIs to configure in Atlassian:

Strict redirect_uri equality:
- The redirect_uri used in /auth/jira/login to build the authorize URL MUST be identical to the redirect_uri used in the token exchange (/auth/jira/callback), and MUST match exactly what is registered in Atlassian (including scheme, host, port, and path).
- Current required value: https://vscode-internal-14727-beta.beta01.cloud.kavia.ai:3001/auth/jira/callback

- Jira: https://<backend-domain>/api/auth/jira/callback (if your proxy keeps `/api`), otherwise https://<backend-domain>/auth/jira/callback
- Confluence: https://<backend-domain>/api/auth/confluence/callback (or without `/api` if your proxy strips it)

Environment fallback mapping:
- The backend now accepts NEXT_PUBLIC_* variants commonly used in frontend environments:
  - JIRA_OAUTH_CLIENT_ID falls back to ATLASSIAN_CLIENT_ID / NEXT_PUBLIC_JIRA_OAUTH_CLIENT_ID / NEXT_PUBLIC_JIRA_CLIENT_ID / NEXT_PUBLIC_ATLASSIAN_CLIENT_ID
  - JIRA_OAUTH_CLIENT_SECRET falls back to ATLASSIAN_CLIENT_SECRET / NEXT_PUBLIC_JIRA_OAUTH_CLIENT_SECRET / NEXT_PUBLIC_ATLASSIAN_CLIENT_SECRET
  - JIRA_OAUTH_REDIRECT_URI falls back to ATLASSIAN_REDIRECT_URI / NEXT_PUBLIC_JIRA_OAUTH_REDIRECT_URI / NEXT_PUBLIC_ATLASSIAN_REDIRECT_URI
  - CONFLUENCE_OAUTH_* fall back to their Jira/Atlassian counterparts if not provided
  - APP_FRONTEND_URL falls back to NEXT_PUBLIC_APP_FRONTEND_URL / NEXT_PUBLIC_FRONTEND_BASE_URL
  - ATLASSIAN_CLOUD_BASE_URL falls back to NEXT_PUBLIC_ATLASSIAN_CLOUD_BASE_URL

### Frontend integration notes
- The "Connect Now" button for Jira should initiate a request to POST /integrations/jira/connect and then follow the redirect_url returned ("/auth/jira/login").
  Alternatively, the button can directly open GET /auth/jira/login?redirect=true to perform a backend 307 redirect to Atlassian (Cache-Control: no-store). If you prefer to control navigation from the client, call GET /auth/jira/login without the flag and use the returned JSON {"url": "..."}.
- Confluence connect is analogous ("/auth/confluence/login").
- After Atlassian redirects back to our backend callbacks, the backend will:
  - Exchange authorization code for tokens
  - Store access_token, refresh_token, and expiration on a resolved user:
    - If state carries user_id or email, we associate to that user (creating by email if necessary)
    - Else if any user exists, we use the first one
    - Else we auto-create a placeholder user (email oauth-user-<uuid>@example.local)
  - Redirect to APP_FRONTEND_URL + "/oauth/jira?status=success&user_id=<id>&state=<optional>" for Jira
    (Default APP_FRONTEND_URL if not set: https://vscode-internal-14727-beta.beta01.cloud.kavia.ai:3000)
- Your frontend should implement a route (/oauth/jira) to read these query params and update UI state — e.g., mark the provider as "Connected".
- For CSRF mitigation, you can generate a state string on the frontend and pass it to /auth/*/login via ?state=..., and validate on your own after redirection.

### Important notes
- Do NOT hardcode client secrets or tokens. Use environment variables or a secret manager.
- For production:
  - Store secrets securely (KMS/Secret Manager), and encrypt sensitive fields at rest.
  - Replace the demo "first user" selection with real user context (e.g., session or JWT).
  - Implement state verification for OAuth flows.
  - Implement token refresh using Atlassian "refresh_token" before expiry.

---

## Diagnostics and request tracing

To improve observability for OAuth flows and diagnose 502/500s, the backend includes structured logging and request ID correlation:

- Each incoming request is assigned an X-Request-ID (uuid4) if not provided by the client. The value is:
  - Exposed to handlers via `request.state.request_id`
  - Added to all structured log lines
  - Echoed back in the response header `X-Request-ID`

- Logs are emitted in JSON-like structured lines with fields including:
  - timestamp, level, logger, event
  - request_id, provider, path, method
  - query_params (with sensitive fields redacted)
  - a safe subset of headers (User-Agent, X-Forwarded-For, etc., non-sensitive)
  - additional context (e.g., token exchange HTTP status, redirect targets without secrets)

- OAuth routes log key steps:
  - oauth_login_start, oauth_login_redirect
  - oauth_callback_received, token_exchange_start
  - token_exchange_response (status only), token_exchange_success (no tokens)
  - oauth_user_token_persisted, frontend_redirect
  - Any errors are logged with stack traces and the request_id for correlation.

- Sensitive values are never logged:
  - The following query/header fields are redacted: code, state, token, access_token, refresh_token, id_token, client_secret, authorization, cookie.

- You can control the log level with the `LOG_LEVEL` env var (default `INFO`).

Example: set and trace a custom Request ID with curl
```
curl -H "X-Request-ID: my-debug-123" "http://localhost:3001/api/auth/jira/callback?code=...&state=..."
# Inspect backend logs and filter by "request_id":"my-debug-123"
```

Use the `X-Request-ID` value returned by the backend in error responses (500) to quickly locate the associated logs when filing support tickets or debugging issues.

### Manual verification checklist (OAuth callbacks)

1. Configure env in integration_backend/.env (or container env):
   - JIRA_OAUTH_CLIENT_ID, JIRA_OAUTH_CLIENT_SECRET, JIRA_OAUTH_REDIRECT_URI
   - APP_FRONTEND_URL (e.g., http://localhost:3000)
   - ATLASSIAN_CLOUD_BASE_URL (e.g., https://your-team.atlassian.net)

2. Start backend:
   uvicorn src.api.main:app --reload --port 3001 --app-dir integration_backend

3. Visit GET /auth/jira/login to get authorize URL and complete consent.
   Atlassian redirects to /auth/jira/callback?code=...&state=...

4. Callback behavior:
   - If no users exist, backend auto-creates a placeholder user and stores tokens.
   - If a user exists, backend uses the first user by default.
   - If the state contains user_id=<id> or email=<addr>, backend resolves and associates to that user.

5. Observe redirect to the frontend:
   - For Jira: APP_FRONTEND_URL + /oauth/jira?status=success&user_id=<id>&state=<state>
   - For Confluence: APP_FRONTEND_URL + /oauth/callback?provider=confluence&status=success&user_id=<id>&state=<state>

6. Confirm in backend data:
   - GET /users -> returns list with the created/updated user
   - Tokens are stored on the server (not exposed by API responses)

Troubleshooting tips:
- Ensure the redirect_uri configured on Atlassian matches EXACTLY what backend uses.
- Use `LOG_LEVEL=DEBUG` and trace logs via X-Request-ID.
- In development (`DEV_MODE=true`), /auth/jira/login returns a mock URL if misconfigured to keep flows testable.
