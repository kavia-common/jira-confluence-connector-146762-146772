# Integration Backend

FastAPI backend for Jira/Confluence connector.

Quick start:
1) python -m venv .venv && source .venv/bin/activate
2) pip install -r requirements.txt
3) (optional) cp .env.example .env and fill values; for startup, no secrets are required

Start the server (recommended; ensures imports resolve from any working directory):
- python -m integration_backend.app_entrypoint

Alternate (when working directory is integration_backend and PYTHONPATH includes ./src):
- python dev_server.py
- uvicorn src.api.main:app --host 0.0.0.0 --port 3001

Important:
- Uvicorn app import path is src.api.main:app (NOT main:app).
- The API listens on port 3001. Check readiness via:
  - GET http://localhost:3001/healthz -> {"status":"ok"}
  - GET http://localhost:3001/health -> {"status":"ok"}
  - GET http://localhost:3001/docs -> Swagger UI

Server:
- Boots on port 3001
- OpenAPI: /openapi.json
- Docs: /docs
- Health: /healthz, /health, and / (detailed)

CORS:
- Configure via ALLOWED_ORIGINS (preferred) as a comma-separated list.
- Fallbacks: BACKEND_CORS_ORIGINS or NEXT_PUBLIC_BACKEND_CORS_ORIGINS if ALLOWED_ORIGINS is unset.
- If you use cookies/credentials (OAuth state cookie, session cookies) you MUST set explicit origins; wildcard "*" is not allowed when allow_credentials=true.
- The middleware allows methods: GET, POST, PUT, PATCH, DELETE, OPTIONS and headers: Authorization, Content-Type, X-CSRF-Token, X-Requested-With, Accept, Origin.
- Example:
  - ALLOWED_ORIGINS=http://localhost:3000,https://vscode-internal-12731-beta.beta01.cloud.kavia.ai:3000
- Preflight:
  - Starlette CORSMiddleware handles OPTIONS automatically. A helper endpoint exists at OPTIONS /__cors_probe__ for simple verification.

OAuth (Jira):
- /auth/jira/login
  - GET returns { url: https://auth.atlassian.com/authorize?... } with required params (audience, client_id, scope, redirect_uri, response_type=code, prompt=consent, state)
  - Pass ?redirect=true to receive a 307 redirect to Atlassian
  - Generates signed state stored in HttpOnly SameSite=None cookie 'jira_oauth_state'
  - Accepts optional ?return_url=... to persist and use on callback
- /auth/jira/callback
  - Requires 'state' param and matching signed cookie; returns 422 when missing/invalid (clear message)
  - Requires 'code' param; returns 400 when missing
  - On success, exchanges tokens and redirects to return_url, or FRONTEND_URL/login (connected=jira)

Health helpers:
- /health/authorize-url -> returns authorize URL without redirect
- /health/redirect-uri -> shows active redirect URIs

Confluence:
- Limited endpoints exist under /connectors/confluence.

Tenancy:
- Pass X-Tenant-Id header to scope connections and operations. Defaults to "default" if missing.

Standardized errors:
- Shape: { "status": "error", "code": "TOKEN_EXPIRED|RATE_LIMITED|VALIDATION|NOT_CONNECTED|VENDOR_ERROR|UNAUTHORIZED|FORBIDDEN|NOT_FOUND|INTERNAL_ERROR", "message": "...", "retry_after"?: number }
- Headers: may include Retry-After on 429

Connectors:
- GET  /connectors
- GET  /connectors/{jira|confluence}/connection
- PATCH /connectors/{jira|confluence}/connection  (rotate/base_url; Jira supports PAT when ENABLE_JIRA_PAT=true)
- DELETE /connectors/{jira|confluence}/connection
- GET  /connectors/jira/projects
- GET  /connectors/jira/search?q=...
- POST /connectors/jira/create
- GET  /connectors/confluence/spaces
- GET  /connectors/confluence/search
- POST /connectors/confluence/create
- POST /connectors/tools/invoke   (Kavia tool adapter scaffold)

Token refresh:
- Jira client refreshes before expiry and retries once on 401; saves new expiry/refreshed_at.

PAT/API key:
- Optional Jira PAT enabled via ENABLE_JIRA_PAT=true. Save via PATCH /connectors/jira/connection { "pat": "..." }.
- Secrets are masked in logs.

Environment variables (key ones):
- JIRA_OAUTH_CLIENT_ID
- JIRA_OAUTH_CLIENT_SECRET
- JIRA_REDIRECT_URI (must match Atlassian dev console setting)
- ATLASSIAN_CLOUD_BASE_URL
- APP_FRONTEND_URL (used for post-auth redirect target)
- BACKEND_CORS_ORIGINS or NEXT_PUBLIC_BACKEND_CORS_ORIGINS
- ENABLE_JIRA_PAT (true/false)
- ENABLE_OAUTH_PKCE (true/false)
- STATE_SIGNING_SECRET (recommended)
- INTEGRATION_DB_URL (optional; default sqlite:///./integration.db)

Validation (CORS):
1) Set ALLOWED_ORIGINS in integration_backend/.env to include your Next.js origin (e.g., https://vscode-internal-12731-beta.beta01.cloud.kavia.ai:3000).
2) Start backend: python -m integration_backend.app_entrypoint
3) From the browser/Next.js origin, call:
   - GET https://<backend-host>:3001/health
   - Expect 200 and response headers including:
     - Access-Control-Allow-Origin: <your-frontend-origin>
     - Access-Control-Allow-Credentials: true (if credentials are used)
   - For preflight, ensure the browser sends OPTIONS and receives 204/200 with appropriate Access-Control-Allow-* headers.
4) You can hit OPTIONS /__cors_probe__ manually to confirm a 200 status with CORS headers added by middleware.

OAuth cookies and CORS:
- OAuth state and CSRF cookies are issued with Secure and SameSite settings appropriate to cross-site usage.
- SameSite=None; Secure is required for third-party cookie contexts. Ensure your environment uses HTTPS.
- These cookies do not conflict with CORS; however, browsers require Access-Control-Allow-Credentials and explicit origin matches for credentialed requests.

Troubleshooting startup (port 3001 not ready):
- Use the recommended entrypoint: python -m integration_backend.app_entrypoint
- Ensure the module path is correct: uvicorn src.api.main:app --port 3001
- Verify Python path includes integration_backend/src; the app_entrypoint ensures this automatically
- Check for import-time errors in logs (entrypoint prints traceback if app import fails)
- The app does not require secrets at import time; missing OAuth envs only affect /auth/jira/login (returns 400)
- Verify /healthz responds with 200; if not, ensure requirements are installed and no syntax/import errors occurred
