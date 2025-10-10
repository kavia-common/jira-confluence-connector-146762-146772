# Integration Backend

FastAPI backend for Jira/Confluence connector.

Running:
- pip install -r requirements.txt
- uvicorn integration_backend.src.api.main:app --reload --port 3001

Environment variables (required):
- JIRA_OAUTH_CLIENT_ID
- JIRA_OAUTH_CLIENT_SECRET
- JIRA_REDIRECT_URI
- BACKEND_CORS_ORIGINS
- APP_FRONTEND_URL

Optional:
- ATLASSIAN_CLOUD_BASE_URL (override Jira Cloud base URL discovery)
- ENCRYPTION_KEY (recommended)
- INTEGRATION_DB_URL (for durable token store replacement)

Tenancy:
- All connector endpoints honor the X-Tenant-Id header; if missing, defaults to "default".

Jira Endpoints:
- GET /connectors -> list available connectors with per-tenant status {connected, scopes, expires_at, refreshed_at, last_error}
- GET /connectors/jira/status -> connection status
- GET /connectors/jira/projects -> list Jira projects (requires connection)
- GET /connectors/jira/search?q=<JQL>&limit=<n> -> normalized SearchResultItem[]
- POST /connectors/jira/create {resource:"issue", project_key, summary, description?} -> CreateResult
- DELETE /connectors/jira/connection -> purge tokens for tenant
- PATCH /connectors/jira/connection {base_url} -> set site base URL (optional)

Errors:
All connector routes return standardized error payloads:
{ "status":"error", "code":"<CODE>", "message":"...", "retry_after"?:number }
Codes: UNAUTHORIZED, TOKEN_EXPIRED, RATE_LIMITED, VALIDATION_ERROR, VENDOR_ERROR, CONFIG_ERROR.

Token refresh:
The Jira client auto-refreshes tokens if expiry is near (2 minutes window) and retries once on 401. On 429, it maps to RATE_LIMITED and surfaces Retry-After header.

Notes:
- Redirect URI is not taken from the frontend; it is read from env JIRA_REDIRECT_URI.
- State validation occurs in the existing auth flow; for durable storage/state, replace the in-memory token store.
