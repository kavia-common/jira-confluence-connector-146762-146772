# Integration Backend

FastAPI backend for Jira/Confluence connector.

Run:
- pip install -r requirements.txt
- uvicorn src.api.main:app --reload --port 3001

Server:
- Boots on port 3001
- OpenAPI: /openapi.json
- Docs: /docs

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

OAuth:
- /auth/jira/login -> returns authorize URL JSON by default; add ?redirect=true to 307 redirect
- /auth/jira/callback -> validates state cookie, exchanges code, stores tokens
- /auth/confluence/login, /auth/confluence/callback similarly supported
- Aliases under /api/auth/* and /api/oauth/atlassian/callback available for proxy compatibility
- State signing: HMAC with STATE_SIGNING_SECRET (or APP_SECRET_KEY/SECRET_KEY); HttpOnly SameSite=Lax cookie

Token refresh:
- Jira client refreshes before expiry and retries once on 401; saves new expiry/refreshed_at.

PAT/API key:
- Optional Jira PAT enabled via ENABLE_JIRA_PAT=true. Save via PATCH /connectors/jira/connection { "pat": "..." }.
- Secrets are masked in logs.

List endpoints:
- GET /connectors/jira/projects
- GET /connectors/confluence/spaces

Kavia tool hooks:
- POST /connectors/tools/invoke with { tool: "jira.search" | "jira.create" | "jira.projects" | "confluence.search" | "confluence.spaces", args: {...} }

Environment variables:
- NEXT_PUBLIC_ATLASSIAN_CLIENT_ID
- NEXT_PUBLIC_ATLASSIAN_CLIENT_SECRET
- NEXT_PUBLIC_ATLASSIAN_REDIRECT_URI
- NEXT_PUBLIC_JIRA_OAUTH_CLIENT_ID (fallback)
- NEXT_PUBLIC_JIRA_OAUTH_CLIENT_SECRET (fallback)
- NEXT_PUBLIC_CONFLUENCE_OAUTH_CLIENT_ID
- NEXT_PUBLIC_CONFLUENCE_OAUTH_CLIENT_SECRET
- NEXT_PUBLIC_CONFLUENCE_OAUTH_REDIRECT_URI
- NEXT_PUBLIC_ATLASSIAN_CLOUD_BASE_URL
- APP_FRONTEND_URL
- BACKEND_CORS_ORIGINS or NEXT_PUBLIC_BACKEND_CORS_ORIGINS
- ENABLE_JIRA_PAT (true/false)
- ENABLE_OAUTH_PKCE (true/false)
- STATE_SIGNING_SECRET (recommended)

Notes:
- Confluence client is minimal for list/search/create.
- Jira client implements normalization, pagination, and retry/refresh.
