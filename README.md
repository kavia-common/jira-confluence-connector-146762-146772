# jira-confluence-connector-146762-146772

## Integration Backend - Persistence Layer

This backend includes a lightweight SQLAlchemy-based persistence layer using SQLite by default.
- Configure DB via INTEGRATION_DB_URL in an `.env` file (see `integration_backend/.env.example`).
- Default: `sqlite:///./integration.db` created in the backend working directory.
- Tables are auto-created at startup for demo/demo purposes.

Now supports OAuth 2.0 (3LO) for Atlassian (Jira/Confluence) with PKCE:
- Configure OAuth via environment variables (see `integration_backend/.env.example`).
- New endpoints (PKCE-based):
  - GET /api/oauth/atlassian/login -> redirects to Atlassian authorization with PKCE
  - GET /api/oauth/callback/atlassian -> handles token exchange using PKCE, stores tokens in a server session
  - POST /api/oauth/atlassian/refresh -> refresh access token using refresh_token
  - GET /api/atlassian/resources -> lists accessible resources (Cloud IDs) with the session access_token
- Legacy endpoints (remain available):
  - GET /auth/jira/login
  - GET /auth/jira/callback
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
   - Set ATLASSIAN_CLIENT_ID, ATLASSIAN_REDIRECT_URI, APP_FRONTEND_URL, BACKEND_CORS_ORIGINS, etc.
4. Run API:
   - `uvicorn src.api.main:app --reload --port 3001 --app-dir integration_backend`
5. Generate OpenAPI spec (optional, while API is running is not required):
   - `python -m src.api.generate_openapi` (run from `integration_backend` directory)

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
- OAuth (PKCE):
  - GET /api/oauth/atlassian/login -> redirect to Atlassian with PKCE
  - GET /api/oauth/callback/atlassian -> exchange code using code_verifier
  - POST /api/oauth/atlassian/refresh -> refresh access token
  - GET /api/atlassian/resources -> verify connection (accessible resources)

### OAuth 2.0 Configuration (Atlassian, PKCE)
Set the following environment variables (see `integration_backend/.env.example`):
- ATLASSIAN_CLIENT_ID (required)
- ATLASSIAN_CLIENT_SECRET (optional; if set it will be sent for token/refresh)
- ATLASSIAN_REDIRECT_URI (required; e.g., http://localhost:3001/api/oauth/callback/atlassian — must exactly match Atlassian console)
- ATLASSIAN_SCOPES (optional; space-separated; default covers Jira+Confluence read + offline_access)
- APP_BASE_URL (optional)
- APP_FRONTEND_URL (optional; e.g., http://localhost:3000 for success redirect)
- BACKEND_CORS_ORIGINS (optional; comma-separated origins; default "*")

Scopes:
- Example default: read:jira-work read:jira-user read:confluence-content.all read:confluence-space.summary offline_access

### Frontend integration notes
- The login button should navigate the browser to GET /api/oauth/atlassian/login (full-page redirect).
- After Atlassian redirects back to the backend callback, the backend will:
  - Validate state and complete the PKCE token exchange
  - Store access_token, refresh_token, and expiration in a server session (httpOnly cookie)
  - Redirect to APP_FRONTEND_URL (default "/connected")
- Your frontend can call `GET /api/atlassian/resources` (credentials: include) to verify and show accessible Cloud IDs.

### Security notes
- This implementation uses an in-memory session store for demo simplicity. Replace with Redis or persistent storage for production.
- Ensure HTTPS so Secure cookies are respected.
- Do NOT hardcode client secrets or tokens. Use environment variables or a secret manager.
- The redirect_uri must exactly match the value configured in the Atlassian developer console.

### Important notes
- For production:
  - Store secrets securely (KMS/Secret Manager), and encrypt sensitive fields at rest.
  - Replace the demo "first user" selection with real user context where applicable.
  - Implement periodic token refresh using Atlassian "refresh_token" before expiry.
  - Tighten CORS to specific trusted origins.
