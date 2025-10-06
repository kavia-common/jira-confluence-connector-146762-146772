# jira-confluence-connector-146762-146772

## Integration Backend - Persistence Layer

This backend includes a lightweight SQLAlchemy-based persistence layer using SQLite by default.
- Configure DB via INTEGRATION_DB_URL in an `.env` file (see `integration_backend/.env.example`).
- Default: `sqlite:///./integration.db` created in the backend working directory.
- Tables are auto-created at startup for demo/demo purposes.

Now supports OAuth 2.0 (3LO) for Atlassian (Jira/Confluence):
- Configure OAuth via environment variables (see `integration_backend/.env.example`).
- New endpoints:
  - GET /auth/jira/login -> redirects to Atlassian authorization
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
   - IMPORTANT: Set JIRA_OAUTH_REDIRECT_URI to the provided callback URL:
     https://vscode-internal-30616-beta.beta01.cloud.kavia.ai:4000/oauth/jira
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
- OAuth:
  - GET /auth/jira/login -> redirect to Atlassian
  - GET /auth/jira/callback -> exchange code; persists tokens on first user (demo)
  - GET /auth/confluence/login
  - GET /auth/confluence/callback

### OAuth 2.0 Configuration (Atlassian)
Set the following environment variables (see `.env.example`):
- ATLASSIAN_CLOUD_BASE_URL: e.g., https://your-team.atlassian.net
- JIRA_OAUTH_CLIENT_ID, JIRA_OAUTH_CLIENT_SECRET
- JIRA_OAUTH_REDIRECT_URI: e.g., https://yourapp.com/api/auth/jira/callback
- Optional for Confluence if using separate app:
  - CONFLUENCE_OAUTH_CLIENT_ID, CONFLUENCE_OAUTH_CLIENT_SECRET
  - CONFLUENCE_OAUTH_REDIRECT_URI
- APP_FRONTEND_URL: e.g., http://localhost:3000 — used to redirect users after successful auth

Scopes:
- Jira example: read:jira-work read:jira-user offline_access
- Confluence example: read:confluence-content.all read:confluence-space.summary offline_access
Configure scopes on Atlassian Developer Console for your app.

### Frontend integration notes
- The "Connect Now" button for Jira should initiate a request to POST /integrations/jira/connect and then follow the redirect_url returned ("/auth/jira/login").
  Alternatively, the button can directly open GET /auth/jira/login.
- Confluence connect is analogous ("/auth/confluence/login").
- After Atlassian redirects back to our backend callbacks, the backend will:
  - Exchange authorization code for tokens
  - Store access_token, refresh_token, and expiration on the first user (demo simplification)
  - Redirect to APP_FRONTEND_URL + "/oauth/callback?provider=<jira|confluence>&status=success&user_id=<id>&state=<optional>"
- Your frontend should implement a route (/oauth/callback) to read these query params and update UI state — e.g., mark the provider as "Connected".
- For CSRF mitigation, you can generate a state string on the frontend and pass it to /auth/*/login via ?state=..., and validate on your own after redirection.

### Important notes
- Do NOT hardcode client secrets or tokens. Use environment variables or a secret manager.
- For production:
  - Store secrets securely (KMS/Secret Manager), and encrypt sensitive fields at rest.
  - Replace the demo "first user" selection with real user context (e.g., session or JWT).
  - Implement state verification for OAuth flows.
  - Implement token refresh using Atlassian "refresh_token" before expiry.
