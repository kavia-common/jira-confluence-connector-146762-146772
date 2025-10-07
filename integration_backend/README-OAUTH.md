# OAuth Start Flow (Backend)

Aligned Atlassian OAuth endpoints with return_url handling and standardized redirect_uri.

Required environment variables:
- ATLASSIAN_CLIENT_ID
- ATLASSIAN_CLIENT_SECRET (optional with PKCE)
- ATLASSIAN_SCOPES (optional; space-separated)
- BACKEND_CORS_ORIGINS (comma-separated origins; include your frontend origin)
  Example:
    BACKEND_CORS_ORIGINS=https://vscode-internal-18211-beta.beta01.cloud.kavia.ai:3000,http://localhost:3000
  Note:
    - Because the backend issues an httpOnly session cookie (sid), CORS allow_credentials=True is enabled.
      Do not use '*' for origins; specify explicit origins.
- BACKEND_PUBLIC_BASE_URL (recommended; absolute URL ORIGIN of the backend, used to construct redirect_uri; must NOT include any path like '/docs')

Redirect URI registration:
- Register the following exact redirect URI in the Atlassian Developer Console:
  {BACKEND_PUBLIC_BASE_URL}/api/oauth/atlassian/callback
  Example:
  https://your-backend.example.com/api/oauth/atlassian/callback

Centralized configuration:
- get_public_base_url() reads BACKEND_PUBLIC_BASE_URL (origin-only) and normalizes it.
- get_atlassian_redirect_uri() returns ATLASSIAN_REDIRECT_URI if set; otherwise derives:
  {BACKEND_PUBLIC_BASE_URL}/api/oauth/atlassian/callback

Only the standardized callback is supported. Legacy aliases like /api/oauth/callback/jira have been removed.

Notes:
- If ATLASSIAN_REDIRECT_URI is set, the backend will compare it to the constructed value from BACKEND_PUBLIC_BASE_URL and log a warning if they differ.
- The backend uses the constructed redirect_uri when BACKEND_PUBLIC_BASE_URL is provided to ensure exact match and avoid unauthorized_client errors.
- Only /api/oauth/atlassian/callback is supported; update your Atlassian app and frontend accordingly.

Jira legacy OAuth vars (for non-PKCE legacy flows):
- JIRA_OAUTH_CLIENT_ID
- JIRA_OAUTH_CLIENT_SECRET
- JIRA_OAUTH_REDIRECT_URI

If required env values are missing, GET /api/oauth/atlassian/login returns a 500 with a helpful error message indicating which variables to set.

New/Aligned Routing:
- GET /api/oauth/atlassian/login
  Query: return_url (required absolute URL), scope (optional)
  Behavior: generate state + PKCE, persist state->return_url, set httpOnly sid cookie, redirect (307) to Atlassian authorize
- GET /api/oauth/atlassian/callback
  Query: code, state
  Behavior: validate state and session, exchange code for tokens, persist tokens (in-memory session), redirect 307 to saved return_url with:
    - success: ?result=success
    - error: ?result=error&message=<url-encoded message>

Compatibility/Diagnostics:
- GET /api/oauth/start -> 307 to /api/oauth/atlassian/login (preserves return_url via ?redirect=)
- GET /routes -> lists registered routes for diagnostics
- GET /api/config -> shows effective backendBaseUrl, frontendBaseUrl, redirectUri and presence flags. Use this to verify redirectUri matches what you registered.

Frontend Integration:
- Use your Connect page (e.g., /connect) as return_url:
  window.location.href = `${BACKEND_URL}/api/oauth/atlassian/login?return_url=${encodeURIComponent(window.location.origin + '/connect')}`
- After auth, the backend redirects to:
  /connect?result=success
  or /connect?result=error&message=...

Host and frontend settings:
- In cloud preview, your backend is hosted at a non-localhost domain (e.g., https://...:3001).
- Do not call localhost:3001 from the frontend preview. Instead set NEXT_PUBLIC_BACKEND_URL to the preview domain and use it for all API calls.
- Example:
  NEXT_PUBLIC_BACKEND_URL=https://vscode-internal-XXXXX-beta.beta01.cloud.kavia.ai:3001

Dotenv:
- The application attempts to load .env automatically on startup.
- Set BACKEND_PUBLIC_BASE_URL to the publicly reachable backend ORIGIN (no trailing slash, no path), for example:
  BACKEND_PUBLIC_BASE_URL=https://vscode-internal-18211-beta.beta01.cloud.kavia.ai:3001
  WRONG: BACKEND_PUBLIC_BASE_URL=https://vscode-internal-18211-beta.beta01.cloud.kavia.ai:3001/docs  <- contains a path and will be stripped
  The backend will compute:
  redirect_uri=https://vscode-internal-18211-beta.beta01.cloud.kavia.ai:3001/api/oauth/atlassian/callback
- You can verify at runtime via:
  GET {BACKEND_PUBLIC_BASE_URL}/api/config -> field "redirectUri" must match what you registered in Atlassian.
- See integration_backend/.env.example for variables.

Examples:
- Start login directly with return_url to /connect:
  GET ${NEXT_PUBLIC_BACKEND_URL}/api/oauth/atlassian/login?return_url=${encodeURIComponent(`${window.location.origin}/connect`)}
- Start via shim preserving UI redirect (alternate path):
  GET ${NEXT_PUBLIC_BACKEND_URL}/api/oauth/start?redirect=${encodeURIComponent(`${window.location.origin}/connect`)}

Redis-backed state storage:
- Set REDIS_URL=redis://localhost:6379 (or your managed Redis endpoint) to store OAuth state with TTL.
- Configure OAUTH_STATE_TTL_SECONDS=600 (default 10 minutes) to control state lifetime.
- The backend uses SETEX oauth:state:{state} -> {"return_url","code_verifier"} and consumes it once on callback.
- If REDIS_URL is not set or Redis is unavailable, an in-memory fallback is used (not suitable for production).

Diagnostics:
- GET /api/config now includes:
  { hasRedis: boolean, stateTtlSeconds: number, ... }
- GET /api/oauth/diagnostics returns:
  { backend: "redis"|"memory", approxActiveStates: number, ttlSeconds: number }
