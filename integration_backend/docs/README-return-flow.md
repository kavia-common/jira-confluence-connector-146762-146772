# Atlassian OAuth return_url Flow

Endpoints:
- GET /api/oauth/atlassian/login?return_url=<absolute-url>
  - Validates return_url is absolute, generates state + PKCE, stores state->return_url with TTL, sets httpOnly sid cookie, and 307-redirects to Atlassian authorize.
- GET /api/oauth/atlassian/callback?code=...&state=...
  - Validates state against the session, exchanges code for tokens, persists in session (in-memory demo), and 307-redirects back to the saved return_url:
    - success: ?result=success
    - error: ?result=error&message=<url-encoded message>

Configuration:
- ATLASSIAN_CLIENT_ID (required)
- ATLASSIAN_REDIRECT_URI (required; must match Atlassian app)
- ATLASSIAN_CLIENT_SECRET (optional with PKCE)
- ATLASSIAN_SCOPES (optional; space-separated)
- BACKEND_CORS_ORIGINS should include the frontend origin.

State/TTL and Diagnostics:
- A 10-minute TTL is applied to state mappings created at /api/oauth/atlassian/login. Late callbacks will result in a clear error and a redirect back to return_url with result=error.
- You can inspect active state entries during development using GET /api/oauth/diagnostics (non-production). It returns masked state identifiers, age, TTL, and the return_url host for debugging.

Security Notes:
- In-memory state and session stores are for demo only. Replace with Redis or DB for production.
- Use HTTPS so Secure cookies are transmitted.
