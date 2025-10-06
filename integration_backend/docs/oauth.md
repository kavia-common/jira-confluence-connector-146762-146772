# Atlassian OAuth 2.0 (3LO) with PKCE

Endpoints:
- GET /api/oauth/atlassian/login
- GET /api/oauth/callback/atlassian
- POST /api/oauth/atlassian/refresh
- GET /api/atlassian/resources

How it works:
1. Frontend navigates the browser to /api/oauth/atlassian/login. The backend generates a state and PKCE values, stores them in a server-side session keyed by an httpOnly cookie, and redirects to Atlassian authorize.
2. Atlassian redirects back to /api/oauth/callback/atlassian with a code and state. Backend validates state, exchanges code for tokens using code_verifier, stores tokens in the session, and redirects to APP_FRONTEND_URL (default /connected).
3. Frontend can call GET /api/atlassian/resources to verify and list accessible cloud IDs. The httpOnly cookie is automatically sent by the browser.

Environment variables:
- ATLASSIAN_CLIENT_ID (required)
- ATLASSIAN_CLIENT_SECRET (optional)
- ATLASSIAN_REDIRECT_URI (required; must match Atlassian console, e.g. https://<backend>/api/oauth/callback/atlassian)
- ATLASSIAN_SCOPES (optional; space-separated)
- FRONTEND_BASE_URL (optional; absolute frontend URL for post-auth redirect)
- BACKEND_CORS_ORIGINS (optional; comma-separated; include your frontend origin)

Jira (legacy/non-PKCE) OAuth variables:
- JIRA_OAUTH_CLIENT_ID
- JIRA_OAUTH_CLIENT_SECRET
- JIRA_OAUTH_REDIRECT_URI
  Set this to the provided callback URL:
  https://vscode-internal-36910-beta.beta01.cloud.kavia.ai:4000/oauth/jira

Security notes:
- This demo uses an in-memory session store. Replace with Redis for production.
- Ensure HTTPS so cookies with Secure flag are included.
- Validate and rotate refresh tokens as per Atlassian best practices.

Frontend example (Next.js button):
```
<button onClick={() => { window.location.href = `${process.env.NEXT_PUBLIC_BACKEND_URL}/api/oauth/atlassian/login`; }}>
  Connect Atlassian
</button>
```
Then, on a status page, call:
```
fetch(`${process.env.NEXT_PUBLIC_BACKEND_URL}/api/atlassian/resources`, { credentials: 'include' })
  .then(r => r.json()).then(console.log)
```
