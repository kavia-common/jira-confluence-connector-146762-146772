# Authentication and OAuth

This backend supports OAuth flows for Atlassian (Jira/Confluence).

Key routes:
- GET /auth/jira/login
  - Returns JSON { url } by default with Atlassian authorize URL.
  - If redirect=true is provided, responds with 307 redirect to Atlassian and sets state cookie.
- GET /auth/jira/callback
  - Validates state via cookie + query parameter.
  - Exchanges code for tokens via connector.
  - Redirects back to frontend return_url if provided in state, else to /login.

Health:
- GET /healthz -> {"status":"ok"}
- GET /health -> {"status":"ok"}

CSRF/session helpers:
- GET /auth/csrf -> issues a CSRF cookie and returns token for header echo
- GET /auth/session -> check bearer token and returns authenticated state
- POST /auth/refresh -> exchange refresh for new access token
- POST /auth/logout -> stateless JWT logout indicator

Notes:
- For local validation, OAuth envs are optional; login returns 400 if required envs are missing. Server still boots.
- Ensure JIRA_REDIRECT_URI matches your Atlassian app configuration exactly.
