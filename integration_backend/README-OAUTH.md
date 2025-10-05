# OAuth Start Flow (Backend)

Required environment variables:
- ATLASSIAN_CLIENT_ID
- ATLASSIAN_REDIRECT_URI

If these are missing, GET /api/oauth/atlassian/login will respond with 500 and a JSON error.

Routing:
- GET /api/oauth/start -> 307 to /api/oauth/atlassian/login (passes ?redirect=<return_url> if provided)
- GET /api/oauth/atlassian/login -> 302 to Atlassian authorize URL

Dotenv:
- The application attempts to load .env automatically on startup.
