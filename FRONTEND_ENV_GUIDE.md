Frontend environment guide (Next.js)

- Frontend dev server must run on port 3000.
- All API calls should target the backend on port 3001.

Recommended .env.local settings for the Next.js container (integration_frontend):
- NEXT_PUBLIC_BACKEND_BASE_URL=http://localhost:3001
- NEXT_PUBLIC_APP_FRONTEND_URL=http://localhost:3000
- NEXT_PUBLIC_ATLASSIAN_CLOUD_BASE_URL=<your-site>.atlassian.net

OAuth login:
- Frontend should call backend endpoints to initiate OAuth:
  GET /auth/jira/login    or    GET /api/auth/jira/login
- The backend constructs redirect_uri and must use port 3001 for callbacks.
