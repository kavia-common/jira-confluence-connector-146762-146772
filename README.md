# jira-confluence-connector-146762-146772

## Integration Backend - Persistence Layer

This backend includes a lightweight SQLAlchemy-based persistence layer using SQLite by default.
- Configure DB via INTEGRATION_DB_URL in an `.env` file (see `integration_backend/.env.example`).
- Default: `sqlite:///./integration.db` created in the backend working directory.
- Tables are auto-created at startup for demo purposes.

### Quick start (dev)
1. Create and activate your environment.
2. Install dependencies:
   - `pip install -r integration_backend/requirements.txt`
3. Run API:
   - `uvicorn src.api.main:app --reload --port 3001 --app-dir integration_backend`
4. Generate OpenAPI spec (optional, while API is running is not required):
   - `python -m src.api.generate_openapi` (run from `integration_backend` directory)

### API Highlights
- Auth (demo):
  - POST /auth/token -> returns a demo bearer token tied to a created/updated user
  - Use header: `Authorization: Bearer demo-token-user-<id>`
- Users:
  - POST /users -> create/idempotent user
  - GET /users -> list users (requires Authorization)
  - GET /users/{user_id} -> fetch user (requires Authorization)
- Integrations (placeholders):
  - POST /integrations/jira/connect -> save JIRA base_url and token for current user
  - POST /integrations/confluence/connect -> save Confluence base_url and token for current user
  - GET /integrations/jira/projects/fetch -> returns stored JIRA projects for current user
  - GET /integrations/confluence/pages/fetch -> returns stored Confluence pages for current user
- Data operations:
  - POST /jira/projects, GET /jira/projects/{owner_id}
  - POST /confluence/pages, GET /confluence/pages/{owner_id}