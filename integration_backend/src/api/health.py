# PUBLIC_INTERFACE
from fastapi import APIRouter
from fastapi.responses import JSONResponse

router = APIRouter()

@router.get(
    "/",
    tags=["Health"],
    summary="Health Check",
    description="Health check endpoint indicating the API is up.\n\nReturns:\n    JSON with status and a simple message.",
)
def health_check():
    """Simple health check endpoint."""
    return JSONResponse({"status": "ok", "message": "integration_backend running"})

@router.get(
    "/health",
    tags=["Health"],
    summary="Health Check (alias)",
    description="Alias endpoint for health checks. Returns the same payload as '/'.",
)
def health_check_alias():
    """Alias health endpoint for compatibility."""
    return JSONResponse({"status": "ok", "message": "integration_backend running"})
