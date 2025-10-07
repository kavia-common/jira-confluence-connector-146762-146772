# PUBLIC_INTERFACE
from fastapi import APIRouter
from fastapi.responses import JSONResponse

router = APIRouter()


@router.get(
    "/auth/status",
    tags=["Auth"],
    summary="Connection status",
    description="Lightweight endpoint to indicate connection status to the frontend. Returns { connected: false } for now unless a session cookie indicates otherwise.",
    responses={
        200: {"description": "Successful Response", "content": {"application/json": {"example": {"connected": False}}}},
    },
)
def auth_status():
    """Return a minimal connection status JSON.

    For now, always returns connected: false. This prevents 404s from being treated as errors by the frontend.
    Future implementations can inspect an httpOnly session cookie and return true/false accordingly.
    """
    return JSONResponse({"connected": False})
