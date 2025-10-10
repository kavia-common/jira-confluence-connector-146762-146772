from typing import Optional, Dict, Any
from fastapi import HTTPException, status as http_status

# PUBLIC_INTERFACE
def error_response(code: str, message: str, status_code: int = http_status.HTTP_400_BAD_REQUEST, retry_after: Optional[int] = None, details: Optional[Dict[str, Any]] = None) -> HTTPException:
    """
    Standardized error response factory.

    Args:
        code: Machine-readable error code (e.g., UNAUTHORIZED, TOKEN_EXPIRED, RATE_LIMITED, VALIDATION_ERROR, VENDOR_ERROR, CONFIG_ERROR).
        message: Human-readable message describing the error.
        status_code: HTTP status code to return.
        retry_after: Optional seconds after which the client can retry (used for rate limiting).
        details: Optional dictionary of structured details for debugging.

    Returns:
        HTTPException configured with standardized payload for FastAPI to raise.
    """
    payload: Dict[str, Any] = {
        "status": "error",
        "code": code,
        "message": message,
    }
    if retry_after is not None:
        payload["retry_after"] = retry_after
    if details:
        payload["details"] = details
    return HTTPException(status_code=status_code, detail=payload)
