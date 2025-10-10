from typing import Optional, Dict, Any
from fastapi import HTTPException
from pydantic import BaseModel, Field

# PUBLIC_INTERFACE
class ErrorCode:
    """Enum-like class for standardized error codes."""
    TOKEN_EXPIRED = "TOKEN_EXPIRED"
    RATE_LIMITED = "RATE_LIMITED"
    VALIDATION = "VALIDATION"
    NOT_CONNECTED = "NOT_CONNECTED"
    VENDOR_ERROR = "VENDOR_ERROR"
    UNAUTHORIZED = "UNAUTHORIZED"
    FORBIDDEN = "FORBIDDEN"
    NOT_FOUND = "NOT_FOUND"
    INTERNAL_ERROR = "INTERNAL_ERROR"


# PUBLIC_INTERFACE
class ErrorResponse(BaseModel):
    """Standardized error response shape across connector routes."""
    status: str = Field(default="error", description="Fixed value 'error'.")
    code: str = Field(..., description="Machine-readable error code.")
    message: str = Field(..., description="Human-readable description.")
    retry_after: Optional[int] = Field(None, description="Seconds to wait before retrying, when applicable.")
    details: Optional[Dict[str, Any]] = Field(None, description="Optional additional error details.")


def http_error(
    status_code: int,
    code: str,
    message: str,
    retry_after: Optional[int] = None,
    details: Optional[Dict[str, Any]] = None,
) -> HTTPException:
    """Create an HTTPException with the standardized error response body."""
    payload = ErrorResponse(code=code, message=message, retry_after=retry_after, details=details).dict()
    headers = {}
    if retry_after is not None:
        headers["Retry-After"] = str(retry_after)
    return HTTPException(status_code=status_code, detail=payload, headers=headers)


def map_vendor_error(e: Exception) -> HTTPException:
    """
    Map vendor exceptions to a standardized HTTP error.
    Extend as vendor clients raise richer exception types.
    """
    message = "Vendor error"
    code = ErrorCode.VENDOR_ERROR
    status = 502
    retry_after = None

    # Basic mapping by attributes
    status_attr = getattr(e, "status", None) or getattr(e, "status_code", None)
    if status_attr == 401:
        return http_error(401, ErrorCode.UNAUTHORIZED, "Unauthorized with vendor (token invalid/expired)")
    if status_attr == 403:
        return http_error(403, ErrorCode.FORBIDDEN, "Forbidden by vendor")
    if status_attr == 404:
        return http_error(404, ErrorCode.NOT_FOUND, "Resource not found at vendor")
    if status_attr == 429:
        retry_after_hdr = getattr(e, "retry_after", None)
        if isinstance(retry_after_hdr, int):
            retry_after = retry_after_hdr
        return http_error(429, ErrorCode.RATE_LIMITED, "Rate limited by vendor", retry_after=retry_after)

    return http_error(status, code, message)
