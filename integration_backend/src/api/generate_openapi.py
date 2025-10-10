from fastapi import FastAPI

# PUBLIC_INTERFACE
def generate_openapi_schema(app: FastAPI):
    """Return FastAPI-generated OpenAPI; hooks for post-processing can be added here."""
    schema = app.openapi()
    # Ensure ErrorResponse exists in components for standardized errors
    components = schema.setdefault("components", {}).setdefault("schemas", {})
    if "ErrorResponse" not in components:
        components["ErrorResponse"] = {
            "title": "ErrorResponse",
            "type": "object",
            "properties": {
                "status": {"type": "string"},
                "code": {"type": "string"},
                "message": {"type": "string"},
                "retry_after": {"type": ["integer", "null"]},
                "details": {"type": ["object", "null"], "additionalProperties": True},
            },
            "required": ["status", "code", "message"],
        }
    return schema
