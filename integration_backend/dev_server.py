import os
import uvicorn

# PUBLIC_INTERFACE
def main():
    """Run the FastAPI app on port 3001 for local/dev usage.

    This uses the uvicorn module path 'src.api.main:app'.
    Notes:
    - No secrets are required at import time; missing OAuth envs will not prevent startup.
    - Use HOST and PORT envs to override bind address and port (defaults: 0.0.0.0:3001).
    """
    # Import here to surface any import-time errors in a controlled way
    try:
        from src.api.main import app  # noqa: F401
    except Exception:
        # Print a clear message to logs before failing the process
        import traceback
        print("Failed to import src.api.main:app. Traceback follows:")
        traceback.print_exc()
        raise

    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "3001"))
    # Explicitly specify factory path string; avoids issues with double import
    uvicorn.run("src.api.main:app", host=host, port=port, reload=False, lifespan="on")

if __name__ == "__main__":
    main()
