import os
import uvicorn

# PUBLIC_INTERFACE
def main():
    """Run the FastAPI app on port 3001 for local/dev usage.
    Use uvicorn module path 'src.api.main:app'. Ensure PYTHONPATH includes integration_backend/.
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
    uvicorn.run("src.api.main:app", host=host, port=port, reload=False)

if __name__ == "__main__":
    main()
