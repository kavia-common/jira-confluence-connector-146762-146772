import os
import uvicorn

# PUBLIC_INTERFACE
def main():
    """Run the FastAPI app on port 3001 for local/dev usage."""
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "3001"))
    uvicorn.run("src.api.main:app", host=host, port=port, reload=False)

if __name__ == "__main__":
    main()
