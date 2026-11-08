import os


__version__ = "0.2.0"


def main() -> None:
    """Run the local Atlas API and frontend server."""
    import uvicorn

    uvicorn.run(
        "multi_tenant_rag_assistants.backend.auth:app",
        host=os.getenv("APP_HOST", "127.0.0.1"),
        port=int(os.getenv("APP_PORT", "8000")),
        reload=os.getenv("APP_RELOAD", "false").lower() == "true",
    )

if __name__ == "__main__":
    main()
