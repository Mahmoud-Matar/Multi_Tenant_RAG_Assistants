def main() -> None:
    """Run the local Atlas API and frontend server."""
    import uvicorn

    uvicorn.run(
        "multi_tenant_rag_assistants.backend.auth:app",
        host="127.0.0.1",
        port=8000,
        reload=True,
    )

if __name__ == "__main__":
    main()
