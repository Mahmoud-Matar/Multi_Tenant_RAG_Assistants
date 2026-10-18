"""FastAPI transport for the tenant-aware RAG service."""

from __future__ import annotations

from collections.abc import Callable

from fastapi import APIRouter, Depends, HTTPException

from .audit import write_denied_query_audit
from .models import RAGQueryRequest, RAGQueryResponse
from .security import build_security_context
from .service import create_rag_service


def create_rag_router(require_chat_user: Callable[..., dict]) -> APIRouter:
    router = APIRouter(prefix="/api/rag", tags=["tenant-aware RAG"])

    @router.post("/query", response_model=RAGQueryResponse)
    def query_knowledge(
        payload: RAGQueryRequest,
        user: dict = Depends(require_chat_user),
    ) -> RAGQueryResponse:
        try:
            context = build_security_context(user)
        except HTTPException as exc:
            write_denied_query_audit(
                user=user,
                question=payload.question,
                reason=str(exc.detail),
            )
            raise
        try:
            return create_rag_service().ask(context, payload.question, payload.top_k)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(
                status_code=502,
                detail="The knowledge assistant could not complete this request.",
            ) from exc

    return router
