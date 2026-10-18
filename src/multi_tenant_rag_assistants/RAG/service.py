"""Orchestration for tenant-aware retrieval and grounded generation."""

from __future__ import annotations

from time import monotonic
from uuid import uuid4

from .audit import write_query_audit
from .generation import OpenAIAnswerGenerator
from .grounding import validate_citations
from .models import RAGQueryResponse, SecurityContext
from .retrieval import TenantRetriever
from .screening import screen_query


ABSTENTION = "I couldn't find enough authorized information to answer that question."


class RAGService:
    def __init__(self, retriever=None, generator=None, audit_writer=write_query_audit) -> None:
        self.retriever = retriever or TenantRetriever()
        self.generator = generator or OpenAIAnswerGenerator()
        self.audit_writer = audit_writer

    def ask(
        self, context: SecurityContext, question: str, top_k: int | None = None
    ) -> RAGQueryResponse:
        started = monotonic()
        request_id = f"qry_{uuid4().hex[:20]}"
        try:
            normalized = screen_query(question)
        except ValueError:
            self.audit_writer(
                request_id=request_id,
                context=context,
                question=question,
                outcome="denied",
                retrieved_count=0,
                cited_count=0,
                latency_ms=round((monotonic() - started) * 1000),
                details={"reason": "input_screening"},
            )
            raise
        chunks = []
        try:
            chunks = self.retriever.retrieve(context, normalized, top_k)
            if not chunks:
                response = RAGQueryResponse(
                    request_id=request_id,
                    answer=ABSTENTION,
                    citations=[],
                    abstained=True,
                    retrieved_chunk_count=0,
                )
                outcome = "abstained"
            else:
                generated = self.generator.generate(normalized, chunks)
                citations = validate_citations(generated.answer, chunks)
                if not citations:
                    response = RAGQueryResponse(
                        request_id=request_id,
                        answer=ABSTENTION,
                        citations=[],
                        abstained=True,
                        retrieved_chunk_count=len(chunks),
                    )
                    outcome = "abstained"
                else:
                    response = RAGQueryResponse(
                        request_id=request_id,
                        answer=generated.answer,
                        citations=citations,
                        abstained=False,
                        retrieved_chunk_count=len(chunks),
                    )
                    outcome = "answered"
            self.audit_writer(
                request_id=request_id,
                context=context,
                question=normalized,
                outcome=outcome,
                retrieved_count=len(chunks),
                cited_count=len(response.citations),
                latency_ms=round((monotonic() - started) * 1000),
            )
            return response
        except Exception as exc:
            self.audit_writer(
                request_id=request_id,
                context=context,
                question=normalized,
                outcome="failed",
                retrieved_count=len(chunks),
                cited_count=0,
                latency_ms=round((monotonic() - started) * 1000),
                details={"error_type": exc.__class__.__name__},
            )
            raise


def create_rag_service() -> RAGService:
    return RAGService()
