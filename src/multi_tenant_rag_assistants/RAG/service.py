"""Orchestration for tenant-aware retrieval and grounded generation."""

from __future__ import annotations

from time import monotonic
from uuid import uuid4

from .audit import write_query_audit
from .generation import OpenAIAnswerGenerator
from .grounding import validate_citations
from .incidents import write_security_incident
from .models import RAGQueryResponse, SecurityContext
from .retrieval import TenantRetriever
from .screening import screen_query
from .threats import screen_for_threats


ABSTENTION = "I couldn't find enough authorized information to answer that question."
SECURITY_BLOCKED = (
    "I can't complete this request because it requires security review. "
    "Your tenant's security contacts have been notified."
)


class RAGService:
    def __init__(
        self,
        retriever=None,
        generator=None,
        audit_writer=write_query_audit,
        incident_writer=write_security_incident,
    ) -> None:
        self.retriever = retriever or TenantRetriever()
        self.generator = generator
        self.audit_writer = audit_writer
        self.incident_writer = incident_writer

    def _record_findings(
        self, *, context, request_id, source, findings, chunk=None
    ) -> list[str]:
        return [
            self.incident_writer(
                context=context,
                request_id=request_id,
                source=source,
                finding=finding,
                chunk=chunk,
            )
            for finding in findings
        ]

    def _security_response(
        self, *, context, request_id: str, retrieved_count: int
    ) -> RAGQueryResponse:
        return RAGQueryResponse(
            request_id=request_id,
            policy_version=context.contract_version,
            answer=SECURITY_BLOCKED,
            citations=[],
            abstained=True,
            retrieved_chunk_count=retrieved_count,
            security_blocked=True,
        )

    def ask(
        self, context: SecurityContext, question: str, top_k: int | None = None
    ) -> RAGQueryResponse:
        started = monotonic()
        request_id = f"qry_{uuid4().hex[:20]}"
        query_findings = screen_for_threats(question, source="user_query")
        if query_findings:
            incident_ids = self._record_findings(
                context=context,
                request_id=request_id,
                source="user_query",
                findings=query_findings,
            )
            response = self._security_response(
                context=context, request_id=request_id, retrieved_count=0
            )
            self.audit_writer(
                request_id=request_id,
                context=context,
                question=question,
                outcome="denied",
                retrieved_count=0,
                cited_count=0,
                latency_ms=round((monotonic() - started) * 1000),
                details={
                    "reason": "security_screening",
                    "incident_ids": incident_ids,
                    "categories": sorted({item.category for item in query_findings}),
                },
            )
            return response
        try:
            domain = context.contract["domain"]
            normalized = screen_query(
                question,
                allowed_topics=domain.get("allowed_topics"),
                excluded_topics=domain.get("excluded_topics"),
            )
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
            abstention = domain.get("refusal_message", ABSTENTION)
            chunks = self.retriever.retrieve(context, normalized, top_k)
            incident_ids = []
            incident_categories = set()
            for chunk in chunks:
                findings = screen_for_threats(chunk.text, source="retrieved_content")
                if not findings:
                    continue
                incident_ids.extend(
                    self._record_findings(
                        context=context,
                        request_id=request_id,
                        source="retrieved_content",
                        findings=findings,
                        chunk=chunk,
                    )
                )
                incident_categories.update(item.category for item in findings)
            if incident_ids:
                response = self._security_response(
                    context=context,
                    request_id=request_id,
                    retrieved_count=len(chunks),
                )
                self.audit_writer(
                    request_id=request_id,
                    context=context,
                    question=normalized,
                    outcome="denied",
                    retrieved_count=len(chunks),
                    cited_count=0,
                    latency_ms=round((monotonic() - started) * 1000),
                    details={
                        "reason": "retrieved_content_screening",
                        "incident_ids": incident_ids,
                        "categories": sorted(incident_categories),
                    },
                )
                return response
            if not chunks:
                response = RAGQueryResponse(
                    request_id=request_id,
                    policy_version=context.contract_version,
                    answer=abstention,
                    citations=[],
                    abstained=True,
                    retrieved_chunk_count=0,
                )
                outcome = "abstained"
            else:
                generator = self.generator or OpenAIAnswerGenerator(
                    model=context.contract["models"]["chat_model"]
                )
                generated = generator.generate(normalized, chunks)
                citations = validate_citations(
                    generated.answer,
                    chunks,
                    minimum_support=context.contract["thresholds"][
                        "minimum_citation_support"
                    ],
                )
                if not citations:
                    response = RAGQueryResponse(
                        request_id=request_id,
                        policy_version=context.contract_version,
                        answer=abstention,
                        citations=[],
                        abstained=True,
                        retrieved_chunk_count=len(chunks),
                    )
                    outcome = "abstained"
                else:
                    response = RAGQueryResponse(
                        request_id=request_id,
                        policy_version=context.contract_version,
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
