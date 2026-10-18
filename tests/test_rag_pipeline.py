"""Unit and integration coverage for the tenant-aware RAG runtime."""

from __future__ import annotations

import gc
import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

import chromadb
from argon2 import PasswordHasher
from chromadb.api.client import SharedSystemClient
from fastapi import HTTPException
from fastapi.testclient import TestClient
from langchain_openai import OpenAIEmbeddings

from multi_tenant_rag_assistants.RAG.generation import OpenAIAnswerGenerator
from multi_tenant_rag_assistants.RAG.models import (
    Citation,
    GeneratedAnswer,
    RAGQueryResponse,
    RetrievedChunk,
)
from multi_tenant_rag_assistants.RAG.retrieval import TenantRetriever
from multi_tenant_rag_assistants.RAG.security import build_security_context
from multi_tenant_rag_assistants.RAG.service import ABSTENTION, RAGService
from multi_tenant_rag_assistants.backend import documents
from multi_tenant_rag_assistants.backend.auth import app
from multi_tenant_rag_assistants.backend.database import connect, initialize_database


class StubGenerator:
    def __init__(self, answer: str) -> None:
        self.answer = answer
        self.calls = 0

    def generate(self, question, chunks):
        self.calls += 1
        return GeneratedAnswer(self.answer)


class RAGPipelineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        initialize_database()

    def setUp(self) -> None:
        self.temp_directory = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.chroma_patch = patch.object(
            documents, "CHROMA_ROOT", Path(self.temp_directory.name) / "chroma"
        )
        self.chroma_patch.start()
        suffix = uuid4().hex
        self.slug_a = f"rag-a-{suffix}"
        self.slug_b = f"rag-b-{suffix}"
        self.user_email = f"rag-user-{suffix}@example.com"
        with connect() as connection:
            tenant_a = connection.execute(
                "INSERT INTO rag_tenants (name, slug, description) VALUES (%s, %s, '') RETURNING id, slug",
                (f"RAG A {suffix}", self.slug_a),
            ).fetchone()
            tenant_b = connection.execute(
                "INSERT INTO rag_tenants (name, slug, description) VALUES (%s, %s, '') RETURNING id, slug",
                (f"RAG B {suffix}", self.slug_b),
            ).fetchone()
            self.tenant_a = tenant_a
            self.tenant_b = tenant_b
            self.user_a = connection.execute(
                """
                INSERT INTO rag_users (username, email, password_hash, tenant_id, role)
                VALUES (%s, %s, %s, %s, 'user') RETURNING id, tenant_id, role
                """,
                (
                    f"rag-user-{suffix}",
                    self.user_email,
                    PasswordHasher().hash("Test-Pass-42"),
                    tenant_a["id"],
                ),
            ).fetchone()
            self.manager_a = connection.execute(
                """
                INSERT INTO rag_users (username, email, password_hash, tenant_id, role)
                VALUES (%s, %s, %s, %s, 'tenant_manager') RETURNING id, tenant_id, role
                """,
                (
                    f"rag-manager-{suffix}",
                    f"rag-manager-{suffix}@example.com",
                    PasswordHasher().hash("Test-Pass-42"),
                    tenant_a["id"],
                ),
            ).fetchone()
            user_b = connection.execute(
                """
                INSERT INTO rag_users (username, email, password_hash, tenant_id, role)
                VALUES (%s, %s, %s, %s, 'user') RETURNING id
                """,
                (
                    f"rag-user-b-{suffix}",
                    f"rag-user-b-{suffix}@example.com",
                    PasswordHasher().hash("Test-Pass-42"),
                    tenant_b["id"],
                ),
            ).fetchone()
            self.user_b_id = user_b["id"]
            self.doc_a = f"doc_{uuid4().hex[:16]}"
            self.ver_a = f"ver_{uuid4().hex[:16]}"
            self.doc_b = f"doc_{uuid4().hex[:16]}"
            self.ver_b = f"ver_{uuid4().hex[:16]}"
            for tenant, uploader, document_id, version_id, filename in (
                (tenant_a, self.user_a["id"], self.doc_a, self.ver_a, "alpha-policy.txt"),
                (tenant_b, self.user_b_id, self.doc_b, self.ver_b, "secret-policy.txt"),
            ):
                key = f"tenants/{documents.tenant_key(tenant)}/originals/{version_id}.txt"
                connection.execute(
                    """
                    INSERT INTO rag_documents
                        (id, tenant_id, original_filename, storage_key, current_version,
                         status, access_scope, uploaded_by)
                    VALUES (%s, %s, %s, %s, 1, 'active', 'employee', %s)
                    """,
                    (document_id, tenant["id"], filename, key, uploader),
                )
                connection.execute(
                    """
                    INSERT INTO rag_document_versions
                        (id, document_id, version_number, checksum, storage_key, mime_type,
                         size_bytes, approval_status, ingestion_status, chunk_count, approved_by)
                    VALUES (%s, %s, 1, %s, %s, 'text/plain', 10,
                            'approved', 'active', 1, %s)
                    """,
                    (version_id, document_id, "0" * 64, key, uploader),
                )

        self.context = build_security_context(self.user_a)
        self.collection = documents.chroma_collection()
        self.collection.add(
            ids=[f"{self.ver_a}_chunk_000001", f"{self.ver_b}_chunk_000001"],
            embeddings=[[1.0, 0.0, 0.0], [1.0, 0.0, 0.0]],
            documents=[
                "Alpha employees must use hardware security keys.",
                "The other tenant has a confidential launch code.",
            ],
            metadatas=[
                {
                    "tenant_id": documents.tenant_key(self.tenant_a),
                    "document_id": self.doc_a,
                    "version_id": self.ver_a,
                    "chunk_id": f"{self.ver_a}_chunk_000001",
                    "access_scope": "employee",
                    "status": "active",
                },
                {
                    "tenant_id": documents.tenant_key(self.tenant_b),
                    "document_id": self.doc_b,
                    "version_id": self.ver_b,
                    "chunk_id": f"{self.ver_b}_chunk_000001",
                    "access_scope": "employee",
                    "status": "active",
                },
            ],
        )

    def tearDown(self) -> None:
        with connect() as connection:
            connection.execute(
                "DELETE FROM rag_query_audit WHERE tenant_id IN (%s, %s)",
                (self.tenant_a["id"], self.tenant_b["id"]),
            )
            connection.execute(
                "DELETE FROM rag_documents WHERE tenant_id IN (%s, %s)",
                (self.tenant_a["id"], self.tenant_b["id"]),
            )
            connection.execute(
                "DELETE FROM rag_users WHERE tenant_id IN (%s, %s)",
                (self.tenant_a["id"], self.tenant_b["id"]),
            )
            connection.execute(
                "DELETE FROM rag_tenants WHERE id IN (%s, %s)",
                (self.tenant_a["id"], self.tenant_b["id"]),
            )
        self.chroma_patch.stop()
        SharedSystemClient.clear_system_cache()
        gc.collect()
        self.temp_directory.cleanup()

    def test_retrieval_is_tenant_filtered_before_results_are_returned(self) -> None:
        retriever = TenantRetriever(
            collection_factory=lambda: self.collection,
            embedding_function=lambda _: [1.0, 0.0, 0.0],
            max_distance=2.0,
        )
        chunks = retriever.retrieve(self.context, "What authentication is required?")
        self.assertEqual([chunk.document_id for chunk in chunks], [self.doc_a])
        self.assertNotIn("launch code", " ".join(chunk.text for chunk in chunks))

    def test_configured_chat_model_is_gpt_4o_mini(self) -> None:
        self.assertEqual(OpenAIAnswerGenerator().model, "gpt-4o-mini")

    def test_service_answers_with_validated_citations_and_audits(self) -> None:
        chunk = RetrievedChunk(
            text="Employees must use hardware security keys.",
            distance=0.1,
            document_id=self.doc_a,
            version_id=self.ver_a,
            chunk_id=f"{self.ver_a}_chunk_000001",
            filename="alpha-policy.txt",
            access_scope="employee",
        )
        events = []
        retriever = type("Retriever", (), {"retrieve": lambda *_: [chunk]})()
        service = RAGService(
            retriever=retriever,
            generator=StubGenerator("Use a hardware security key [1]."),
            audit_writer=lambda **event: events.append(event),
        )
        response = service.ask(self.context, "How should I sign in?")
        self.assertFalse(response.abstained)
        self.assertEqual(response.citations[0].filename, "alpha-policy.txt")
        self.assertEqual(events[0]["outcome"], "answered")
        self.assertNotIn("How should I sign in?", str(events[0].get("details", {})))

    def test_service_abstains_without_evidence_or_valid_citations(self) -> None:
        empty_generator = StubGenerator("This must not be called")
        empty_service = RAGService(
            retriever=type("Retriever", (), {"retrieve": lambda *_: []})(),
            generator=empty_generator,
            audit_writer=lambda **_: None,
        )
        self.assertEqual(empty_service.ask(self.context, "Unknown topic").answer, ABSTENTION)
        self.assertEqual(empty_generator.calls, 0)

        chunk = RetrievedChunk(
            "Evidence", 0.1, self.doc_a, self.ver_a, "chunk", "alpha-policy.txt", "employee"
        )
        unsupported = RAGService(
            retriever=type("Retriever", (), {"retrieve": lambda *_: [chunk]})(),
            generator=StubGenerator("An uncited answer."),
            audit_writer=lambda **_: None,
        ).ask(self.context, "Question")
        self.assertTrue(unsupported.abstained)
        self.assertEqual(unsupported.answer, ABSTENTION)

    def test_invalid_tenant_context_is_rejected(self) -> None:
        with self.assertRaises(HTTPException) as raised:
            build_security_context({"id": self.user_a["id"], "tenant_id": None, "role": "user"})
        self.assertEqual(raised.exception.status_code, 403)

    def test_authenticated_api_uses_server_derived_context(self) -> None:
        captured = {}

        class APIService:
            def ask(_, context, question, top_k):
                captured.update(context=context, question=question, top_k=top_k)
                return RAGQueryResponse(
                    request_id="qry_test",
                    answer="Use a hardware security key [1].",
                    citations=[Citation(
                        number=1,
                        document_id=self.doc_a,
                        version_id=self.ver_a,
                        chunk_id=f"{self.ver_a}_chunk_000001",
                        filename="alpha-policy.txt",
                        excerpt="Employees must use hardware security keys.",
                    )],
                    abstained=False,
                    retrieved_chunk_count=1,
                )

        with TestClient(app) as client:
            unauthenticated = client.post(
                "/api/rag/query", json={"question": "What is required?"}
            )
            self.assertEqual(unauthenticated.status_code, 401)
            login = client.post(
                "/api/auth/login",
                json={
                    "identifier": self.user_email,
                    "password": "Test-Pass-42",
                    "remember": False,
                },
            )
            self.assertEqual(login.status_code, 200)
            with patch(
                "multi_tenant_rag_assistants.RAG.api.create_rag_service",
                return_value=APIService(),
            ):
                response = client.post(
                    "/api/rag/query",
                    json={"question": "What is required?", "top_k": 3},
                )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(captured["context"].tenant_id, self.tenant_a["id"])
        self.assertEqual(captured["context"].tenant_key, documents.tenant_key(self.tenant_a))
        self.assertEqual(captured["context"].access_scopes, ("employee",))
        self.assertEqual(captured["top_k"], 3)

    def test_admin_rag_request_is_denied_and_audited(self) -> None:
        question = f"Forbidden administrator query {uuid4().hex}"
        query_hash = hashlib.sha256(question.encode("utf-8")).hexdigest()
        with TestClient(app) as client:
            login = client.post(
                "/api/auth/login",
                json={"identifier": "admin", "password": "admin", "remember": False},
            )
            self.assertEqual(login.status_code, 200)
            response = client.post("/api/rag/query", json={"question": question})
        self.assertEqual(response.status_code, 403)
        with connect() as connection:
            event = connection.execute(
                "SELECT id, outcome FROM rag_query_audit WHERE query_hash = %s",
                (query_hash,),
            ).fetchone()
            self.assertIsNotNone(event)
            self.assertEqual(event["outcome"], "denied")
            connection.execute("DELETE FROM rag_query_audit WHERE id = %s", (event["id"],))

    @unittest.skipUnless(
        os.getenv("RUN_OPENAI_RAG_TESTS") == "1",
        "Set RUN_OPENAI_RAG_TESTS=1 to run the billable OpenAI smoke test.",
    )
    def test_real_openai_embedding_and_grounded_generation(self) -> None:
        text = "Alpha employees must use hardware security keys for all production access."
        vector = OpenAIEmbeddings(model=documents.EMBEDDING_MODEL).embed_query(text)
        real_collection = chromadb.PersistentClient(
            path=str(Path(self.temp_directory.name) / "real-openai-chroma")
        ).get_or_create_collection(
            "organization_knowledge", metadata={"hnsw:space": "cosine"}
        )
        real_collection.add(
            ids=[f"{self.ver_a}_chunk_000001"],
            embeddings=[vector],
            documents=[text],
            metadatas=[{
                "tenant_id": documents.tenant_key(self.tenant_a),
                "document_id": self.doc_a,
                "version_id": self.ver_a,
                "chunk_id": f"{self.ver_a}_chunk_000001",
                "access_scope": "employee",
                "status": "active",
            }],
        )
        response = RAGService(
            retriever=TenantRetriever(
                collection_factory=lambda: real_collection,
                max_distance=1.0,
            ),
            generator=OpenAIAnswerGenerator(),
            audit_writer=lambda **_: None,
        ).ask(self.context, "What is required for production access?")
        self.assertFalse(response.abstained)
        self.assertTrue(response.citations)
        self.assertIn("[1]", response.answer)


if __name__ == "__main__":
    unittest.main()
