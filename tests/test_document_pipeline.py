"""Integration coverage for tenant-scoped document storage and ingestion."""

from __future__ import annotations

import tempfile
import unittest
import gc
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

from argon2 import PasswordHasher
from chromadb.api.client import SharedSystemClient
from fastapi.testclient import TestClient

from multi_tenant_rag_assistants.backend import documents
from multi_tenant_rag_assistants.backend.auth import app
from multi_tenant_rag_assistants.backend.database import connect


class DocumentPipelineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.client_context = TestClient(app)
        cls.client = cls.client_context.__enter__()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.client_context.__exit__(None, None, None)

    def setUp(self) -> None:
        self.temp_directory = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        temp_root = Path(self.temp_directory.name)
        self.storage_patch = patch.object(documents, "STORAGE_ROOT", temp_root / "storage")
        self.chroma_patch = patch.object(documents, "CHROMA_ROOT", temp_root / "chroma")
        self.storage_patch.start()
        self.chroma_patch.start()

        suffix = uuid4().hex
        self.tenant_slug = f"docs-{suffix}"
        self.manager_email = f"manager-{suffix}@example.com"
        self.manager_password = "Manager-Pass-42"
        with connect() as connection:
            tenant = connection.execute(
                """
                INSERT INTO rag_tenants (name, slug, description)
                VALUES (%s, %s, 'Document pipeline integration tenant')
                RETURNING id, slug
                """,
                (f"Document Pipeline {suffix}", self.tenant_slug),
            ).fetchone()
            self.tenant_id = tenant["id"]
            manager = connection.execute(
                """
                INSERT INTO rag_users
                    (username, email, password_hash, tenant_id, role)
                VALUES (%s, %s, %s, %s, 'tenant_manager')
                RETURNING id
                """,
                (
                    f"manager-{suffix}",
                    self.manager_email,
                    PasswordHasher().hash(self.manager_password),
                    self.tenant_id,
                ),
            ).fetchone()
            self.manager_id = manager["id"]

    def tearDown(self) -> None:
        self.client.post("/api/auth/logout")
        with connect() as connection:
            connection.execute(
                "DELETE FROM rag_document_audit WHERE tenant_id = %s",
                (self.tenant_id,),
            )
            connection.execute(
                "DELETE FROM rag_documents WHERE tenant_id = %s",
                (self.tenant_id,),
            )
            connection.execute("DELETE FROM rag_users WHERE id = %s", (self.manager_id,))
            connection.execute("DELETE FROM rag_tenants WHERE id = %s", (self.tenant_id,))
        self.chroma_patch.stop()
        self.storage_patch.stop()
        SharedSystemClient.clear_system_cache()
        gc.collect()
        self.temp_directory.cleanup()

    @staticmethod
    def fake_embeddings(texts: list[str]) -> list[list[float]]:
        return [[float(index + 1), 0.25, 0.75] for index, _ in enumerate(texts)]

    def login_admin(self) -> None:
        response = self.client.post(
            "/api/auth/login",
            json={"identifier": "admin", "password": "admin", "remember": False},
        )
        self.assertEqual(response.status_code, 200)

    def login_manager(self) -> None:
        response = self.client.post(
            "/api/auth/login",
            json={
                "identifier": self.manager_email,
                "password": self.manager_password,
                "remember": False,
            },
        )
        self.assertEqual(response.status_code, 200)

    def test_upload_approval_indexing_isolation_and_revocation(self) -> None:
        self.login_admin()
        admin_content = (
            b"Atlas security policy. Employees must use multifactor authentication. "
            b"Report suspicious access to the security team."
        )
        with patch.object(documents, "embed_texts", side_effect=self.fake_embeddings):
            uploaded = self.client.post(
                f"/api/admin/tenants/{self.tenant_id}/documents",
                files={"file": ("security-policy.txt", admin_content, "text/plain")},
            )
        self.assertEqual(uploaded.status_code, 202, uploaded.text)
        admin_document_id = uploaded.json()["document_id"]
        admin_version_id = uploaded.json()["version_id"]

        registry = self.client.get(
            f"/api/admin/tenants/{self.tenant_id}/documents"
        )
        self.assertEqual(registry.status_code, 200)
        indexed_document = next(
            item for item in registry.json() if item["id"] == admin_document_id
        )
        self.assertEqual(indexed_document["status"], "active")
        self.assertEqual(indexed_document["version"]["ingestion_status"], "active")
        self.assertGreater(indexed_document["version"]["chunk_count"], 0)

        with connect() as connection:
            stored = connection.execute(
                """
                SELECT d.storage_key, v.checksum
                FROM rag_documents d
                JOIN rag_document_versions v ON v.document_id = d.id
                WHERE d.id = %s AND v.id = %s
                """,
                (admin_document_id, admin_version_id),
            ).fetchone()
        self.assertTrue(stored["storage_key"].startswith("tenants/tenant_docs-"))
        self.assertNotIn("security-policy", stored["storage_key"])
        self.assertTrue((documents.STORAGE_ROOT / stored["storage_key"]).is_file())
        self.assertEqual(len(stored["checksum"]), 64)

        vectors = documents.chroma_collection().get(
            where={"document_id": admin_document_id},
            include=["metadatas"],
        )
        self.assertGreater(len(vectors["ids"]), 0)
        for metadata in vectors["metadatas"]:
            self.assertEqual(metadata["document_id"], admin_document_id)
            self.assertEqual(metadata["version_id"], admin_version_id)
            self.assertEqual(metadata["access_scope"], "employee")
            self.assertEqual(metadata["status"], "active")
            self.assertEqual(metadata["tenant_db_id"], self.tenant_id)
            self.assertTrue(metadata["tenant_id"].startswith("tenant_docs-"))

        with patch.object(documents, "OpenAIEmbeddings") as embeddings_class:
            embeddings_class.return_value.embed_query.return_value = [1.0, 0.25, 0.75]
            matches = documents.search_tenant_knowledge(
                tenant_id=self.tenant_id,
                query="What authentication is required?",
            )
        self.assertTrue(matches)
        self.assertEqual(matches[0]["metadata"]["document_id"], admin_document_id)

        with connect() as connection:
            connection.execute(
                "UPDATE rag_documents SET status = 'failed' WHERE id = %s",
                (admin_document_id,),
            )
        self.assertEqual(
            documents.search_tenant_knowledge(
                tenant_id=self.tenant_id,
                query="This must not reach the embedding service",
            ),
            [],
        )
        with connect() as connection:
            connection.execute(
                "UPDATE rag_documents SET status = 'active' WHERE id = %s",
                (admin_document_id,),
            )

        with patch.object(documents, "embed_texts", side_effect=self.fake_embeddings):
            reindexed = self.client.post(
                f"/api/admin/tenants/{self.tenant_id}/documents/{admin_document_id}/reindex"
            )
        self.assertEqual(reindexed.status_code, 202, reindexed.text)
        self.assertEqual(reindexed.json()["version_number"], 2)
        with connect() as connection:
            old_version = connection.execute(
                "SELECT ingestion_status FROM rag_document_versions WHERE id = %s",
                (admin_version_id,),
            ).fetchone()
            new_version = connection.execute(
                "SELECT ingestion_status FROM rag_document_versions WHERE id = %s",
                (reindexed.json()["version_id"],),
            ).fetchone()
        self.assertEqual(old_version["ingestion_status"], "superseded")
        self.assertEqual(new_version["ingestion_status"], "active")
        self.assertEqual(
            documents.chroma_collection().get(ids=vectors["ids"])["ids"], []
        )

        duplicate = self.client.post(
            f"/api/admin/tenants/{self.tenant_id}/documents",
            files={"file": ("duplicate.txt", admin_content, "text/plain")},
        )
        self.assertEqual(duplicate.status_code, 409)

        invalid = self.client.post(
            f"/api/admin/tenants/{self.tenant_id}/documents",
            files={"file": ("not-really.pdf", b"plain text", "application/pdf")},
        )
        self.assertEqual(invalid.status_code, 400)
        with connect() as connection:
            rejected_audit = connection.execute(
                """
                SELECT 1 FROM rag_document_audit
                WHERE tenant_id = %s AND action = 'document_upload'
                  AND outcome = 'rejected'
                """,
                (self.tenant_id,),
            ).fetchone()
        self.assertIsNotNone(rejected_audit)

        self.client.post("/api/auth/logout")
        self.login_manager()
        manager_content = b"IT onboarding guide for approved tenant employees."
        manager_upload = self.client.post(
            "/api/manager/documents",
            files={"file": ("onboarding.txt", manager_content, "text/plain")},
        )
        self.assertEqual(manager_upload.status_code, 202, manager_upload.text)
        manager_document_id = manager_upload.json()["document_id"]
        manager_version_id = manager_upload.json()["version_id"]
        self.assertEqual(manager_upload.json()["approval_status"], "pending")
        manager_registry = self.client.get("/api/manager/documents")
        pending = next(
            item for item in manager_registry.json() if item["id"] == manager_document_id
        )
        self.assertEqual(pending["status"], "pending_approval")
        self.assertEqual(pending["version"]["ingestion_status"], "quarantined")
        pending_vectors = documents.chroma_collection().get(
            where={"document_id": manager_document_id}
        )
        self.assertEqual(pending_vectors["ids"], [])
        self.assertEqual(
            self.client.get(
                f"/api/admin/tenants/{self.tenant_id}/documents"
            ).status_code,
            403,
        )

        self.client.post("/api/auth/logout")
        self.login_admin()
        with patch.object(documents, "embed_texts", side_effect=self.fake_embeddings):
            approval = self.client.post(
                f"/api/admin/documents/{manager_version_id}/approve"
            )
        self.assertEqual(approval.status_code, 202, approval.text)
        approved_registry = self.client.get(
            f"/api/admin/tenants/{self.tenant_id}/documents"
        ).json()
        approved = next(
            item for item in approved_registry if item["id"] == manager_document_id
        )
        self.assertEqual(approved["status"], "active")
        self.assertEqual(approved["version"]["approval_status"], "approved")
        self.assertEqual(approved["version"]["ingestion_status"], "active")

        self.client.post("/api/auth/logout")
        self.login_manager()
        revoked = self.client.delete(
            f"/api/manager/documents/{manager_document_id}"
        )
        self.assertEqual(revoked.status_code, 204)
        remaining = self.client.get("/api/manager/documents").json()
        self.assertNotIn(manager_document_id, {item["id"] for item in remaining})
        removed_vectors = documents.chroma_collection().get(
            where={"document_id": manager_document_id}
        )
        self.assertEqual(removed_vectors["ids"], [])
        with connect() as connection:
            revoked_record = connection.execute(
                "SELECT status FROM rag_documents WHERE id = %s",
                (manager_document_id,),
            ).fetchone()
            revoked_version = connection.execute(
                "SELECT ingestion_status FROM rag_document_versions WHERE id = %s",
                (manager_version_id,),
            ).fetchone()
        self.assertEqual(revoked_record["status"], "deleted")
        self.assertEqual(revoked_version["ingestion_status"], "revoked")


if __name__ == "__main__":
    unittest.main()
