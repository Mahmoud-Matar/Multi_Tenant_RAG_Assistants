"""Lifecycle and enforcement tests for signed Tenant Domain Contracts."""

from __future__ import annotations

import unittest
from uuid import uuid4

from argon2 import PasswordHasher
from fastapi import HTTPException
from fastapi.testclient import TestClient

from multi_tenant_rag_assistants.RAG.security import build_security_context
from multi_tenant_rag_assistants.backend.auth import app
from multi_tenant_rag_assistants.backend.database import connect


class TenantDomainContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.client_context = TestClient(app, headers={"Origin": "http://testserver"})
        cls.client = cls.client_context.__enter__()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.client_context.__exit__(None, None, None)

    def setUp(self) -> None:
        with connect() as connection:
            connection.execute("DELETE FROM auth_rate_limits")
        self.client.post("/api/auth/logout")
        login = self.client.post(
            "/api/auth/login",
            json={"identifier": "admin", "password": "admin", "remember": False},
        )
        self.assertEqual(login.status_code, 200)
        suffix = uuid4().hex
        created = self.client.post(
            "/api/admin/tenants",
            json={
                "name": f"Contract Tenant {suffix}",
                "slug": f"contract-{suffix}",
                "description": "Tenant Domain Contract integration test",
            },
        )
        self.assertEqual(created.status_code, 201, created.text)
        self.tenant = created.json()["tenant"]
        self.user_ids: list[int] = []

    def tearDown(self) -> None:
        self.client.post("/api/auth/logout")
        with connect() as connection:
            connection.execute(
                "DELETE FROM rag_query_audit WHERE tenant_id = %s", (self.tenant["id"],)
            )
            connection.execute(
                "DELETE FROM rag_document_audit WHERE tenant_id = %s",
                (self.tenant["id"],),
            )
            connection.execute(
                "DELETE FROM rag_documents WHERE tenant_id = %s", (self.tenant["id"],)
            )
            connection.execute(
                "DELETE FROM rag_users WHERE tenant_id = %s", (self.tenant["id"],)
            )
            connection.execute(
                "DELETE FROM rag_tenants WHERE id = %s", (self.tenant["id"],)
            )

    def activate_default_contract(self) -> dict:
        contract = self.client.get(
            f"/api/admin/tenants/{self.tenant['id']}/contracts"
        ).json()[0]
        if contract["state"] == "draft":
            approved = self.client.post(
                f"/api/admin/contracts/{contract['id']}/approve"
            )
            self.assertEqual(approved.status_code, 200)
            activated = self.client.post(
                f"/api/admin/contracts/{contract['id']}/activate"
            )
            self.assertEqual(activated.status_code, 200)
        return contract

    def test_contract_lifecycle_activation_and_rollback(self) -> None:
        history = self.client.get(
            f"/api/admin/tenants/{self.tenant['id']}/contracts"
        )
        self.assertEqual(history.status_code, 200)
        default_version = history.json()[0]
        self.assertEqual(default_version["state"], "draft")
        self.assertTrue(default_version["signature_valid"])
        self.assertFalse(self.tenant["is_active"])

        blocked_activation = self.client.patch(
            f"/api/admin/tenants/{self.tenant['id']}", json={"is_active": True}
        )
        self.assertEqual(blocked_activation.status_code, 409)
        approved_default = self.client.post(
            f"/api/admin/contracts/{default_version['id']}/approve"
        )
        self.assertEqual(approved_default.status_code, 200)
        activated_default = self.client.post(
            f"/api/admin/contracts/{default_version['id']}/activate"
        )
        self.assertEqual(activated_default.status_code, 200)
        with connect() as connection:
            tenant_status = connection.execute(
                "SELECT is_active FROM rag_tenants WHERE id = %s", (self.tenant["id"],)
            ).fetchone()
        self.assertTrue(tenant_status["is_active"])

        contract = default_version["contract"]
        contract["domain"]["allowed_topics"] = ["employee policy"]
        contract["domain"]["excluded_topics"] = ["medical advice"]
        contract["thresholds"]["top_k"] = 3
        contract["metrics"] = [
            {
                "id": "assistant_abstention_rate",
                "label": "Assistant abstention rate",
                "definition": "Share of eligible requests without a supported answer",
                "allowed_roles": ["tenant_manager"],
                "minimum_group_size": 10,
                "allowed_filters": ["date_range", "intent"],
            }
        ]

        created = self.client.post(
            f"/api/admin/tenants/{self.tenant['id']}/contracts", json=contract
        )
        self.assertEqual(created.status_code, 201, created.text)
        draft = created.json()["contract"]
        self.assertEqual(draft["version"], 2)
        self.assertEqual(draft["state"], "draft")

        premature = self.client.post(f"/api/admin/contracts/{draft['id']}/activate")
        self.assertEqual(premature.status_code, 409)
        approved = self.client.post(f"/api/admin/contracts/{draft['id']}/approve")
        self.assertEqual(approved.status_code, 200)
        self.assertEqual(approved.json()["contract"]["state"], "approved")
        activated = self.client.post(f"/api/admin/contracts/{draft['id']}/activate")
        self.assertEqual(activated.status_code, 200)
        self.assertEqual(activated.json()["contract"]["state"], "active")

        history = self.client.get(
            f"/api/admin/tenants/{self.tenant['id']}/contracts"
        ).json()
        states = {item["version"]: item["state"] for item in history}
        self.assertEqual(states, {2: "active", 1: "superseded"})
        self.assertTrue(all(item["signature_valid"] for item in history))

        restored = self.client.post(
            f"/api/admin/contracts/{default_version['id']}/rollback"
        )
        self.assertEqual(restored.status_code, 200, restored.text)
        restored_contract = restored.json()["contract"]
        self.assertEqual(restored_contract["version"], 3)
        self.assertEqual(restored_contract["state"], "active")
        self.assertEqual(restored_contract["based_on_id"], default_version["id"])

        with connect() as connection:
            previous = connection.execute(
                "SELECT state FROM tenant_domain_contracts WHERE id = %s", (draft["id"],)
            ).fetchone()
        self.assertEqual(previous["state"], "rolled_back")

    def test_tampered_active_contract_fails_closed(self) -> None:
        self.activate_default_contract()
        suffix = uuid4().hex
        with connect() as connection:
            user = connection.execute(
                """
                INSERT INTO rag_users (username, email, password_hash, tenant_id, role)
                VALUES (%s, %s, %s, %s, 'user')
                RETURNING id, tenant_id, role
                """,
                (
                    f"contract-user-{suffix}",
                    f"contract-user-{suffix}@example.com",
                    PasswordHasher().hash("Contract-Test-42"),
                    self.tenant["id"],
                ),
            ).fetchone()
            connection.execute(
                """
                UPDATE tenant_domain_contracts
                SET contract = jsonb_set(contract, '{name}', '"tampered contract"')
                WHERE tenant_id = %s AND state = 'active'
                """,
                (self.tenant["id"],),
            )

        with self.assertRaises(HTTPException) as raised:
            build_security_context(user)
        self.assertEqual(raised.exception.status_code, 503)
        self.assertEqual(
            raised.exception.detail, "The tenant policy is unavailable or invalid."
        )

if __name__ == "__main__":
    unittest.main()
