"""Integration tests for the local PostgreSQL authentication flow."""

from __future__ import annotations

import unittest
from urllib.parse import parse_qs, urlparse
from unittest.mock import patch
from uuid import uuid4

from argon2 import PasswordHasher
from fastapi.testclient import TestClient

from multi_tenant_rag_assistants.backend.auth import app
from multi_tenant_rag_assistants.backend.auth_security import validate_signing_secret
from multi_tenant_rag_assistants.backend.contracts import ensure_default_contract
from multi_tenant_rag_assistants.backend.database import connect


class AuthenticationApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.client_context = TestClient(app, headers={"Origin": "http://127.0.0.1:8000"})
        cls.client = cls.client_context.__enter__()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.client_context.__exit__(None, None, None)

    def setUp(self) -> None:
        self.client.cookies.clear()
        self.email = f"integration-{uuid4().hex}@example.com"
        self.created_emails = [self.email]
        self.created_tenant_ids = []
        with connect() as connection:
            connection.execute("DELETE FROM auth_rate_limits")

    def tearDown(self) -> None:
        with connect() as connection:
            connection.execute(
                "DELETE FROM rag_users WHERE email = ANY(%s)",
                (self.created_emails,),
            )
            if self.created_tenant_ids:
                connection.execute(
                    "DELETE FROM rag_tenants WHERE id = ANY(%s)",
                    (self.created_tenant_ids,),
                )

    def test_tenants_registration_and_login(self) -> None:
        health_response = self.client.get("/api/health")
        self.assertEqual(health_response.status_code, 200)

        page_response = self.client.get("/")
        self.assertEqual(page_response.status_code, 200)
        self.assertIn("data-theme-toggle", page_response.text)

        protected_page = self.client.get("/chat", follow_redirects=False)
        self.assertEqual(protected_page.status_code, 303)
        self.assertEqual(self.client.get("/api/auth/me").status_code, 401)

        tenant_response = self.client.get("/api/tenants")
        self.assertEqual(tenant_response.status_code, 200)
        tenants = tenant_response.json()
        self.assertTrue(
            {"IT Tenant", "HR Tenant", "Operations Tenant", "R&D Tenant"}.issubset(
                {tenant["name"] for tenant in tenants}
            )
        )

        password = "Correct-Horse-42"
        registration = self.client.post(
            "/api/auth/register",
            json={"email": self.email, "password": password, "tenant_id": tenants[0]["id"]},
        )
        self.assertEqual(registration.status_code, 201)

        with connect() as connection:
            saved_user = connection.execute(
                "SELECT username, password_hash, tenant_id, email_verified_at FROM rag_users WHERE email = %s",
                (self.email,),
            ).fetchone()
        expected_username = self.email.split("@", 1)[0]
        self.assertEqual(saved_user["username"], expected_username)
        self.assertEqual(registration.json()["user"]["username"], expected_username)
        self.assertTrue(saved_user["password_hash"].startswith("$argon2id$"))
        self.assertNotEqual(saved_user["password_hash"], password)
        self.assertEqual(saved_user["tenant_id"], tenants[0]["id"])
        self.assertEqual(registration.json()["user"]["role"], "pending")
        self.assertIsNone(saved_user["email_verified_at"])

        duplicate = self.client.post(
            "/api/auth/register",
            json={"email": self.email, "password": password, "tenant_id": tenants[0]["id"]},
        )
        self.assertEqual(duplicate.status_code, 409)

        collision_email = f"{expected_username}@another-example.com"
        self.created_emails.append(collision_email)
        collision_registration = self.client.post(
            "/api/auth/register",
            json={
                "email": collision_email,
                "password": password,
                "tenant_id": tenants[0]["id"],
            },
        )
        self.assertEqual(collision_registration.status_code, 201)
        self.assertEqual(
            collision_registration.json()["user"]["username"],
            f"{expected_username}-2",
        )

        pending_login = self.client.post(
            "/api/auth/login",
            json={"identifier": self.email, "password": password, "remember": True},
        )
        self.assertEqual(pending_login.status_code, 401)

        with connect() as connection:
            connection.execute(
                "UPDATE rag_users SET email_verified_at = CURRENT_TIMESTAMP WHERE email = %s",
                (self.email,),
            )

        approval_admin_login = self.client.post(
            "/api/auth/login",
            json={"identifier": "admin", "password": "admin", "remember": False},
        )
        self.assertEqual(approval_admin_login.status_code, 200)

        approval = self.client.post(
            f"/api/admin/users/{registration.json()['user']['id']}/approve"
        )
        self.assertEqual(approval.status_code, 200)
        self.assertEqual(approval.json()["user"]["role"], "user")

        decline = self.client.delete(
            f"/api/admin/users/{collision_registration.json()['user']['id']}"
        )
        self.assertEqual(decline.status_code, 204)
        with connect() as connection:
            declined_user = connection.execute(
                "SELECT id FROM rag_users WHERE email = %s",
                (collision_email,),
            ).fetchone()
        self.assertIsNone(declined_user)
        self.assertEqual(self.client.post("/api/auth/logout").status_code, 204)

        login = self.client.post(
            "/api/auth/login",
            json={"identifier": self.email, "password": password, "remember": True},
        )
        self.assertEqual(login.status_code, 200)
        self.assertEqual(login.json()["landing_path"], "/chat")
        self.assertIn("atlas_session", login.cookies)
        self.assertTrue(login.cookies["atlas_session"])

        session = self.client.get("/api/auth/me")
        self.assertEqual(session.status_code, 200)
        self.assertEqual(session.json()["user"]["email"], self.email)

        chat_page = self.client.get("/chat")
        self.assertEqual(chat_page.status_code, 200)
        self.assertIn("data-composer", chat_page.text)

        admin_redirect = self.client.get("/admin", follow_redirects=False)
        self.assertEqual(admin_redirect.status_code, 303)
        self.assertEqual(admin_redirect.headers["location"], "/chat")
        manager_redirect = self.client.get("/manager", follow_redirects=False)
        self.assertEqual(manager_redirect.status_code, 303)
        self.assertEqual(manager_redirect.headers["location"], "/chat")
        self.assertEqual(self.client.get("/api/admin/tenants").status_code, 403)
        self.assertEqual(self.client.get("/api/manager/tenant").status_code, 403)

        logout = self.client.post("/api/auth/logout")
        self.assertEqual(logout.status_code, 204)
        self.assertEqual(self.client.get("/api/auth/me").status_code, 401)

        with connect() as connection:
            admin_user = connection.execute(
                """
                SELECT username, email, password_hash, tenant_id, role
                FROM rag_users WHERE username = 'admin'
                """
            ).fetchone()
        self.assertEqual(admin_user["role"], "admin")
        self.assertIsNone(admin_user["tenant_id"])
        self.assertIsNone(admin_user["email"])
        self.assertTrue(admin_user["password_hash"].startswith("$argon2id$"))

        admin_login = self.client.post(
            "/api/auth/login",
            json={"identifier": "admin", "password": "admin", "remember": False},
        )
        self.assertEqual(admin_login.status_code, 200)
        self.assertEqual(admin_login.json()["landing_path"], "/admin")
        self.assertEqual(admin_login.json()["user"]["role"], "admin")
        self.assertIsNone(admin_login.json()["user"]["tenant"])

        admin_page = self.client.get("/admin")
        self.assertEqual(admin_page.status_code, 200)
        self.assertIn("data-tenant-grid", admin_page.text)
        self.assertIn("data-theme-toggle", admin_page.text)
        self.assertIn('data-view="admins"', admin_page.text)
        self.assertIn('data-panel="admins"', admin_page.text)
        self.assertIn('data-view="contracts"', admin_page.text)
        self.assertIn('data-panel="contracts"', admin_page.text)
        self.assertIn("data-contract-json", admin_page.text)
        self.assertIn('data-view="security"', admin_page.text)
        self.assertIn("data-security-incidents", admin_page.text)
        self.assertIn("data-document-dropzone", admin_page.text)
        self.assertIn("data-upload-documents", admin_page.text)
        self.assertIn("data-document-registry", admin_page.text)
        self.assertIn("v=20261107-rag-security", admin_page.text)
        self.assertIn("no-store", admin_page.headers["cache-control"])

        admin_script = self.client.get(
            "/admin-assets/scripts/app.js?v=20261107-rag-security"
        )
        self.assertEqual(admin_script.status_code, 200)
        self.assertIn("tenant-card__open", admin_script.text)
        self.assertIn("openRoleConfirmation", admin_script.text)
        self.assertIn("loadAdmins", admin_script.text)
        self.assertIn("updateKnowledgePanel", admin_script.text)
        self.assertIn("selectDocuments", admin_script.text)
        self.assertIn("loadDocuments", admin_script.text)
        self.assertIn("loadContracts", admin_script.text)
        self.assertIn("contractAction", admin_script.text)
        self.assertIn("loadSecurityIncidents", admin_script.text)
        self.assertIn("no-store", admin_script.headers["cache-control"])

        chat_redirect = self.client.get("/chat", follow_redirects=False)
        self.assertEqual(chat_redirect.status_code, 303)
        self.assertEqual(chat_redirect.headers["location"], "/admin")
        manager_redirect = self.client.get("/manager", follow_redirects=False)
        self.assertEqual(manager_redirect.status_code, 303)
        self.assertEqual(manager_redirect.headers["location"], "/admin")

        tenant_slug = f"integration-{uuid4().hex}"
        create_tenant = self.client.post(
            "/api/admin/tenants",
            json={
                "name": f"Integration {tenant_slug}",
                "slug": tenant_slug.upper(),
                "description": "Integration test tenant",
            },
        )
        self.assertEqual(create_tenant.status_code, 201)
        created_tenant = create_tenant.json()["tenant"]
        self.created_tenant_ids.append(created_tenant["id"])
        self.assertEqual(created_tenant["slug"], tenant_slug)
        self.assertFalse(created_tenant["is_active"])
        self.assertEqual(created_tenant["contract_state"], "draft")

        contracts = self.client.get(
            f"/api/admin/tenants/{created_tenant['id']}/contracts"
        )
        self.assertEqual(contracts.status_code, 200)
        self.assertEqual(len(contracts.json()), 1)
        self.assertEqual(contracts.json()[0]["state"], "draft")
        self.assertTrue(contracts.json()[0]["signature_valid"])
        default_contract_id = contracts.json()[0]["id"]

        unavailable_registration = self.client.post(
            "/api/auth/register",
            json={
                "email": f"onboarding-{uuid4().hex}@example.com",
                "password": password,
                "tenant_id": created_tenant["id"],
            },
        )
        self.assertEqual(unavailable_registration.status_code, 400)
        blocked_manual_activation = self.client.patch(
            f"/api/admin/tenants/{created_tenant['id']}",
            json={"is_active": True},
        )
        self.assertEqual(blocked_manual_activation.status_code, 409)

        approved_contract = self.client.post(
            f"/api/admin/contracts/{default_contract_id}/approve"
        )
        self.assertEqual(approved_contract.status_code, 200)
        activated_contract = self.client.post(
            f"/api/admin/contracts/{default_contract_id}/activate"
        )
        self.assertEqual(activated_contract.status_code, 200)

        managed_tenants = self.client.get("/api/admin/tenants")
        self.assertEqual(managed_tenants.status_code, 200)
        self.assertIn(created_tenant["id"], {item["id"] for item in managed_tenants.json()})
        activated_tenant = next(
            item for item in managed_tenants.json() if item["id"] == created_tenant["id"]
        )
        self.assertTrue(activated_tenant["is_active"])
        self.assertEqual(activated_tenant["contract_state"], "active")

        duplicate_tenant = self.client.post(
            "/api/admin/tenants",
            json={
                "name": created_tenant["name"],
                "slug": created_tenant["slug"],
                "description": "Duplicate",
            },
        )
        self.assertEqual(duplicate_tenant.status_code, 409)

        managed_email = f"managed-{uuid4().hex}@example.com"
        self.created_emails.append(managed_email)
        managed_registration = self.client.post(
            "/api/auth/register",
            json={
                "email": managed_email,
                "password": password,
                "tenant_id": created_tenant["id"],
            },
        )
        self.assertEqual(managed_registration.status_code, 201)
        with connect() as connection:
            connection.execute(
                "UPDATE rag_users SET email_verified_at = CURRENT_TIMESTAMP WHERE email = %s",
                (managed_email,),
            )

        tenant_users = self.client.get(
            f"/api/admin/tenants/{created_tenant['id']}/users"
        )
        self.assertEqual(tenant_users.status_code, 200)
        self.assertEqual(len(tenant_users.json()["users"]), 1)
        self.assertEqual(tenant_users.json()["users"][0]["email"], managed_email)
        self.assertEqual(tenant_users.json()["users"][0]["role"], "pending")

        managed_user_id = managed_registration.json()["user"]["id"]
        managed_approval = self.client.post(
            f"/api/admin/users/{managed_user_id}/approve"
        )
        self.assertEqual(managed_approval.status_code, 200)
        self.assertEqual(managed_approval.json()["user"]["role"], "user")

        suspend_user = self.client.patch(
            f"/api/admin/users/{managed_user_id}",
            json={"is_active": False},
        )
        self.assertEqual(suspend_user.status_code, 200)
        self.assertFalse(suspend_user.json()["user"]["is_active"])
        blocked_login = self.client.post(
            "/api/auth/login",
            json={"identifier": managed_email, "password": password, "remember": False},
        )
        self.assertEqual(blocked_login.status_code, 401)

        reactivate_user = self.client.patch(
            f"/api/admin/users/{managed_user_id}",
            json={"is_active": True},
        )
        self.assertEqual(reactivate_user.status_code, 200)
        self.assertTrue(reactivate_user.json()["user"]["is_active"])

        rejected_role_change = self.client.patch(
            f"/api/admin/users/{managed_user_id}/role",
            json={"role": "tenant_manager", "admin_password": "incorrect"},
        )
        self.assertEqual(rejected_role_change.status_code, 401)

        manager_role = self.client.patch(
            f"/api/admin/users/{managed_user_id}/role",
            json={"role": "tenant_manager", "admin_password": "admin"},
        )
        self.assertEqual(manager_role.status_code, 200)
        self.assertEqual(manager_role.json()["user"]["role"], "tenant_manager")

        colleague_email = f"colleague-{uuid4().hex}@example.com"
        self.created_emails.append(colleague_email)
        colleague_registration = self.client.post(
            "/api/auth/register",
            json={
                "email": colleague_email,
                "password": password,
                "tenant_id": created_tenant["id"],
            },
        )
        self.assertEqual(colleague_registration.status_code, 201)
        with connect() as connection:
            connection.execute(
                "UPDATE rag_users SET email_verified_at = CURRENT_TIMESTAMP WHERE email = %s",
                (colleague_email,),
            )
        colleague_id = colleague_registration.json()["user"]["id"]
        colleague_approval = self.client.post(
            f"/api/admin/users/{colleague_id}/approve"
        )
        self.assertEqual(colleague_approval.status_code, 200)

        self.assertEqual(self.client.post("/api/auth/logout").status_code, 204)
        tenant_manager_login = self.client.post(
            "/api/auth/login",
            json={
                "identifier": managed_email,
                "password": password,
                "remember": False,
            },
        )
        self.assertEqual(tenant_manager_login.status_code, 200)
        self.assertEqual(tenant_manager_login.json()["landing_path"], "/manager")
        self.assertEqual(
            tenant_manager_login.json()["user"]["role"], "tenant_manager"
        )

        manager_page = self.client.get("/manager")
        self.assertEqual(manager_page.status_code, 200)
        self.assertIn('data-panel="chat"', manager_page.text)
        self.assertIn('data-panel="management"', manager_page.text)
        self.assertIn('data-panel="security"', manager_page.text)
        self.assertIn("data-security-incidents", manager_page.text)
        self.assertIn("data-document-dropzone", manager_page.text)
        self.assertIn("data-document-registry", manager_page.text)
        self.assertIn("v=20261107-rag-security", manager_page.text)
        self.assertIn("no-store", manager_page.headers["cache-control"])
        manager_script = self.client.get(
            "/manager-assets/scripts/app.js?v=20261107-rag-security"
        )
        self.assertEqual(manager_script.status_code, 200)
        self.assertIn("loadTenantWorkspace", manager_script.text)
        self.assertIn("openRoleConfirmation", manager_script.text)
        self.assertIn("loadDocuments", manager_script.text)
        self.assertIn("loadSecurityIncidents", manager_script.text)
        self.assertIn("no-store", manager_script.headers["cache-control"])

        tenant_workspace = self.client.get("/api/manager/tenant")
        self.assertEqual(tenant_workspace.status_code, 200)
        self.assertEqual(tenant_workspace.json()["tenant"]["id"], created_tenant["id"])
        tenant_member_ids = {
            user["id"] for user in tenant_workspace.json()["users"]
        }
        self.assertIn(managed_user_id, tenant_member_ids)
        self.assertIn(colleague_id, tenant_member_ids)
        self.assertNotIn(registration.json()["user"]["id"], tenant_member_ids)
        self.assertEqual(self.client.get("/api/admin/tenants").status_code, 403)

        chat_redirect = self.client.get("/chat", follow_redirects=False)
        self.assertEqual(chat_redirect.status_code, 303)
        self.assertEqual(chat_redirect.headers["location"], "/manager")
        admin_redirect = self.client.get("/admin", follow_redirects=False)
        self.assertEqual(admin_redirect.status_code, 303)
        self.assertEqual(admin_redirect.headers["location"], "/manager")

        rejected_manager_change = self.client.patch(
            f"/api/manager/users/{colleague_id}/role",
            json={"role": "tenant_manager", "manager_password": "incorrect"},
        )
        self.assertEqual(rejected_manager_change.status_code, 401)
        promoted_colleague = self.client.patch(
            f"/api/manager/users/{colleague_id}/role",
            json={"role": "tenant_manager", "manager_password": password},
        )
        self.assertEqual(promoted_colleague.status_code, 200)
        self.assertEqual(
            promoted_colleague.json()["user"]["role"], "tenant_manager"
        )
        forbidden_admin_grant = self.client.patch(
            f"/api/manager/users/{colleague_id}/role",
            json={"role": "admin", "manager_password": password},
        )
        self.assertEqual(forbidden_admin_grant.status_code, 422)
        cross_tenant_change = self.client.patch(
            f"/api/manager/users/{registration.json()['user']['id']}/role",
            json={"role": "tenant_manager", "manager_password": password},
        )
        self.assertEqual(cross_tenant_change.status_code, 404)
        self_demotion = self.client.patch(
            f"/api/manager/users/{managed_user_id}/role",
            json={"role": "user", "manager_password": password},
        )
        self.assertEqual(self_demotion.status_code, 400)
        demoted_colleague = self.client.patch(
            f"/api/manager/users/{colleague_id}/role",
            json={"role": "user", "manager_password": password},
        )
        self.assertEqual(demoted_colleague.status_code, 200)
        self.assertEqual(demoted_colleague.json()["user"]["role"], "user")

        self.assertEqual(self.client.post("/api/auth/logout").status_code, 204)
        resumed_admin_login = self.client.post(
            "/api/auth/login",
            json={"identifier": "admin", "password": "admin", "remember": False},
        )
        self.assertEqual(resumed_admin_login.status_code, 200)
        self.assertEqual(self.client.get("/api/manager/tenant").status_code, 403)

        admin_role = self.client.patch(
            f"/api/admin/users/{managed_user_id}/role",
            json={"role": "admin", "admin_password": "admin"},
        )
        self.assertEqual(admin_role.status_code, 200)
        self.assertEqual(admin_role.json()["user"]["role"], "admin")
        self.assertEqual(admin_role.json()["user"]["tenant_id"], created_tenant["id"])

        administrators = self.client.get("/api/admin/admins")
        self.assertEqual(administrators.status_code, 200)
        administrators_by_id = {
            administrator["id"]: administrator
            for administrator in administrators.json()
        }
        self.assertIn(managed_user_id, administrators_by_id)
        self.assertEqual(
            administrators_by_id[managed_user_id]["tenant_id"],
            created_tenant["id"],
        )
        self.assertEqual(
            administrators_by_id[managed_user_id]["tenant_name"],
            created_tenant["name"],
        )
        platform_admin = next(
            administrator
            for administrator in administrators.json()
            if administrator["username"] == "admin"
        )
        self.assertIsNone(platform_admin["tenant_id"])
        self.assertIsNone(platform_admin["tenant_name"])

        user_role = self.client.patch(
            f"/api/admin/users/{managed_user_id}/role",
            json={"role": "user", "admin_password": "admin"},
        )
        self.assertEqual(user_role.status_code, 200)
        self.assertEqual(user_role.json()["user"]["role"], "user")
        self.assertNotIn(
            managed_user_id,
            {
                administrator["id"]
                for administrator in self.client.get("/api/admin/admins").json()
            },
        )

        suspend = self.client.patch(
            f"/api/admin/tenants/{created_tenant['id']}",
            json={"is_active": False},
        )
        self.assertEqual(suspend.status_code, 200)
        self.assertFalse(suspend.json()["tenant"]["is_active"])

        public_tenants = self.client.get("/api/tenants").json()
        self.assertNotIn(created_tenant["id"], {tenant["id"] for tenant in public_tenants})

    def test_security_headers_origin_protection_and_secret_validation(self) -> None:
        response = self.client.get("/api/health")
        self.assertEqual(response.json()["phase"], 2)
        self.assertEqual(response.json()["version"], "0.2.0")
        self.assertEqual(response.json()["checks"], {"database": "ok"})
        self.assertEqual(self.client.get("/api/health/live").status_code, 200)
        self.assertEqual(self.client.get("/api/health/ready").status_code, 200)
        self.assertEqual(response.headers["cache-control"], "no-store")
        self.assertTrue(response.headers["x-request-id"].startswith("req_"))
        self.assertEqual(response.headers["x-content-type-options"], "nosniff")
        self.assertEqual(response.headers["x-frame-options"], "DENY")
        self.assertEqual(response.headers["cross-origin-opener-policy"], "same-origin")
        self.assertEqual(response.headers["cross-origin-resource-policy"], "same-origin")
        self.assertIn("frame-ancestors 'none'", response.headers["content-security-policy"])
        self.assertEqual(self.client.get("/verify-email?token=example").status_code, 200)
        self.assertEqual(self.client.get("/reset-password?token=example").status_code, 200)
        rejected = self.client.post(
            "/api/auth/login",
            headers={"Origin": "https://attacker.example"},
            json={"identifier": "admin", "password": "admin", "remember": False},
        )
        self.assertEqual(rejected.status_code, 403)
        with self.assertRaises(RuntimeError):
            validate_signing_secret("replace-with-a-long-random-secret")
        with self.assertRaises(RuntimeError):
            validate_signing_secret("short")

        with patch(
            "multi_tenant_rag_assistants.backend.auth.connect",
            side_effect=RuntimeError("database unavailable"),
        ):
            unavailable = self.client.get("/api/health/ready")
        self.assertEqual(unavailable.status_code, 503)
        self.assertEqual(unavailable.json()["status"], "not_ready")
        self.assertNotIn("database unavailable", unavailable.text)

    def test_privilege_and_tenant_changes_revoke_active_sessions(self) -> None:
        password = "Session-Change-42"
        suffix = uuid4().hex
        with connect() as connection:
            tenant = connection.execute(
                """
                INSERT INTO rag_tenants (name, slug, description)
                VALUES (%s, %s, 'Session revocation tenant') RETURNING id, name
                """,
                (f"Session Tenant {suffix}", f"session-{suffix}"),
            ).fetchone()
            self.created_tenant_ids.append(tenant["id"])
            ensure_default_contract(connection, tenant["id"], tenant["name"])
            user = connection.execute(
                """
                INSERT INTO rag_users (username, email, password_hash, tenant_id, role)
                VALUES (%s, %s, %s, %s, 'user') RETURNING id
                """,
                (self.email.split("@", 1)[0], self.email, PasswordHasher().hash(password), tenant["id"]),
            ).fetchone()

        with TestClient(app) as user_device:
            user_device.headers.update({"Origin": "http://127.0.0.1:8000"})
            signed_in = user_device.post(
                "/api/auth/login",
                headers={"Origin": "http://127.0.0.1:8000"},
                json={"identifier": self.email, "password": password, "remember": True},
            )
            self.assertEqual(signed_in.status_code, 200, signed_in.text)
            self.assertEqual(
                self.client.post(
                    "/api/auth/login",
                    json={"identifier": "admin", "password": "admin", "remember": False},
                ).status_code,
                200,
            )

            suspended = self.client.patch(
                f"/api/admin/users/{user['id']}", json={"is_active": False}
            )
            self.assertEqual(suspended.status_code, 200, suspended.text)
            self.assertEqual(user_device.get("/api/auth/me").status_code, 401)

            self.assertEqual(
                self.client.patch(
                    f"/api/admin/users/{user['id']}", json={"is_active": True}
                ).status_code,
                200,
            )
            self.assertEqual(
                user_device.post(
                    "/api/auth/login",
                    headers={"Origin": "http://127.0.0.1:8000"},
                    json={"identifier": self.email, "password": password, "remember": True},
                ).status_code,
                200,
            )
            promoted = self.client.patch(
                f"/api/admin/users/{user['id']}/role",
                json={"role": "tenant_manager", "admin_password": "admin"},
            )
            self.assertEqual(promoted.status_code, 200, promoted.text)
            self.assertEqual(user_device.get("/api/auth/me").status_code, 401)

            self.assertEqual(
                user_device.post(
                    "/api/auth/login",
                    headers={"Origin": "http://127.0.0.1:8000"},
                    json={"identifier": self.email, "password": password, "remember": True},
                ).status_code,
                200,
            )
            deactivated = self.client.patch(
                f"/api/admin/tenants/{tenant['id']}", json={"is_active": False}
            )
            self.assertEqual(deactivated.status_code, 200, deactivated.text)
            self.assertEqual(user_device.get("/api/auth/me").status_code, 401)

        with connect() as connection:
            active_sessions = connection.execute(
                """
                SELECT COUNT(*) AS count FROM auth_sessions
                WHERE user_id = %s AND revoked_at IS NULL
                """,
                (user["id"],),
            ).fetchone()["count"]
        self.assertEqual(active_sessions, 0)

    def test_email_verification_and_password_reset_are_one_time(self) -> None:
        tenant = self.client.get("/api/tenants").json()[0]
        delivered = []
        with patch(
            "multi_tenant_rag_assistants.backend.auth.deliver_auth_email",
            side_effect=lambda **message: delivered.append(message),
        ):
            registration = self.client.post(
                "/api/auth/register",
                json={
                    "email": self.email,
                    "password": "Initial-Pass-42",
                    "tenant_id": tenant["id"],
                },
            )
        self.assertEqual(registration.status_code, 201, registration.text)
        verification_token = parse_qs(
            urlparse(delivered[-1]["body"].splitlines()[-1]).query
        )["token"][0]
        self.assertEqual(
            self.client.post("/api/auth/verify-email", json={"token": verification_token}).status_code,
            200,
        )
        self.assertEqual(
            self.client.post("/api/auth/verify-email", json={"token": verification_token}).status_code,
            400,
        )
        delivered.clear()
        with patch(
            "multi_tenant_rag_assistants.backend.auth.deliver_auth_email",
            side_effect=lambda **message: delivered.append(message),
        ):
            requested = self.client.post(
                "/api/auth/password-reset/request", json={"email": self.email}
            )
        self.assertEqual(requested.status_code, 202)
        reset_token = parse_qs(
            urlparse(delivered[-1]["body"].splitlines()[-1]).query
        )["token"][0]
        new_password = "Replacement-Pass-42"
        reset = self.client.post(
            "/api/auth/password-reset/confirm",
            json={"token": reset_token, "new_password": new_password},
        )
        self.assertEqual(reset.status_code, 200, reset.text)
        with connect() as connection:
            user = connection.execute(
                "SELECT password_hash, email_verified_at FROM rag_users WHERE email = %s",
                (self.email,),
            ).fetchone()
        self.assertIsNotNone(user["email_verified_at"])
        self.assertTrue(PasswordHasher().verify(user["password_hash"], new_password))
        reused = self.client.post(
            "/api/auth/password-reset/confirm",
            json={"token": reset_token, "new_password": "Another-Pass-42"},
        )
        self.assertEqual(reused.status_code, 400)

    def test_account_lockout_and_server_side_session_revocation(self) -> None:
        tenant = self.client.get("/api/tenants").json()[0]
        password = "Lockout-Test-42"
        with connect() as connection:
            user = connection.execute(
                """
                INSERT INTO rag_users (username, email, password_hash, tenant_id, role)
                VALUES (%s, %s, %s, %s, 'user') RETURNING id
                """,
                (
                    self.email.split("@", 1)[0],
                    self.email,
                    PasswordHasher().hash(password),
                    tenant["id"],
                ),
            ).fetchone()
        for _ in range(5):
            failed = self.client.post(
                "/api/auth/login",
                json={
                    "identifier": self.email,
                    "password": "Wrong-Pass-42",
                    "remember": False,
                },
            )
            self.assertEqual(failed.status_code, 401)
        locked = self.client.post(
            "/api/auth/login",
            json={"identifier": self.email, "password": password, "remember": False},
        )
        self.assertEqual(locked.status_code, 429)
        with connect() as connection:
            connection.execute(
                "UPDATE rag_users SET failed_login_count = 0, locked_until = NULL WHERE id = %s",
                (user["id"],),
            )
            connection.execute("DELETE FROM auth_rate_limits")
        login = self.client.post(
            "/api/auth/login",
            json={"identifier": self.email, "password": password, "remember": False},
        )
        self.assertEqual(login.status_code, 200, login.text)
        security_page = self.client.get("/account-security")
        self.assertEqual(security_page.status_code, 200)
        self.assertIn("data-session-list", security_page.text)
        sessions = self.client.get("/api/auth/sessions")
        current = next(item for item in sessions.json()["sessions"] if item["is_current"])
        self.assertEqual(
            self.client.delete(f"/api/auth/sessions/{current['id']}").status_code,
            204,
        )
        self.assertEqual(self.client.get("/api/auth/me").status_code, 401)
        self.assertEqual(
            self.client.post(
                "/api/auth/login",
                json={"identifier": self.email, "password": password, "remember": False},
            ).status_code,
            200,
        )
        with TestClient(app, headers={"Origin": "http://127.0.0.1:8000"}) as other_device:
            self.assertEqual(
                other_device.post(
                    "/api/auth/login",
                    json={"identifier": self.email, "password": password, "remember": True},
                ).status_code,
                200,
            )
            active = self.client.get("/api/auth/sessions").json()["sessions"]
            self.assertGreaterEqual(len(active), 2)
            self.assertEqual(self.client.post("/api/auth/logout-all").status_code, 204)
            self.assertEqual(other_device.get("/api/auth/me").status_code, 401)


if __name__ == "__main__":
    unittest.main()
