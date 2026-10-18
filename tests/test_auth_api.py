"""Integration tests for the local PostgreSQL authentication flow."""

from __future__ import annotations

import unittest
from uuid import uuid4

from fastapi.testclient import TestClient

from multi_tenant_rag_assistants.backend.auth import app
from multi_tenant_rag_assistants.backend.database import connect


class AuthenticationApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.client_context = TestClient(app)
        cls.client = cls.client_context.__enter__()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.client_context.__exit__(None, None, None)

    def setUp(self) -> None:
        self.email = f"integration-{uuid4().hex}@example.com"
        self.created_emails = [self.email]
        self.created_tenant_ids = []

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
                "SELECT username, password_hash, tenant_id FROM rag_users WHERE email = %s",
                (self.email,),
            ).fetchone()
        expected_username = self.email.split("@", 1)[0]
        self.assertEqual(saved_user["username"], expected_username)
        self.assertEqual(registration.json()["user"]["username"], expected_username)
        self.assertTrue(saved_user["password_hash"].startswith("$argon2id$"))
        self.assertNotEqual(saved_user["password_hash"], password)
        self.assertEqual(saved_user["tenant_id"], tenants[0]["id"])
        self.assertEqual(registration.json()["user"]["role"], "pending")

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
        self.assertIn("data-document-dropzone", admin_page.text)
        self.assertIn("data-upload-documents", admin_page.text)
        self.assertIn("data-document-registry", admin_page.text)
        self.assertIn("v=20261016-document-pipeline", admin_page.text)
        self.assertIn("no-store", admin_page.headers["cache-control"])

        admin_script = self.client.get(
            "/admin-assets/scripts/app.js?v=20261016-document-pipeline"
        )
        self.assertEqual(admin_script.status_code, 200)
        self.assertIn("tenant-card__open", admin_script.text)
        self.assertIn("openRoleConfirmation", admin_script.text)
        self.assertIn("loadAdmins", admin_script.text)
        self.assertIn("updateKnowledgePanel", admin_script.text)
        self.assertIn("selectDocuments", admin_script.text)
        self.assertIn("loadDocuments", admin_script.text)
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
        self.assertTrue(created_tenant["is_active"])

        managed_tenants = self.client.get("/api/admin/tenants")
        self.assertEqual(managed_tenants.status_code, 200)
        self.assertIn(created_tenant["id"], {item["id"] for item in managed_tenants.json()})

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
        self.assertIn("data-document-dropzone", manager_page.text)
        self.assertIn("data-document-registry", manager_page.text)
        self.assertIn("v=20261016-document-pipeline", manager_page.text)
        self.assertIn("no-store", manager_page.headers["cache-control"])
        manager_script = self.client.get(
            "/manager-assets/scripts/app.js?v=20261016-document-pipeline"
        )
        self.assertEqual(manager_script.status_code, 200)
        self.assertIn("loadTenantWorkspace", manager_script.text)
        self.assertIn("openRoleConfirmation", manager_script.text)
        self.assertIn("loadDocuments", manager_script.text)
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


if __name__ == "__main__":
    unittest.main()
