const state = { tenants: [], selectedTenantId: null, roleChange: null };
const root = document.documentElement;
const themeToggle = document.querySelector("[data-theme-toggle]");
const tenantGrid = document.querySelector("[data-tenant-grid]");
const tenantTabs = document.querySelector("[data-tenant-tabs]");
const userList = document.querySelector("[data-user-list]");
const adminList = document.querySelector("[data-admin-list]");
const dialog = document.querySelector("[data-tenant-dialog]");
const tenantForm = document.querySelector("[data-tenant-form]");
const formMessage = document.querySelector("[data-form-message]");
const toast = document.querySelector("[data-toast]");
const roleDialog = document.querySelector("[data-role-dialog]");
const roleForm = document.querySelector("[data-role-form]");
const roleMessage = document.querySelector("[data-role-message]");
const documentInput = document.querySelector("[data-document-input]");
const documentDropzone = document.querySelector("[data-document-dropzone]");
const documentQueue = document.querySelector("[data-document-queue]");
const documentList = document.querySelector("[data-document-list]");
const uploadDocumentsButton = document.querySelector("[data-upload-documents]");
const documentRegistry = document.querySelector("[data-document-registry]");
const contractTenant = document.querySelector("[data-contract-tenant]");
const contractForm = document.querySelector("[data-contract-form]");
const contractJson = document.querySelector("[data-contract-json]");
const contractMessage = document.querySelector("[data-contract-message]");
const contractHistory = document.querySelector("[data-contract-history]");
const securityIncidents = document.querySelector("[data-security-incidents]");
let selectedDocuments = [];

const request = async (url, options = {}) => {
  const response = await fetch(url, options);
  const result = response.status === 204 ? null : await response.json();
  if (response.status === 401) {
    window.location.replace("/");
    throw new Error("Session expired");
  }
  if (response.status === 403) {
    window.location.replace("/chat");
    throw new Error("Administrator access required");
  }
  if (!response.ok) {
    const detail = Array.isArray(result?.detail)
      ? result.detail[0]?.msg
      : result?.detail;
    throw new Error(detail || "The request could not be completed.");
  }
  return result;
};

const setTheme = (theme) => {
  const isDark = theme === "dark";
  root.dataset.theme = theme;
  themeToggle.setAttribute("aria-pressed", String(isDark));
  themeToggle.setAttribute(
    "aria-label",
    `Switch to ${isDark ? "light" : "dark"} mode`,
  );
};
setTheme(
  localStorage.getItem("atlasTheme") ||
    (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light"),
);
themeToggle.addEventListener("click", () => {
  const theme = root.dataset.theme === "dark" ? "light" : "dark";
  localStorage.setItem("atlasTheme", theme);
  setTheme(theme);
});

const initials = (name) =>
  name
    .split(/\s+/)
    .map((part) => part[0])
    .join("")
    .toUpperCase()
    .slice(0, 3);
const showToast = (message) => {
  toast.textContent = message;
  toast.hidden = false;
  window.setTimeout(() => {
    toast.hidden = true;
  }, 3000);
};

const renderEmptyUsers = (message) => {
  const row = document.createElement("tr");
  const cell = document.createElement("td");
  cell.colSpan = 5;
  cell.className = "empty-state";
  cell.textContent = message;
  row.append(cell);
  userList.replaceChildren(row);
};

const renderEmptyAdmins = (message) => {
  const row = document.createElement("tr");
  const cell = document.createElement("td");
  cell.colSpan = 4;
  cell.className = "empty-state";
  cell.textContent = message;
  row.append(cell);
  adminList.replaceChildren(row);
};

const updateSummary = () => {
  document.querySelector("[data-total-tenants]").textContent =
    state.tenants.length;
  document.querySelector("[data-active-tenants]").textContent =
    state.tenants.filter((tenant) => tenant.is_active).length;
  document.querySelector("[data-total-users]").textContent =
    state.tenants.reduce((total, tenant) => total + tenant.user_count, 0);
};

const renderTenants = () => {
  tenantGrid.replaceChildren(
    ...state.tenants.map((tenant) => {
      const card = document.createElement("article");
      card.className = "tenant-card";
      const openButton = document.createElement("button");
      openButton.type = "button";
      openButton.className = "tenant-card__open";
      openButton.setAttribute("aria-label", `View users in ${tenant.name}`);
      openButton.addEventListener("click", () => openUsersForTenant(tenant.id));
      const badge = document.createElement("span");
      badge.className = "tenant-card__badge";
      badge.textContent = initials(tenant.name);
      const copy = document.createElement("div");
      copy.className = "tenant-card__copy";
      const name = document.createElement("strong");
      name.textContent = tenant.name;
      const description = document.createElement("small");
      description.textContent = tenant.description || `/${tenant.slug}`;
      const meta = document.createElement("div");
      meta.className = "tenant-card__meta";
      const status = document.createElement("span");
      const onboarding =
        !tenant.is_active && ["draft", "approved"].includes(tenant.contract_state);
      status.className = `state-pill${tenant.is_active ? "" : onboarding ? " is-onboarding" : " is-suspended"}`;
      status.textContent = tenant.is_active
        ? "Active"
        : onboarding
          ? "Onboarding"
          : "Suspended";
      const count = document.createElement("span");
      count.textContent = `${tenant.user_count} ${tenant.user_count === 1 ? "user" : "users"}`;
      meta.append(status, count);
      copy.append(name, description, meta);
      const action = document.createElement("button");
      action.type = "button";
      action.className = `tenant-card__action${tenant.is_active || onboarding ? "" : " is-reactivate"}`;
      action.textContent = onboarding
        ? "Configure policy"
        : tenant.is_active
          ? "Suspend"
          : "Reactivate";
      action.addEventListener("click", (event) => {
        event.stopPropagation();
        if (onboarding) {
          state.selectedTenantId = tenant.id;
          contractTenant.value = String(tenant.id);
          setView("contracts");
          loadContracts(tenant.id);
          return;
        }
        setTenantStatus(tenant, !tenant.is_active, action);
      });
      card.append(openButton, badge, copy, action);
      return card;
    }),
  );
  document.querySelector("[data-tenant-status]").textContent =
    `${state.tenants.length} total`;
  updateSummary();
  renderTenantTabs();
};

const renderTenantTabs = () => {
  tenantTabs.replaceChildren(
    ...state.tenants.map((tenant) => {
      const button = document.createElement("button");
      button.type = "button";
      button.role = "tab";
      button.classList.toggle(
        "is-active",
        tenant.id === state.selectedTenantId,
      );
      button.textContent = tenant.name;
      button.addEventListener("click", () => loadUsers(tenant.id));
      return button;
    }),
  );
};

const formatFileSize = (bytes) => {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
};

const renderDocumentQueue = () => {
  documentQueue.hidden = selectedDocuments.length === 0;
  uploadDocumentsButton.disabled = selectedDocuments.length === 0;
  document.querySelector("[data-document-count]").textContent =
    `${selectedDocuments.length} ${selectedDocuments.length === 1 ? "file" : "files"}`;
  documentList.replaceChildren(
    ...selectedDocuments.map((file) => {
      const item = document.createElement("li");
      const icon = document.createElementNS("http://www.w3.org/2000/svg", "svg");
      icon.setAttribute("viewBox", "0 0 24 24");
      icon.setAttribute("aria-hidden", "true");
      icon.innerHTML = '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6M8 13h8M8 17h5"/>';
      const name = document.createElement("span");
      name.textContent = file.name;
      const size = document.createElement("small");
      size.textContent = formatFileSize(file.size);
      item.append(icon, name, size);
      return item;
    }),
  );
};

const selectDocuments = (files) => {
  const allowedExtensions = ["pdf", "docx", "txt"];
  selectedDocuments = [...files].filter((file) =>
    allowedExtensions.includes(file.name.split(".").pop()?.toLowerCase()),
  );
  renderDocumentQueue();
  if (files.length && !selectedDocuments.length)
    showToast("Choose PDF, DOCX, or TXT documents.");
};

const updateKnowledgePanel = (tenantId) => {
  const tenant = state.tenants.find((item) => item.id === tenantId);
  if (!tenant) return;
  document.querySelector("[data-knowledge-tenant]").textContent = tenant.name;
  document.querySelector("[data-knowledge-badge]").textContent = tenant.name;
  document.querySelector("[data-knowledge-description]").textContent =
    `Choose approved source documents for ${tenant.name}'s RAG assistant.`;
  selectedDocuments = [];
  documentInput.value = "";
  renderDocumentQueue();
};

const documentStatus = (document) =>
  document.version.approval_status === "pending"
    ? "pending approval"
    : document.version.ingestion_status;

const createDocumentButton = (label, className, handler) => {
  const button = document.createElement("button");
  button.type = "button";
  button.className = className;
  button.textContent = label;
  button.addEventListener("click", async () => {
    button.disabled = true;
    try {
      await handler();
    } catch (error) {
      showToast(error.message);
    } finally {
      button.disabled = false;
    }
  });
  return button;
};

const renderDocuments = (documents) => {
  document.querySelector("[data-registry-count]").textContent =
    `${documents.length} ${documents.length === 1 ? "document" : "documents"}`;
  if (!documents.length) {
    const empty = document.createElement("p");
    empty.className = "empty-state";
    empty.textContent = "No documents have been uploaded for this tenant.";
    documentRegistry.replaceChildren(empty);
    return;
  }
  documentRegistry.replaceChildren(
    ...documents.map((storedDocument) => {
      const record = document.createElement("article");
      record.className = "document-record";
      const copy = document.createElement("div");
      copy.className = "document-record__name";
      const name = document.createElement("strong");
      name.textContent = storedDocument.original_filename;
      const details = document.createElement("small");
      details.textContent = `Version ${storedDocument.version.version_number} · ${formatFileSize(storedDocument.version.size_bytes)} · ${storedDocument.version.chunk_count} chunks`;
      copy.append(name, details);
      const currentStatus = documentStatus(storedDocument);
      const badge = document.createElement("span");
      badge.className = `document-status document-status--${currentStatus.replaceAll(" ", "-")}`;
      badge.textContent = currentStatus;
      const actions = document.createElement("div");
      actions.className = "document-actions";
      if (storedDocument.version.approval_status === "pending") {
        actions.append(
          createDocumentButton("Approve", "approve-document", async () => {
            await request(`/api/admin/documents/${storedDocument.version.id}/approve`, {
              method: "POST",
            });
            await loadDocuments(state.selectedTenantId);
            showToast(`${storedDocument.original_filename} approved and queued for indexing.`);
          }),
          createDocumentButton("Reject", "reject-document", async () => {
            const reason = window.prompt("Reason for rejecting this document:", "");
            if (reason === null) return;
            await request(`/api/admin/documents/${storedDocument.version.id}/reject`, {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ reason }),
            });
            await loadDocuments(state.selectedTenantId);
            showToast(`${storedDocument.original_filename} rejected.`);
          }),
        );
      }
      if (storedDocument.version.ingestion_status === "active") {
        actions.append(
          createDocumentButton("Reindex", "reindex-document", async () => {
            await request(
              `/api/admin/tenants/${state.selectedTenantId}/documents/${storedDocument.id}/reindex`,
              { method: "POST" },
            );
            await loadDocuments(state.selectedTenantId);
            showToast(`${storedDocument.original_filename} queued for reindexing.`);
          }),
        );
      }
      actions.append(
        createDocumentButton("Revoke", "delete-document", async () => {
          if (!window.confirm(`Revoke ${storedDocument.original_filename} from retrieval?`)) return;
          await request(
            `/api/admin/tenants/${state.selectedTenantId}/documents/${storedDocument.id}`,
            { method: "DELETE" },
          );
          await loadDocuments(state.selectedTenantId);
          showToast(`${storedDocument.original_filename} revoked.`);
        }),
      );
      record.append(copy, badge, actions);
      return record;
    }),
  );
};

const loadDocuments = async (tenantId) => {
  try {
    renderDocuments(await request(`/api/admin/tenants/${tenantId}/documents`));
  } catch (error) {
    document.querySelector("[data-registry-count]").textContent = "—";
    const message = document.createElement("p");
    message.className = "empty-state";
    message.textContent = error.message;
    documentRegistry.replaceChildren(message);
  }
};

const loadTenants = async () => {
  const result = await request("/api/admin/tenants");
  state.tenants = result;
  if (!state.selectedTenantId && result.length)
    state.selectedTenantId = result[0].id;
  renderTenants();
  contractTenant.replaceChildren(
    ...result.map((tenant) => {
      const option = document.createElement("option");
      option.value = tenant.id;
      option.textContent = tenant.name;
      option.selected = tenant.id === state.selectedTenantId;
      return option;
    }),
  );
};

const contractAction = async (contract, action) => {
  try {
    await request(`/api/admin/contracts/${contract.id}/${action}`, { method: "POST" });
    await loadContracts(Number(contractTenant.value));
    showToast(`Contract version ${contract.version} ${action === "rollback" ? "restored" : `${action}d`}.`);
  } catch (error) {
    showToast(error.message);
  }
};

const renderContracts = (contracts) => {
  document.querySelector("[data-contract-count]").textContent =
    `${contracts.length} ${contracts.length === 1 ? "version" : "versions"}`;
  const active = contracts.find((contract) => contract.state === "active");
  document.querySelector("[data-contract-status]").textContent = active
    ? `Active v${active.version}`
    : "No active contract";
  document.querySelector("[data-contract-signature]").textContent = active?.signature_valid
    ? `Active signature verified · ${active.contract_hash.slice(0, 12)}…`
    : "No verified active policy";
  if (active) contractJson.value = JSON.stringify(active.contract, null, 2);
  if (!contracts.length) {
    contractHistory.replaceChildren(Object.assign(document.createElement("p"), {
      className: "empty-state",
      textContent: "No contract versions exist for this tenant.",
    }));
    return;
  }
  contractHistory.replaceChildren(
    ...contracts.map((contract) => {
      const record = document.createElement("article");
      record.className = "contract-record";
      const copy = document.createElement("div");
      const title = document.createElement("strong");
      title.textContent = `Version ${contract.version}`;
      const detail = document.createElement("small");
      detail.textContent = `${contract.state.replaceAll("_", " ")} · ${contract.signature_valid ? "signature valid" : "signature invalid"}`;
      copy.append(title, detail);
      const badge = document.createElement("span");
      badge.className = `contract-state contract-state--${contract.state}`;
      badge.textContent = contract.state.replaceAll("_", " ");
      const actions = document.createElement("div");
      actions.className = "document-actions";
      if (contract.state === "draft") {
        const approve = document.createElement("button");
        approve.type = "button";
        approve.textContent = "Approve";
        approve.addEventListener("click", () => contractAction(contract, "approve"));
        actions.append(approve);
      }
      if (contract.state === "approved") {
        const activate = document.createElement("button");
        activate.type = "button";
        activate.textContent = "Activate";
        activate.addEventListener("click", () => contractAction(contract, "activate"));
        actions.append(activate);
      }
      if (contract.state === "superseded") {
        const rollback = document.createElement("button");
        rollback.type = "button";
        rollback.textContent = "Restore";
        rollback.addEventListener("click", () => contractAction(contract, "rollback"));
        actions.append(rollback);
      }
      const inspect = document.createElement("button");
      inspect.type = "button";
      inspect.textContent = "Inspect";
      inspect.addEventListener("click", () => {
        contractJson.value = JSON.stringify(contract.contract, null, 2);
        contractJson.focus();
      });
      actions.append(inspect);
      record.append(copy, badge, actions);
      return record;
    }),
  );
};

const loadContracts = async (tenantId) => {
  if (!tenantId) return;
  contractHistory.replaceChildren(Object.assign(document.createElement("p"), {
    className: "empty-state",
    textContent: "Loading contract history…",
  }));
  try {
    renderContracts(await request(`/api/admin/tenants/${tenantId}/contracts`));
  } catch (error) {
    showToast(error.message);
  }
};

contractTenant.addEventListener("change", () => loadContracts(Number(contractTenant.value)));
contractForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  contractMessage.hidden = true;
  let contract;
  try {
    contract = JSON.parse(contractJson.value);
  } catch {
    contractMessage.textContent = "Contract JSON is not valid.";
    contractMessage.hidden = false;
    return;
  }
  const button = document.querySelector("[data-save-contract]");
  button.disabled = true;
  try {
    await request(`/api/admin/tenants/${contractTenant.value}/contracts`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(contract),
    });
    await loadContracts(Number(contractTenant.value));
    showToast("Contract draft saved and signed.");
  } catch (error) {
    contractMessage.textContent = error.message;
    contractMessage.hidden = false;
  } finally {
    button.disabled = false;
  }
});

const updateIncidentStatus = async (incident, status) => {
  try {
    await request(`/api/admin/security/incidents/${incident.id}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status }),
    });
    await loadSecurityIncidents();
    showToast(`Incident ${status}.`);
  } catch (error) {
    showToast(error.message);
  }
};

const renderSecurityIncidents = (incidents) => {
  const openCount = incidents.filter((incident) => incident.status !== "resolved").length;
  document.querySelector("[data-security-count]").textContent =
    `${incidents.length} ${incidents.length === 1 ? "report" : "reports"}`;
  document.querySelector("[data-security-open-count]").textContent =
    openCount ? `(${openCount})` : "";
  if (!incidents.length) {
    securityIncidents.replaceChildren(Object.assign(document.createElement("p"), {
      className: "empty-state",
      textContent: "No security incidents have been reported.",
    }));
    return;
  }
  securityIncidents.replaceChildren(
    ...incidents.map((incident) => {
      const report = document.createElement("article");
      report.className = `incident-card incident-card--${incident.severity}`;
      const heading = document.createElement("div");
      heading.className = "incident-card__heading";
      const title = document.createElement("strong");
      title.textContent = incident.category.replaceAll("_", " ");
      const badges = document.createElement("span");
      badges.textContent = `${incident.severity} · ${incident.status}`;
      heading.append(title, badges);
      const summary = document.createElement("p");
      summary.textContent = `${incident.actor_username || incident.actor_email || "Unknown user"} · ${incident.tenant_name} · ${new Date(incident.detected_at).toLocaleString()}`;
      const details = document.createElement("p");
      details.textContent = `${incident.source.replaceAll("_", " ")} · policy v${incident.contract_version} · indicators: ${incident.indicators.join(", ")}`;
      const excerpt = document.createElement("code");
      excerpt.textContent = incident.evidence_excerpt || "No displayable evidence excerpt.";
      const actions = document.createElement("div");
      actions.className = "document-actions";
      if (incident.status === "open") {
        const acknowledge = document.createElement("button");
        acknowledge.type = "button";
        acknowledge.textContent = "Acknowledge";
        acknowledge.addEventListener("click", () => updateIncidentStatus(incident, "acknowledged"));
        actions.append(acknowledge);
      }
      if (incident.status !== "resolved") {
        const resolve = document.createElement("button");
        resolve.type = "button";
        resolve.textContent = "Resolve";
        resolve.addEventListener("click", () => updateIncidentStatus(incident, "resolved"));
        actions.append(resolve);
      }
      report.append(heading, summary, details, excerpt, actions);
      return report;
    }),
  );
};

const loadSecurityIncidents = async () => {
  try {
    renderSecurityIncidents(await request("/api/admin/security/incidents"));
  } catch (error) {
    showToast(error.message);
  }
};

const setTenantStatus = async (tenant, isActive, button) => {
  button.disabled = true;
  try {
    await request(`/api/admin/tenants/${tenant.id}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ is_active: isActive }),
    });
    await loadTenants();
    showToast(`${tenant.name} ${isActive ? "reactivated" : "suspended"}.`);
  } catch (error) {
    showToast(error.message);
  } finally {
    button.disabled = false;
  }
};

const loadUsers = async (tenantId) => {
  state.selectedTenantId = tenantId;
  renderTenantTabs();
  updateKnowledgePanel(tenantId);
  loadDocuments(tenantId);
  renderEmptyUsers("Loading users…");
  try {
    const result = await request(`/api/admin/tenants/${tenantId}/users`);
    if (!result.users.length) {
      renderEmptyUsers("No users belong to this tenant yet.");
      return;
    }
    userList.replaceChildren(
      ...result.users.map((user) => {
        const row = document.createElement("tr");
        const identityCell = document.createElement("td");
        const identity = document.createElement("div");
        identity.className = "user-cell";
        const avatar = document.createElement("span");
        avatar.className = "user-avatar";
        avatar.textContent = (user.username || user.email)[0].toUpperCase();
        const email = document.createElement("span");
        email.textContent = user.email || "—";
        identity.append(avatar, email);
        identityCell.append(identity);
        const username = document.createElement("td");
        username.textContent = user.username || "—";
        const role = document.createElement("td");
      const roleControl = document.createElement("div");
      roleControl.className = "role-control";
      const roleBadge = document.createElement("span");
      roleBadge.className = `role-pill${user.role === "pending" ? " is-pending" : ""}`;
      roleBadge.textContent = user.role.replaceAll("_", " ");
      roleControl.append(roleBadge);
      if (user.role !== "pending") {
        const roleSelect = document.createElement("select");
        roleSelect.setAttribute("aria-label", `Change role for ${user.username || user.email}`);
        ["user", "tenant_manager", "admin"].forEach((availableRole) => {
          const option = document.createElement("option");
          option.value = availableRole;
          option.textContent = availableRole.replaceAll("_", " ");
          option.selected = availableRole === user.role;
          roleSelect.append(option);
        });
        roleSelect.addEventListener("change", () => {
          const nextRole = roleSelect.value;
          roleSelect.value = user.role;
          openRoleConfirmation(user, nextRole);
        });
        roleControl.append(roleSelect);
      }
      role.append(roleControl);
        const status = document.createElement("td");
        status.className = `user-status${user.role === "pending" ? " is-pending" : user.is_active ? "" : " is-suspended"}`;
        status.textContent =
          user.role === "pending"
            ? "Awaiting approval"
            : user.is_active
              ? "Active"
              : "Suspended";
        const actionCell = document.createElement("td");
        const actions = document.createElement("span");
        actions.className = "user-actions";
        if (user.role === "pending") {
          actions.append(
            createUserAction(
              "approve",
              "Approve account",
              '<path d="m5 12 4 4L19 6" />',
              () => approveUser(user),
            ),
            createUserAction(
              "decline",
              "Decline and delete request",
              '<path d="m6 6 12 12M18 6 6 18" />',
              () => declineUser(user),
            ),
          );
      } else if (user.role !== "admin") {
          const action = user.is_active ? "suspend" : "reactivate";
          const label = user.is_active ? "Suspend user" : "Reactivate user";
          const icon = user.is_active
            ? '<circle cx="12" cy="12" r="9" /><path d="m8 8 8 8" />'
            : '<path d="m5 12 4 4L19 6" />';
          actions.append(
            createUserAction(action, label, icon, () =>
              setUserStatus(user, !user.is_active),
            ),
          );
        }
        actionCell.append(actions);
        row.append(identityCell, username, role, status, actionCell);
        return row;
      }),
    );
  } catch (error) {
    renderEmptyUsers(error.message);
  }
};

documentInput.addEventListener("change", () => selectDocuments(documentInput.files));
["dragenter", "dragover"].forEach((eventName) => {
  documentDropzone.addEventListener(eventName, (event) => {
    event.preventDefault();
    documentDropzone.classList.add("is-dragging");
  });
});
["dragleave", "drop"].forEach((eventName) => {
  documentDropzone.addEventListener(eventName, (event) => {
    event.preventDefault();
    documentDropzone.classList.remove("is-dragging");
  });
});
documentDropzone.addEventListener("drop", (event) =>
  selectDocuments(event.dataTransfer.files),
);
uploadDocumentsButton.addEventListener("click", async () => {
  if (!state.selectedTenantId || !selectedDocuments.length) return;
  uploadDocumentsButton.disabled = true;
  const files = [...selectedDocuments];
  let uploaded = 0;
  try {
    for (const file of files) {
      const body = new FormData();
      body.append("file", file);
      await request(`/api/admin/tenants/${state.selectedTenantId}/documents`, {
        method: "POST",
        body,
      });
      uploaded += 1;
    }
    selectedDocuments = [];
    documentInput.value = "";
    renderDocumentQueue();
    await loadDocuments(state.selectedTenantId);
    showToast(`${uploaded} ${uploaded === 1 ? "document" : "documents"} accepted for ingestion.`);
  } catch (error) {
    await loadDocuments(state.selectedTenantId);
    showToast(`${uploaded} uploaded. ${error.message}`);
  } finally {
    uploadDocumentsButton.disabled = selectedDocuments.length === 0;
  }
});

const loadAdmins = async () => {
  renderEmptyAdmins("Loading administrators…");
  try {
    const administrators = await request("/api/admin/admins");
    document.querySelector("[data-admin-count]").textContent =
      `${administrators.length} total`;
    if (!administrators.length) {
      renderEmptyAdmins("No administrator accounts were found.");
      return;
    }
    adminList.replaceChildren(
      ...administrators.map((administrator) => {
        const row = document.createElement("tr");
        const identityCell = document.createElement("td");
        const identity = document.createElement("div");
        identity.className = "user-cell";
        const avatar = document.createElement("span");
        avatar.className = "user-avatar";
        avatar.textContent = (
          administrator.username ||
          administrator.email ||
          "A"
        )[0].toUpperCase();
        const email = document.createElement("span");
        email.textContent = administrator.email || "Platform administrator";
        identity.append(avatar, email);
        identityCell.append(identity);

        const username = document.createElement("td");
        username.textContent = administrator.username || "—";
        const tenant = document.createElement("td");
        tenant.textContent = administrator.tenant_name || "Platform-wide";
        const status = document.createElement("td");
        status.className = `user-status${administrator.is_active ? "" : " is-suspended"}`;
        status.textContent = administrator.is_active ? "Active" : "Suspended";
        row.append(identityCell, username, tenant, status);
        return row;
      }),
    );
  } catch (error) {
    document.querySelector("[data-admin-count]").textContent = "—";
    renderEmptyAdmins(error.message);
  }
};

const createUserAction = (action, label, icon, handler) => {
  const button = document.createElement("button");
  button.type = "button";
  button.className = `user-action user-action--${action}`;
  button.setAttribute("aria-label", label);
  button.title = label;
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("aria-hidden", "true");
  svg.innerHTML = icon;
  button.append(svg);
  button.addEventListener("click", async () => {
    button.disabled = true;
    try {
      await handler();
    } finally {
      button.disabled = false;
    }
  });
  return button;
};

const refreshUsersAndCounts = async () => {
  await loadTenants();
  if (state.selectedTenantId) await loadUsers(state.selectedTenantId);
};

const approveUser = async (user) => {
  await request(`/api/admin/users/${user.id}/approve`, { method: "POST" });
  await refreshUsersAndCounts();
  showToast(`${user.username} approved.`);
};

const declineUser = async (user) => {
  if (!window.confirm(`Decline and permanently remove ${user.email}?`)) return;
  await request(`/api/admin/users/${user.id}`, { method: "DELETE" });
  await refreshUsersAndCounts();
  showToast(`${user.username}'s request declined.`);
};

const setUserStatus = async (user, isActive) => {
  await request(`/api/admin/users/${user.id}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ is_active: isActive }),
  });
  await loadUsers(state.selectedTenantId);
  showToast(`${user.username} ${isActive ? "reactivated" : "suspended"}.`);
};

const openRoleConfirmation = (user, nextRole) => {
  if (nextRole === user.role) return;
  state.roleChange = { user, nextRole };
  roleForm.reset();
  roleMessage.hidden = true;
  document.querySelector("[data-role-user]").textContent = user.email || user.username;
  document.querySelector("[data-role-user-initial]").textContent = (user.username || user.email)[0].toUpperCase();
  document.querySelector("[data-current-role]").textContent = user.role.replaceAll("_", " ");
  document.querySelector("[data-next-role]").textContent = nextRole.replaceAll("_", " ");
  roleDialog.showModal();
  roleForm.elements.adminPassword.focus();
};

document.querySelectorAll("[data-close-role-dialog]").forEach((button) => {
  button.addEventListener("click", () => {
    state.roleChange = null;
    roleDialog.close();
  });
});

roleForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!state.roleChange || !roleForm.reportValidity()) return;
  const button = document.querySelector("[data-confirm-role]");
  const { user, nextRole } = state.roleChange;
  button.disabled = true;
  roleMessage.hidden = true;
  try {
    await request(`/api/admin/users/${user.id}/role`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        role: nextRole,
        admin_password: roleForm.elements.adminPassword.value,
      }),
    });
    roleDialog.close();
    state.roleChange = null;
    await loadUsers(state.selectedTenantId);
    showToast(`${user.username}'s role changed to ${nextRole.replaceAll("_", " ")}.`);
  } catch (error) {
    roleMessage.textContent = error.message;
    roleMessage.hidden = false;
    roleForm.elements.adminPassword.select();
  } finally {
    button.disabled = false;
  }
});

const setView = (view) => {
  document.querySelectorAll("[data-view]").forEach((item) => {
    const active = item.dataset.view === view;
    item.classList.toggle("is-active", active);
    item.setAttribute("aria-selected", String(active));
  });
  document.querySelectorAll("[data-panel]").forEach((panel) => {
    panel.hidden = panel.dataset.panel !== view;
  });
};

const openUsersForTenant = (tenantId) => {
  setView("users");
  loadUsers(tenantId);
};

document.querySelectorAll("[data-view]").forEach((button) => {
  button.addEventListener("click", () => {
    setView(button.dataset.view);
    if (button.dataset.view === "users" && state.selectedTenantId)
      loadUsers(state.selectedTenantId);
    if (button.dataset.view === "admins") loadAdmins();
    if (button.dataset.view === "contracts" && contractTenant.value)
      loadContracts(Number(contractTenant.value));
    if (button.dataset.view === "security") loadSecurityIncidents();
  });
});

document
  .querySelector("[data-open-tenant-dialog]")
  .addEventListener("click", () => {
    tenantForm.reset();
    delete tenantForm.elements.slug.dataset.edited;
    formMessage.hidden = true;
    dialog.showModal();
  });
document
  .querySelectorAll("[data-close-tenant-dialog]")
  .forEach((button) => button.addEventListener("click", () => dialog.close()));
tenantForm.elements.name.addEventListener("input", () => {
  if (tenantForm.elements.slug.dataset.edited === "true") return;
  tenantForm.elements.slug.value = tenantForm.elements.name.value
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "");
});
tenantForm.elements.slug.addEventListener("input", () => {
  tenantForm.elements.slug.dataset.edited = "true";
});
tenantForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!tenantForm.reportValidity()) return;
  const button = document.querySelector("[data-create-tenant]");
  const values = new FormData(tenantForm);
  button.disabled = true;
  formMessage.hidden = true;
  try {
    const result = await request("/api/admin/tenants", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        name: values.get("name"),
        slug: values.get("slug"),
        description: values.get("description"),
      }),
    });
    dialog.close();
    await loadTenants();
    showToast(`${result.tenant.name} created successfully.`);
  } catch (error) {
    formMessage.textContent = error.message;
    formMessage.hidden = false;
  } finally {
    button.disabled = false;
  }
});

document.querySelector("[data-logout]").addEventListener("click", async () => {
  try {
    await fetch("/api/auth/logout", { method: "POST" });
  } finally {
    window.location.replace("/");
  }
});

const initialize = async () => {
  const session = await request("/api/auth/me");
  document.querySelector("[data-admin-name]").textContent =
    session.user.username || "admin";
  await loadTenants();
  await loadSecurityIncidents();
};
initialize().catch((error) => showToast(error.message));
