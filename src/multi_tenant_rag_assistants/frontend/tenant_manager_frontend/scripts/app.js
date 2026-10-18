const state = { session: null, tenant: null, users: [], roleChange: null, files: [] };
const root = document.documentElement;
const sidebar = document.querySelector("[data-sidebar]");
const prompt = document.querySelector("[data-prompt]");
const sendButton = document.querySelector("[data-send]");
const composer = document.querySelector("[data-composer]");
const welcome = document.querySelector("[data-welcome]");
const messages = document.querySelector("[data-messages]");
const userList = document.querySelector("[data-user-list]");
const roleDialog = document.querySelector("[data-role-dialog]");
const roleForm = document.querySelector("[data-role-form]");
const roleMessage = document.querySelector("[data-role-message]");
const documentInput = document.querySelector("[data-document-input]");
const documentDropzone = document.querySelector("[data-document-dropzone]");
const documentQueue = document.querySelector("[data-document-queue]");
const documentList = document.querySelector("[data-document-list]");
const uploadButton = document.querySelector("[data-upload-documents]");
const documentRegistry = document.querySelector("[data-document-registry]");
const toast = document.querySelector("[data-toast]");

const request = async (url, options = {}) => {
  const response = await fetch(url, options);
  const result = response.status === 204 ? null : await response.json();
  if (response.status === 401) {
    window.location.replace("/");
    throw new Error("Session expired");
  }
  if (response.status === 403) {
    window.location.replace("/chat");
    throw new Error("Tenant manager access required");
  }
  if (!response.ok) {
    const detail = Array.isArray(result?.detail)
      ? result.detail[0]?.msg
      : result?.detail;
    throw new Error(detail || "The request could not be completed.");
  }
  return result;
};

const showToast = (message) => {
  toast.textContent = message;
  toast.hidden = false;
  window.setTimeout(() => {
    toast.hidden = true;
  }, 3200);
};

const setTheme = (theme) => {
  const isDark = theme === "dark";
  root.dataset.theme = theme;
  const button = document.querySelector("[data-theme-toggle]");
  button.setAttribute("aria-pressed", String(isDark));
  button.setAttribute("aria-label", `Switch to ${isDark ? "light" : "dark"} mode`);
};
setTheme(
  localStorage.getItem("atlasTheme") ||
    (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light"),
);
document.querySelector("[data-theme-toggle]").addEventListener("click", () => {
  const theme = root.dataset.theme === "dark" ? "light" : "dark";
  localStorage.setItem("atlasTheme", theme);
  setTheme(theme);
});

const setSidebar = (open) => {
  sidebar.classList.toggle("is-open", open);
  document.body.classList.toggle("sidebar-open", open);
};
document.querySelector("[data-sidebar-open]").addEventListener("click", () => setSidebar(true));
document.querySelectorAll("[data-sidebar-close]").forEach((button) => {
  button.addEventListener("click", () => setSidebar(false));
});

const setView = (view) => {
  document.querySelectorAll("[data-view]").forEach((button) => {
    button.classList.toggle("is-active", button.dataset.view === view);
  });
  document.querySelectorAll("[data-panel]").forEach((panel) => {
    panel.hidden = panel.dataset.panel !== view;
  });
  document.querySelector("[data-chat-navigation]").hidden = view !== "chat";
  document.querySelector("[data-page-title]").textContent =
    view === "chat" ? "Atlas Assistant" : state.tenant?.name || "Tenant management";
  document.querySelector("[data-page-status]").innerHTML =
    view === "chat" ? "<i></i> Ready" : "<i></i> Manager workspace";
  setSidebar(false);
  if (view === "chat") prompt.focus();
};
document.querySelectorAll("[data-view]").forEach((button) => {
  button.addEventListener("click", () => setView(button.dataset.view));
});

const resizePrompt = () => {
  prompt.style.height = "auto";
  prompt.style.height = `${Math.min(prompt.scrollHeight, 190)}px`;
  sendButton.disabled = !prompt.value.trim();
};
prompt.addEventListener("input", resizePrompt);
prompt.addEventListener("keydown", (event) => {
  if (event.key === "Enter" && !event.shiftKey) {
    event.preventDefault();
    if (prompt.value.trim()) composer.requestSubmit();
  }
});

const appendMessage = (role, text, citations = []) => {
  const article = document.createElement("article");
  article.className = `message message--${role}`;
  const avatar = document.createElement("span");
  avatar.className = "message__avatar";
  avatar.textContent =
    role === "user"
      ? document.querySelector("[data-user-initial]").textContent
      : "A";
  const body = document.createElement("div");
  body.className = "message__body";
  const content = document.createElement("p");
  content.textContent = text;
  body.append(content);
  if (citations.length) {
    const sources = document.createElement("div");
    sources.className = "message__sources";
    const label = document.createElement("strong");
    label.textContent = "Sources";
    sources.append(label);
    citations.forEach((citation) => {
      const source = document.createElement("details");
      const summary = document.createElement("summary");
      summary.textContent = `[${citation.number}] ${citation.filename}`;
      const excerpt = document.createElement("p");
      excerpt.textContent = citation.excerpt;
      source.append(summary, excerpt);
      sources.append(source);
    });
    body.append(sources);
  }
  article.append(avatar, body);
  messages.append(article);
  article.scrollIntoView({ behavior: "smooth", block: "end" });
  return article;
};
composer.addEventListener("submit", async (event) => {
  event.preventDefault();
  const text = prompt.value.trim();
  if (!text) return;
  welcome.hidden = true;
  appendMessage("user", text);
  prompt.value = "";
  resizePrompt();
  prompt.disabled = true;
  sendButton.disabled = true;
  const pending = appendMessage("assistant", "Searching your tenant's approved knowledge…");
  pending.classList.add("message--pending");
  try {
    const result = await request("/api/rag/query", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ question: text }),
    });
    pending.remove();
    appendMessage("assistant", result.answer, result.citations);
  } catch (error) {
    pending.remove();
    appendMessage("assistant", error.message || "The assistant could not answer right now.");
  } finally {
    prompt.disabled = false;
    resizePrompt();
    prompt.focus();
  }
});
document.querySelectorAll("[data-suggestion]").forEach((button) => {
  button.addEventListener("click", () => {
    prompt.value = button.dataset.suggestion;
    resizePrompt();
    prompt.focus();
  });
});
document.querySelector("[data-new-chat]").addEventListener("click", () => {
  messages.replaceChildren();
  welcome.hidden = false;
  prompt.value = "";
  resizePrompt();
  prompt.focus();
  setSidebar(false);
});

const renderEmptyUsers = (message) => {
  const row = document.createElement("tr");
  const cell = document.createElement("td");
  cell.colSpan = 4;
  cell.className = "empty-state";
  cell.textContent = message;
  row.append(cell);
  userList.replaceChildren(row);
};

const openRoleConfirmation = (user, nextRole) => {
  if (nextRole === user.role) return;
  state.roleChange = { user, nextRole };
  roleForm.reset();
  roleMessage.hidden = true;
  document.querySelector("[data-role-user]").textContent = user.email || user.username;
  document.querySelector("[data-role-user-initial]").textContent =
    (user.username || user.email)[0].toUpperCase();
  document.querySelector("[data-current-role]").textContent = user.role.replaceAll("_", " ");
  document.querySelector("[data-next-role]").textContent = nextRole.replaceAll("_", " ");
  roleDialog.showModal();
  roleForm.elements.managerPassword.focus();
};

const renderUsers = () => {
  document.querySelector("[data-user-count]").textContent = state.users.length;
  document.querySelector("[data-manager-count]").textContent =
    state.users.filter((user) => user.role === "tenant_manager").length;
  document.querySelector("[data-member-count]").textContent =
    `${state.users.length} ${state.users.length === 1 ? "member" : "members"}`;
  if (!state.users.length) {
    renderEmptyUsers("No users belong to this tenant yet.");
    return;
  }
  userList.replaceChildren(
    ...state.users.map((user) => {
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
      if (["user", "tenant_manager"].includes(user.role)) {
        const select = document.createElement("select");
        select.setAttribute("aria-label", `Change role for ${user.username || user.email}`);
        ["user", "tenant_manager"].forEach((availableRole) => {
          const option = document.createElement("option");
          option.value = availableRole;
          option.textContent = availableRole.replaceAll("_", " ");
          option.selected = availableRole === user.role;
          select.append(option);
        });
        const isSelf = user.id === state.session.id;
        select.disabled = isSelf;
        select.addEventListener("change", () => {
          const nextRole = select.value;
          select.value = user.role;
          openRoleConfirmation(user, nextRole);
        });
        roleControl.append(select);
        if (isSelf) {
          const selfLabel = document.createElement("span");
          selfLabel.className = "self-label";
          selfLabel.textContent = "You";
          roleControl.append(selfLabel);
        }
      }
      role.append(roleControl);

      const status = document.createElement("td");
      status.className = `user-status${user.role === "pending" ? " is-pending" : user.is_active ? "" : " is-suspended"}`;
      status.textContent =
        user.role === "pending"
          ? "Awaiting admin approval"
          : user.is_active
            ? "Active"
            : "Suspended";
      row.append(identityCell, username, role, status);
      return row;
    }),
  );
};

const loadTenantWorkspace = async () => {
  const result = await request("/api/manager/tenant");
  state.tenant = result.tenant;
  state.users = result.users;
  document.querySelector("[data-tenant-name]").textContent = result.tenant.name;
  document.querySelector("[data-tenant-initials]").textContent = result.tenant.name
    .split(/\s+/)
    .map((part) => part[0])
    .join("")
    .toUpperCase()
    .slice(0, 3);
  document.querySelector("[data-management-title]").textContent = `${result.tenant.name} management`;
  document.querySelector("[data-knowledge-tenant]").textContent = result.tenant.name;
  document.querySelector("[data-knowledge-badge]").textContent = result.tenant.name;
  document.querySelector("[data-tenant-status]").textContent =
    result.tenant.is_active ? "Active" : "Suspended";
  renderUsers();
  await loadDocuments();
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
    await request(`/api/manager/users/${user.id}/role`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        role: nextRole,
        manager_password: roleForm.elements.managerPassword.value,
      }),
    });
    roleDialog.close();
    state.roleChange = null;
    await loadTenantWorkspace();
    showToast(`${user.username}'s role changed to ${nextRole.replaceAll("_", " ")}.`);
  } catch (error) {
    roleMessage.textContent = error.message;
    roleMessage.hidden = false;
    roleForm.elements.managerPassword.select();
  } finally {
    button.disabled = false;
  }
});

const formatFileSize = (bytes) => {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
};
const renderFiles = () => {
  documentQueue.hidden = state.files.length === 0;
  uploadButton.disabled = state.files.length === 0;
  document.querySelector("[data-document-count]").textContent =
    `${state.files.length} ${state.files.length === 1 ? "file" : "files"}`;
  documentList.replaceChildren(
    ...state.files.map((file) => {
      const item = document.createElement("li");
      const icon = document.createElementNS("http://www.w3.org/2000/svg", "svg");
      icon.setAttribute("viewBox", "0 0 24 24");
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
const selectFiles = (files) => {
  const allowed = ["pdf", "docx", "txt"];
  state.files = [...files].filter((file) =>
    allowed.includes(file.name.split(".").pop()?.toLowerCase()),
  );
  renderFiles();
  if (files.length && !state.files.length) showToast("Choose PDF, DOCX, or TXT documents.");
};

const documentStatus = (storedDocument) =>
  storedDocument.version.approval_status === "pending"
    ? "pending approval"
    : storedDocument.version.ingestion_status;

const renderDocuments = (documents) => {
  document.querySelector("[data-registry-count]").textContent =
    `${documents.length} ${documents.length === 1 ? "document" : "documents"}`;
  if (!documents.length) {
    const empty = document.createElement("p");
    empty.className = "empty-state";
    empty.textContent = "No documents have been submitted for this tenant.";
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
      const revoke = document.createElement("button");
      revoke.type = "button";
      revoke.className = "delete-document";
      revoke.textContent = "Revoke";
      revoke.addEventListener("click", async () => {
        if (!window.confirm(`Revoke ${storedDocument.original_filename} from retrieval?`)) return;
        revoke.disabled = true;
        try {
          await request(`/api/manager/documents/${storedDocument.id}`, { method: "DELETE" });
          await loadDocuments();
          showToast(`${storedDocument.original_filename} revoked.`);
        } catch (error) {
          showToast(error.message);
        } finally {
          revoke.disabled = false;
        }
      });
      const actions = document.createElement("div");
      actions.className = "document-actions";
      if (storedDocument.version.ingestion_status === "active") {
        const reindex = document.createElement("button");
        reindex.type = "button";
        reindex.className = "reindex-document";
        reindex.textContent = "Reindex";
        reindex.addEventListener("click", async () => {
          reindex.disabled = true;
          try {
            await request(`/api/manager/documents/${storedDocument.id}/reindex`, {
              method: "POST",
            });
            await loadDocuments();
            showToast(`${storedDocument.original_filename} queued for reindexing.`);
          } catch (error) {
            showToast(error.message);
          } finally {
            reindex.disabled = false;
          }
        });
        actions.append(reindex);
      }
      actions.append(revoke);
      record.append(copy, badge, actions);
      return record;
    }),
  );
};

const loadDocuments = async () => {
  try {
    renderDocuments(await request("/api/manager/documents"));
  } catch (error) {
    document.querySelector("[data-registry-count]").textContent = "—";
    const message = document.createElement("p");
    message.className = "empty-state";
    message.textContent = error.message;
    documentRegistry.replaceChildren(message);
  }
};
documentInput.addEventListener("change", () => selectFiles(documentInput.files));
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
documentDropzone.addEventListener("drop", (event) => selectFiles(event.dataTransfer.files));
uploadButton.addEventListener("click", async () => {
  if (!state.files.length) return;
  uploadButton.disabled = true;
  const files = [...state.files];
  let uploaded = 0;
  try {
    for (const file of files) {
      const body = new FormData();
      body.append("file", file);
      await request("/api/manager/documents", { method: "POST", body });
      uploaded += 1;
    }
    state.files = [];
    documentInput.value = "";
    renderFiles();
    await loadDocuments();
    showToast(`${uploaded} ${uploaded === 1 ? "document" : "documents"} submitted for approval.`);
  } catch (error) {
    await loadDocuments();
    showToast(`${uploaded} submitted. ${error.message}`);
  } finally {
    uploadButton.disabled = state.files.length === 0;
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
  const { user } = await request("/api/auth/me");
  state.session = user;
  document.querySelector("[data-user-email]").textContent = user.email;
  document.querySelector("[data-user-initial]").textContent = user.email[0].toUpperCase();
  await loadTenantWorkspace();
};
initialize().catch((error) => showToast(error.message));
prompt.focus();
