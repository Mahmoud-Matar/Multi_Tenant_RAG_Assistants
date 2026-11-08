const list = document.querySelector("[data-session-list]");
const message = document.querySelector("[data-session-message]");

const request = async (url, options = {}) => {
  const response = await fetch(url, options);
  if (response.status === 401) {
    window.location.replace("/");
    throw new Error("Sign in to manage sessions.");
  }
  const result = response.status === 204 ? null : await response.json();
  if (!response.ok) throw new Error(result?.detail || "The request could not be completed.");
  return result;
};

const showMessage = (text, error = false) => {
  message.textContent = text;
  message.classList.toggle("is-error", error);
  message.hidden = false;
};

const describeAgent = (value) => {
  if (!value) return "Unknown browser";
  if (value.includes("Edg/")) return "Microsoft Edge";
  if (value.includes("Chrome/")) return "Google Chrome";
  if (value.includes("Firefox/")) return "Mozilla Firefox";
  if (value.includes("Safari/")) return "Safari";
  return value.slice(0, 80);
};

const loadSessions = async () => {
  const { sessions } = await request("/api/auth/sessions");
  list.replaceChildren(...sessions.map((session) => {
    const card = document.createElement("article");
    card.className = "session-card";
    const copy = document.createElement("div");
    const title = document.createElement("strong");
    title.textContent = `${describeAgent(session.user_agent)}${session.is_current ? " · Current session" : ""}`;
    const detail = document.createElement("small");
    detail.textContent = `${session.ip_address || "Unknown address"} · Last active ${new Date(session.last_seen_at).toLocaleString()}`;
    copy.append(title, detail);
    const button = document.createElement("button");
    button.type = "button";
    button.textContent = "Revoke";
    button.disabled = Boolean(session.revoked_at);
    button.addEventListener("click", async () => {
      try {
        await request(`/api/auth/sessions/${session.id}`, { method: "DELETE" });
        if (session.is_current) window.location.replace("/");
        else await loadSessions();
      } catch (error) {
        showMessage(error.message, true);
      }
    });
    card.append(copy, button);
    return card;
  }));
};

document.querySelector("[data-logout-all]").addEventListener("click", async () => {
  try {
    await request("/api/auth/logout-all", { method: "POST" });
    window.location.replace("/");
  } catch (error) {
    showMessage(error.message, true);
  }
});

try {
  const session = await request("/api/auth/me");
  document.querySelector("[data-back]").href = session.user.role === "admin"
    ? "/admin"
    : session.user.role === "tenant_manager" ? "/manager" : "/chat";
  await loadSessions();
} catch (error) {
  showMessage(error.message, true);
}
