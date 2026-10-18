const root = document.documentElement;
const themeButton = document.querySelector("[data-theme-toggle]");
const prompt = document.querySelector("[data-prompt]");
const sendButton = document.querySelector("[data-send]");
const composer = document.querySelector("[data-composer]");
const welcome = document.querySelector("[data-welcome]");
const messages = document.querySelector("[data-messages]");
const sidebar = document.querySelector("[data-sidebar]");

const setTheme = (theme) => {
  const isDark = theme === "dark";
  root.dataset.theme = theme;
  themeButton.setAttribute("aria-pressed", String(isDark));
  themeButton.setAttribute("aria-label", `Switch to ${isDark ? "light" : "dark"} mode`);
};

const savedTheme = localStorage.getItem("atlasTheme");
setTheme(savedTheme || (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light"));

themeButton.addEventListener("click", () => {
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
  avatar.textContent = role === "user" ? document.querySelector("[data-user-initial]").textContent : "A";
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
    const response = await fetch("/api/rag/query", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ question: text }),
    });
    const result = await response.json();
    if (response.status === 401) {
      window.location.replace("/");
      return;
    }
    if (!response.ok) throw new Error(result.detail || "The assistant could not answer.");
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

const loadSession = async () => {
  try {
    const response = await fetch("/api/auth/me");
    if (!response.ok) throw new Error("Session expired");
    const { user } = await response.json();
    document.querySelector("[data-user-email]").textContent = user.email;
    document.querySelector("[data-user-initial]").textContent = user.email[0].toUpperCase();
    document.querySelector("[data-tenant-name]").textContent = user.tenant.name;
    document.querySelector("[data-tenant-initials]").textContent = user.tenant.initials;
  } catch {
    window.location.replace("/");
  }
};

document.querySelector("[data-logout]").addEventListener("click", async () => {
  try {
    await fetch("/api/auth/logout", { method: "POST" });
  } finally {
    window.location.replace("/");
  }
});

loadSession();
prompt.focus();
