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

const appendMessage = (role, text) => {
  const article = document.createElement("article");
  article.className = `message message--${role}`;
  const avatar = document.createElement("span");
  avatar.className = "message__avatar";
  avatar.textContent = role === "user" ? document.querySelector("[data-user-initial]").textContent : "A";
  const content = document.createElement("p");
  content.textContent = text;
  article.append(avatar, content);
  messages.append(article);
  article.scrollIntoView({ behavior: "smooth", block: "end" });
};

composer.addEventListener("submit", (event) => {
  event.preventDefault();
  const text = prompt.value.trim();
  if (!text) return;
  welcome.hidden = true;
  appendMessage("user", text);
  prompt.value = "";
  resizePrompt();
  window.setTimeout(() => {
    appendMessage("assistant", "Your message is ready. The LLM response will appear here once the chat backend is connected.");
  }, 250);
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
