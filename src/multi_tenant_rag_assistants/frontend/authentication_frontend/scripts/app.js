import { API_BASE_URL } from "./config.js";
import { TenantSelect } from "./components/tenant-select.js";
import { AuthForms } from "./features/auth-form.js";

const themeToggle = document.querySelector("[data-theme-toggle]");
const preferredTheme = localStorage.getItem("atlasTheme")
  || (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");

const setTheme = (theme) => {
  const isDark = theme === "dark";
  document.documentElement.dataset.theme = theme;
  themeToggle.setAttribute("aria-pressed", String(isDark));
  themeToggle.setAttribute("aria-label", `Switch to ${isDark ? "light" : "dark"} mode`);
  themeToggle.querySelector(".theme-toggle__label").textContent = isDark ? "Light mode" : "Dark mode";
};

setTheme(preferredTheme);
themeToggle.addEventListener("click", () => {
  const nextTheme = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
  localStorage.setItem("atlasTheme", nextTheme);
  setTheme(nextTheme);
});

const tenantSelects = [...document.querySelectorAll("[data-tenant-select]")].map(
  (element) => new TenantSelect(element),
);

const loadTenants = async () => {
  tenantSelects.forEach((select) => select.setLoading(true));
  try {
    const response = await fetch(`${API_BASE_URL}/api/tenants`);
    if (!response.ok) throw new Error("Tenant request failed");
    const tenants = await response.json();
    tenantSelects.forEach((select) => select.setTenants(tenants));
  } catch {
    tenantSelects.forEach((select) => select.setError("Tenants unavailable"));
  }
};

new AuthForms(API_BASE_URL);
loadTenants();
