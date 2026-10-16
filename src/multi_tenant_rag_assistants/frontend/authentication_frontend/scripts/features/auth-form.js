const VIEW_COPY = {
  signin: {
    kicker: "Welcome back",
    title: "Sign in to your workspace",
    subtitle: "Enter your details to continue to Atlas.",
  },
  register: {
    kicker: "Join your team",
    title: "Create your account",
    subtitle: "Set up your credentials and choose a workspace.",
  },
};

const getErrorMessage = (input) => {
  if (input.name === "tenant" && !input.value) return "Please select an associated tenant.";
  if (input.validity.valueMissing) return `${input.name.toLowerCase().includes("password") ? "Password" : "Email or username"} is required.`;
  if (input.validity.typeMismatch) return "Enter a valid email address.";
  if (input.validity.tooShort) return "Password must be at least 8 characters.";
  return "Please check this field.";
};

export class AuthForms {
  constructor(apiBaseUrl = "") {
    this.apiBaseUrl = apiBaseUrl;
    this.tabs = [...document.querySelectorAll("[data-mode]")];
    this.forms = [...document.querySelectorAll(".auth-form")];
    this.message = document.querySelector(".form-message");
    this.kicker = document.querySelector("#form-kicker");
    this.title = document.querySelector("#form-title");
    this.subtitle = document.querySelector("#form-subtitle");
    this.bindEvents();
  }

  bindEvents() {
    this.tabs.forEach((tab) => {
      tab.addEventListener("click", () => this.setMode(tab.dataset.mode));
      tab.addEventListener("keydown", (event) => {
        if (!["ArrowLeft", "ArrowRight"].includes(event.key)) return;
        event.preventDefault();
        const mode = tab.dataset.mode === "signin" ? "register" : "signin";
        this.setMode(mode);
        this.tabs.find((item) => item.dataset.mode === mode)?.focus();
      });
    });

    this.forms.forEach((form) => {
      form.addEventListener("submit", (event) => this.handleSubmit(event));
      form.addEventListener("input", (event) => this.clearFieldError(event.target));
    });

    document.querySelectorAll("[data-password-toggle]").forEach((button) => {
      button.addEventListener("click", () => this.togglePassword(button));
    });

    document.querySelector('[data-demo-action="reset"]')?.addEventListener("click", () => {
      this.showMessage("Password recovery will be connected when the authentication backend is added.");
    });
  }

  setMode(mode) {
    const copy = VIEW_COPY[mode];
    this.kicker.textContent = copy.kicker;
    this.title.textContent = copy.title;
    this.subtitle.textContent = copy.subtitle;
    this.message.hidden = true;

    this.tabs.forEach((tab) => {
      const active = tab.dataset.mode === mode;
      tab.classList.toggle("is-active", active);
      tab.setAttribute("aria-selected", String(active));
      tab.tabIndex = active ? 0 : -1;
    });

    this.forms.forEach((form) => {
      const active = form.id === `${mode}-form`;
      form.hidden = !active;
      form.classList.toggle("is-active", active);
    });
  }

  validate(form) {
    let valid = true;
    const inputs = [...form.querySelectorAll("input[required]")];
    const password = form.querySelector('[name="password"]');
    const confirm = form.querySelector('[name="confirmPassword"]');

    inputs.forEach((input) => {
      const isMissingTenant = input.name === "tenant" && !input.value;
      if (!input.checkValidity() || isMissingTenant) {
        this.setFieldError(input, getErrorMessage(input));
        valid = false;
      }
    });

    if (password && confirm?.value && password.value !== confirm.value) {
      this.setFieldError(confirm, "Passwords do not match.");
      valid = false;
    }
    return valid;
  }

  setFieldError(input, message) {
    const field = input.closest(".field");
    field?.classList.add("has-error");
    const error = field?.querySelector(".field__error");
    if (error) error.textContent = message;
    input.setAttribute("aria-invalid", "true");
  }

  clearFieldError(input) {
    if (!(input instanceof HTMLInputElement)) return;
    const field = input.closest(".field");
    field?.classList.remove("has-error");
    input.removeAttribute("aria-invalid");
  }

  async handleSubmit(event) {
    event.preventDefault();
    const form = event.currentTarget;
    if (!this.validate(form)) {
      form.querySelector(".has-error input, .has-error button")?.focus();
      return;
    }

    const isSignIn = form.id === "signin-form";
    const submitButton = form.querySelector('button[type="submit"]');
    const originalLabel = submitButton.querySelector("span").textContent;
    const values = new FormData(form);
    const payload = {
      ...(isSignIn
        ? { identifier: values.get("identifier") }
        : { email: values.get("email") }),
      password: values.get("password"),
      ...(isSignIn
        ? { remember: values.get("remember") === "on" }
        : { tenant_id: Number(values.get("tenant")) }),
    };

    submitButton.disabled = true;
    submitButton.querySelector("span").textContent = isSignIn ? "Signing in…" : "Creating account…";
    this.message.hidden = true;

    try {
      const endpoint = isSignIn ? "/api/auth/login" : "/api/auth/register";
      const response = await fetch(`${this.apiBaseUrl}${endpoint}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const result = await response.json();
      const detail = Array.isArray(result.detail) ? result.detail[0]?.msg : result.detail;
      if (!response.ok) throw new Error(detail || "The request could not be completed.");

      if (isSignIn) {
        const destination = result.user.role === "admin" ? "the administration portal" : result.user.tenant.name;
        this.showMessage(`Signed in to ${destination}.`);
        window.location.assign(result.landing_path);
      } else {
        form.reset();
        this.showMessage(`Request submitted for ${result.user.email}. An administrator must approve the account before you can sign in.`);
      }
    } catch (error) {
      this.showMessage(error.message || "Unable to reach the server. Please try again.", true);
    } finally {
      submitButton.disabled = false;
      submitButton.querySelector("span").textContent = originalLabel;
    }
  }

  showMessage(text, isError = false) {
    this.message.textContent = text;
    this.message.classList.toggle("is-error", isError);
    this.message.hidden = false;
  }

  togglePassword(button) {
    const input = document.getElementById(button.dataset.passwordToggle);
    const show = input.type === "password";
    input.type = show ? "text" : "password";
    button.classList.toggle("is-visible", show);
    button.setAttribute("aria-label", show ? "Hide password" : "Show password");
  }
}
