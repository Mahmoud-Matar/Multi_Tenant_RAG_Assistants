const params = new URLSearchParams(window.location.search);
const token = params.get("token") || "";
const isReset = window.location.pathname === "/reset-password";
const title = document.querySelector("[data-action-title]");
const copy = document.querySelector("[data-action-copy]");
const message = document.querySelector("[data-action-message]");
const form = document.querySelector("[data-reset-form]");

const show = (text, error = false) => {
  message.textContent = text;
  message.classList.toggle("is-error", error);
  message.hidden = false;
};

if (!token) {
  title.textContent = "This link is incomplete";
  copy.textContent = "Request a new security link from the sign-in page.";
  show("The one-time token is missing.", true);
} else if (isReset) {
  title.textContent = "Choose a new password";
  copy.textContent = "Use at least 12 characters. Completing this action logs out every device.";
  form.hidden = false;
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const password = form.elements.password.value;
    try {
      const response = await fetch("/api/auth/password-reset/confirm", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token, new_password: password }),
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.detail || "Unable to reset the password.");
      form.hidden = true;
      title.textContent = "Password updated";
      copy.textContent = result.message;
      show("You can now return to sign in.");
    } catch (error) {
      show(error.message, true);
    }
  });
} else {
  try {
    const response = await fetch("/api/auth/verify-email", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token }),
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.detail || "Unable to verify this email address.");
    title.textContent = "Email verified";
    copy.textContent = "Your address is verified. An administrator must still approve a pending account.";
    show(result.message);
  } catch (error) {
    title.textContent = "Verification failed";
    copy.textContent = "The link may have expired or already been used.";
    show(error.message, true);
  }
}
