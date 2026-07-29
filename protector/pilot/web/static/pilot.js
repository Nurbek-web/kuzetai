"use strict";

const formMessage = (form, message, isError = false) => {
  const target = form.querySelector("[data-form-message]");
  if (!target) {
    return;
  }
  target.textContent = message;
  target.classList.toggle("is-error", isError);
};

const loginForm = document.querySelector("[data-login-form]");
if (loginForm) {
  loginForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const submit = loginForm.querySelector("button[type='submit']");
    submit.disabled = true;
    formMessage(loginForm, "Signing in…");
    const data = new FormData(loginForm);
    try {
      const response = await fetch("/api/auth/login", {
        method: "POST",
        credentials: "same-origin",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({
          username: data.get("username"),
          password: data.get("password"),
          totp_code: data.get("totp_code"),
        }),
      });
      if (!response.ok) {
        formMessage(loginForm, "Sign-in failed. Check your credentials and try again.", true);
        return;
      }
      window.location.assign("/pilot");
    } catch {
      formMessage(loginForm, "The console is unavailable. Try again shortly.", true);
    } finally {
      submit.disabled = false;
    }
  });
}

const reviewForm = document.querySelector("[data-review-form]");
if (reviewForm) {
  reviewForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const action = event.submitter?.value;
    if (action !== "confirmed" && action !== "rejected") {
      formMessage(reviewForm, "Choose confirm or reject.", true);
      return;
    }
    const csrf = document.querySelector("meta[name='csrf-token']")?.content;
    const eventId = reviewForm.dataset.eventId;
    const notes = new FormData(reviewForm).get("notes");
    const idempotencyKey = `review-${crypto.randomUUID()}`;
    const buttons = reviewForm.querySelectorAll("button[type='submit']");
    buttons.forEach((button) => {
      button.disabled = true;
    });
    formMessage(reviewForm, "Saving review…");
    try {
      const response = await fetch(`/api/events/${eventId}/review`, {
        method: "POST",
        credentials: "same-origin",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": csrf,
          "Idempotency-Key": idempotencyKey,
        },
        body: JSON.stringify({
          expected_status: "candidate",
          target_status: action,
          notes: notes || null,
          reviewed_at: new Date().toISOString(),
        }),
      });
      if (response.status === 409) {
        formMessage(reviewForm, "This event changed. Refresh before reviewing again.", true);
        return;
      }
      if (!response.ok) {
        formMessage(reviewForm, "The review was not saved. Try again.", true);
        return;
      }
      window.location.reload();
    } catch {
      formMessage(reviewForm, "Network error. The review was not saved.", true);
    } finally {
      buttons.forEach((button) => {
        button.disabled = false;
      });
    }
  });
}

const refreshButton = document.querySelector("[data-refresh]");
if (refreshButton) {
  refreshButton.addEventListener("click", () => {
    const loading = document.querySelector("[data-loading-state]");
    if (loading) {
      loading.hidden = false;
    }
    refreshButton.disabled = true;
    window.location.reload();
  });
}

const logoutButton = document.querySelector("[data-logout]");
if (logoutButton) {
  logoutButton.addEventListener("click", async () => {
    const csrf = document.querySelector("meta[name='csrf-token']")?.content;
    logoutButton.disabled = true;
    try {
      const response = await fetch("/api/auth/logout", {
        method: "POST",
        credentials: "same-origin",
        headers: {"X-CSRF-Token": csrf},
      });
      if (!response.ok) {
        logoutButton.disabled = false;
        return;
      }
      window.location.assign("/pilot/login");
    } catch {
      logoutButton.disabled = false;
    }
  });
}
