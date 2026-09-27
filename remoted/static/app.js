"use strict";
// Talks only to this origin's /api/v1 routes. No external resources.
const $ = (id) => document.getElementById(id);
const views = ["login", "pair", "confirm", "status"];
const messages = {
  invalid_credential: "The password is incorrect.",
  invalid_pairing_code: "The pairing code is incorrect.",
  pairing_attempts_exhausted: "Too many incorrect codes. Enable remote management again at the console for a new code.",
  no_pending_pairing: "No pairing is pending. Enable remote management at the console first.",
  already_enrolled: "This machine already has an operator. Sign in instead.",
  password_rejected: "The password must be at least 12 characters and differ from the codes.",
  rate_limited: "Too many attempts. Try again later.",
  confirmation_expired: "The confirmation window passed. Enable remote management at the console again.",
  enrollment_unconfirmed: "Finish enrollment by confirming the recovery key.",
  not_enrolled: "No operator is enrolled yet. Pair this browser first.",
  busy: "The machine is busy. Try again.",
  unavailable: "The service is temporarily unavailable.",
};

function show(view, message) {
  for (const name of views) $(name).hidden = name !== view;
  $("message").textContent = message || "";
}

async function call(path, body) {
  const options = { method: body === undefined ? "GET" : "POST", credentials: "same-origin" };
  if (body !== null && body !== undefined) {
    options.headers = { "Content-Type": "application/json" };
    options.body = JSON.stringify(body);
  }
  const response = await fetch(path, options);
  let data = null;
  if (response.status !== 204) {
    try { data = await response.json(); } catch (_) { data = null; }
  }
  return { ok: response.ok, status: response.status, data };
}

function failure(result) {
  const code = result.data && result.data.error;
  return messages[code] || "The request failed.";
}

async function loadStatus() {
  const result = await call("/api/v1/status");
  if (result.ok) {
    $("status-json").textContent = JSON.stringify(result.data, null, 2);
    show("status");
  } else if (result.status === 401) {
    show("login");
  } else {
    show("login", failure(result));
  }
}

$("login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const result = await call("/api/v1/login", { password: $("login-password").value });
  $("login-password").value = "";
  if (result.ok) await loadStatus(); else show("login", failure(result));
});

$("pair-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if ($("pair-password").value !== $("pair-repeat").value) {
    show("pair", "The passwords do not match.");
    return;
  }
  const result = await call("/api/v1/pair", {
    pairing_code: $("pair-code").value.trim(),
    password: $("pair-password").value,
  });
  $("pair-password").value = "";
  $("pair-repeat").value = "";
  if (result.ok) {
    $("recovery-key").textContent = result.data.recovery_key;
    show("confirm");
  } else {
    show("pair", failure(result));
  }
});

$("confirm-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const key = $("confirm-key").value.replace(/[\s-]/g, "").toUpperCase();
  const result = await call("/api/v1/confirm", { recovery_key: key });
  if (result.ok) {
    $("recovery-key").textContent = "";
    $("confirm-key").value = "";
    show("login", "Enrollment is complete. Sign in with your new password.");
  } else {
    show("confirm", failure(result));
  }
});

$("refresh").addEventListener("click", loadStatus);
$("logout").addEventListener("click", async () => {
  await call("/api/v1/logout", null);
  show("login", "Signed out.");
});
$("show-pair").addEventListener("click", () => show("pair"));
$("show-login").addEventListener("click", () => show("login"));

loadStatus();
