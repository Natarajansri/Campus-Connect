/**
 * Campus Connect — Sign-in page logic
 *
 * Security decisions:
 * - No demo accounts, no seeded passwords, no browser-side provisioning.
 * - No role/session data is written to localStorage. Firebase Auth owns the
 *   session; role is read from the ID token custom claim by firebase-service.js.
 * - Credential errors are intentionally generic to prevent account enumeration.
 * - A client-side cooldown slows repeated password guessing. The real brute-force
 *   protection is Firebase Auth's server-side rate limiting / Identity Platform.
 * - Access is blocked until the college email address is verified.
 */

const MAX_LOGIN_ATTEMPTS = 5;
const BASE_COOLDOWN_MS = 30 * 1000;
const MAX_COOLDOWN_MS = 5 * 60 * 1000;
const FAILURE_KEY = "campusLoginFailures";
const COOLDOWN_KEY = "campusLoginCooldownUntil";

function getCooldownRemainingMs() {
  const until = Number(localStorage.getItem(COOLDOWN_KEY) || 0);
  return Math.max(0, until - Date.now());
}

function recordLoginFailure() {
  const failures = Number(localStorage.getItem(FAILURE_KEY) || 0) + 1;
  localStorage.setItem(FAILURE_KEY, String(failures));
  if (failures >= MAX_LOGIN_ATTEMPTS) {
    const exponent = Math.min(failures - MAX_LOGIN_ATTEMPTS, 4);
    const cooldown = Math.min(MAX_COOLDOWN_MS, BASE_COOLDOWN_MS * Math.pow(2, exponent));
    localStorage.setItem(COOLDOWN_KEY, String(Date.now() + cooldown));
  }
}

function clearLoginFailures() {
  localStorage.removeItem(FAILURE_KEY);
  localStorage.removeItem(COOLDOWN_KEY);
}

function showAlert(message, type = "error") {
  const alertBox = document.getElementById("authAlert");
  if (!alertBox) return;
  alertBox.className = `alert-box ${type}`;
  alertBox.textContent = "";
  const icon = document.createElement("span");
  icon.textContent = type === "error" ? "⚠️" : "✅";
  const text = document.createElement("span");
  text.textContent = String(message || "");
  alertBox.appendChild(icon);
  alertBox.appendChild(document.createTextNode(" "));
  alertBox.appendChild(text);
}

function clearAlert() {
  const alertBox = document.getElementById("authAlert");
  if (!alertBox) return;
  alertBox.className = "alert-box";
  alertBox.textContent = "";
}

function showToast(message) {
  const toast = document.getElementById("toastMessage");
  if (!toast) return;
  toast.textContent = message;
  toast.classList.add("show");
  setTimeout(() => toast.classList.remove("show"), 2800);
}

function togglePasswordVisibility(inputId, btn) {
  const input = document.getElementById(inputId);
  if (!input) return;
  if (input.type === "password") {
    input.type = "text";
    btn.textContent = "🙈";
  } else {
    input.type = "password";
    btn.textContent = "👁️";
  }
}

function isValidEmail(email) {
  // Convenience validation only; Firebase Auth validates again server-side.
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) && email.length <= 254;
}

async function handleForgotPassword() {
  clearAlert();
  const email = document.getElementById("loginEmail").value.trim().toLowerCase();
  if (!isValidEmail(email)) {
    showAlert("Enter your college email above, then choose 'Forgot password?'.");
    return;
  }
  const res = await sendPasswordReset(email);
  if (res && !res.success) {
    showAlert(res.error || "Could not send password reset email.");
    return;
  }
  showAlert("Password reset link sent! Check your Gmail (Inbox and Spam/Junk folder).", "success");
}

async function handleLogin(e) {
  e.preventDefault();
  clearAlert();

  const email = document.getElementById("loginEmail").value.trim().toLowerCase();
  const password = document.getElementById("loginPassword").value;
  const rememberMe = document.getElementById("rememberMe").checked;
  const submitBtn = document.getElementById("btnSubmitLogin");

  if (!isValidEmail(email) || !password) {
    showAlert("Enter a valid college email and password.");
    return false;
  }
  if (password.length > 4096) {
    showAlert("Invalid credentials.");
    return false;
  }

  const cooldown = getCooldownRemainingMs();
  if (cooldown > 0) {
    showAlert(`Too many attempts. Try again in ${Math.ceil(cooldown / 1000)} seconds.`);
    return false;
  }

  if (submitBtn) {
    submitBtn.disabled = true;
    submitBtn.dataset.originalText = submitBtn.textContent;
    submitBtn.textContent = "Signing in…";
  }

  try {
    initFirebase();
    if (fbAuth) {
      const persistence = rememberMe
        ? firebase.auth.Auth.Persistence.LOCAL
        : firebase.auth.Auth.Persistence.SESSION;
      try { await fbAuth.setPersistence(persistence); } catch (e) {}
    }

    const result = await firebaseSignIn(email, password);

    if (result.success) {
      clearLoginFailures();
      showAlert("Signed in. Redirecting to your dashboard…", "success");
      showToast("Signed in successfully");
      try { sessionStorage.setItem("postLoginRedirect", "dashboard"); } catch (e) {}
      setTimeout(() => { window.location.href = "index.html"; }, 400);
      return false;
    }

    if (result.notRegistered) {
      showAlert(result.error || "Access Denied: Your email is not registered in the campus directory. Contact campus IT.");
      return false;
    }

    if (result.needsVerification) {
      showAlert(result.error || "Please verify your email before signing in.");
      showToast("Verification email sent");
      return false;
    }

    recordLoginFailure();
    showAlert(result.error || "Invalid credentials.");
    return false;
  } finally {
    if (submitBtn) {
      submitBtn.disabled = false;
      submitBtn.textContent = submitBtn.dataset.originalText || "Sign In to Campus Board";
    }
  }
}

async function handleGoogleSignIn() {
  clearAlert();
  showToast("Opening Google Sign-In…");

  if (typeof firebaseGoogleSignIn !== "function") {
    showAlert("Sign-in is initializing. Please try again in a moment.");
    return;
  }

  const res = await firebaseGoogleSignIn();
  if (res.success) {
    clearLoginFailures();
    showAlert("Signed in with Google. Redirecting…", "success");
    try { sessionStorage.setItem("postLoginRedirect", "dashboard"); } catch (e) {}
    setTimeout(() => { window.location.href = "index.html"; }, 400);
    return;
  }
  if (res.notRegistered) {
    showAlert(res.error || "Access Denied: Your email is not registered in the campus directory. Contact campus IT.");
    return;
  }
  if (res.redirecting) {
    showToast("Redirecting to Google Sign-In…");
    return;
  }
  if (res.needsVerification) {
    showAlert("Please verify your college email before signing in.");
    return;
  }
  if (res.code === "auth/popup-closed-by-user") {
    showAlert("Google sign-in was closed before completion.");
    return;
  }
  if (res.code === "auth/unauthorized-domain") {
    showAlert("This domain is not authorized for Google sign-in. Contact campus IT.");
    return;
  }
  if (res.code === "auth/operation-not-allowed" || res.code === "auth/configuration-not-found") {
    showAlert("Google sign-in is not enabled for this campus. Use your college email and password.");
    return;
  }
  if (res.code === "auth/operation-not-supported-in-this-environment") {
    showAlert("Google sign-in requires the site to be served over HTTP(S), not opened as a local file.");
    return;
  }
  // Generic message: no provider/account details leak.
  showAlert(res.error || "Google sign-in failed. Please try again.");
}

window.addEventListener("DOMContentLoaded", async () => {
  // Complete a Google redirect if the browser returned from one.
  if (typeof firebaseCompleteRedirectSignIn === "function") {
    const res = await firebaseCompleteRedirectSignIn();
    if (res && res.success) {
      clearLoginFailures();
      showToast("Signed in with Google");
      try { sessionStorage.setItem("postLoginRedirect", "dashboard"); } catch (e) {}
      setTimeout(() => { window.location.href = "index.html"; }, 400);
      return;
    }
    if (res && res.notRegistered) {
      showAlert(res.error || "Access Denied: Your email is not registered in the campus directory.");
      return;
    }
    if (res && res.needsVerification) {
      showAlert("Please verify your college email before signing in.");
    }
  }

  const params = new URLSearchParams(window.location.search);
  const emailParam = params.get("email");
  if (emailParam) {
    const emailEl = document.getElementById("loginEmail");
    if (emailEl) emailEl.value = String(emailParam).slice(0, 254);
  }
});
