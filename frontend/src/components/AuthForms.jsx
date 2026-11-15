import React, { useEffect, useState } from "react";
import { ArrowUpRight } from "lucide-react";

export default function AuthForms({
  api,
  run,
  busy,
  notice,
  notify,
  resetToken,
  onSession,
  onResetDone,
}) {
  const [mode, setMode] = useState(resetToken ? "reset" : "login");
  const [available, setAvailable] = useState(null);
  useEffect(() => {
    let active = true;
    api("/auth/recovery-status")
      .then((result) => {
        if (active) setAvailable(result.available);
      })
      .catch(() => {
        if (active) setAvailable(false);
      });
    return () => {
      active = false;
    };
  }, [api]);
  const titles = {
    login: "Welcome back.",
    forgot: "Forgot your password?",
    reset: "Choose a new password.",
  };
  const help = {
    login: "Sign in with your workspace account.",
    forgot: "Enter your username and the recovery email saved on your account.",
    reset:
      "Use at least 12 characters. Updating your password signs out all existing sessions.",
  };
  function switchMode(next) {
    setMode(next);
    notify("");
  }
  async function submit(event) {
    event.preventDefault();
    const values = Object.fromEntries(new FormData(event.currentTarget));
    if (mode === "reset" && values.new_password !== values.confirm_password) {
      notify("The passwords do not match.", "error");
      return;
    }
    await run(async () => {
      if (mode === "login") {
        const result = await api("/auth/login", {
          method: "POST",
          body: new URLSearchParams(values),
        });
        onSession(result.access_token);
      } else if (mode === "forgot") {
        const result = await api("/auth/forgot-password", {
          method: "POST",
          json: values,
        });
        notify(result.message);
      } else {
        const result = await api("/auth/reset-password", {
          method: "POST",
          json: { token: resetToken, new_password: values.new_password },
        });
        onResetDone();
        setMode("login");
        notify(result.message);
      }
    });
  }
  return (
    <>
      <span className="eyebrow">Workspace access</span>
      <h2>{titles[mode]}</h2>
      <p className="muted">{help[mode]}</p>
      {notice?.message && (
        <div
          className={`notice ${notice.tone === "error" ? "error" : "success"}`}
          role={notice.tone === "error" ? "alert" : "status"}
        >
          {notice.message}
        </div>
      )}
      {mode === "forgot" && available === false && (
        <p className="notice">
          Email recovery is unavailable. Your workspace administrator can reset
          your password from People &amp; access.
        </p>
      )}
      <form onSubmit={submit} key={mode}>
        {mode !== "reset" && (
          <label>
            Username
            <input
              name="username"
              autoComplete="username"
              required
              maxLength={64}
              placeholder="Your username"
            />
          </label>
        )}
        {mode === "forgot" && (
          <label>
            Recovery email
            <input
              name="email"
              type="email"
              autoComplete="email"
              required
              maxLength={254}
              placeholder="you@example.com"
            />
          </label>
        )}
        {mode === "login" && (
          <label>
            Password
            <input
              name="password"
              type="password"
              autoComplete="current-password"
              required
              placeholder="Enter your password"
            />
          </label>
        )}
        {mode === "reset" && (
          <>
            <label>
              New password
              <input
                name="new_password"
                type="password"
                autoComplete="new-password"
                required
                minLength={12}
                maxLength={128}
              />
            </label>
            <label>
              Confirm new password
              <input
                name="confirm_password"
                type="password"
                autoComplete="new-password"
                required
                minLength={12}
                maxLength={128}
              />
            </label>
          </>
        )}
        <button
          className="button primary"
          disabled={busy || (mode === "forgot" && available !== true)}
        >
          {busy
            ? "Please wait…"
            : mode === "login"
              ? "Sign in"
              : mode === "forgot"
                ? "Send reset link"
                : "Update password"}
          <ArrowUpRight size={16} />
        </button>
      </form>
      <div className="login-help">
        {mode === "login" ? (
          <>
            <button
              className="button small secondary"
              onClick={() => switchMode("forgot")}
            >
              Forgot password?
            </button>
            <p>
              Need an account? Your workspace administrator can create one for
              you.
            </p>
          </>
        ) : (
          <button
            className="button small secondary"
            onClick={() => {
              if (resetToken) onResetDone();
              switchMode("login");
            }}
          >
            Back to sign in
          </button>
        )}
        {mode === "reset" && notice?.tone === "error" && (
          <button
            className="button small secondary"
            onClick={() => switchMode("forgot")}
          >
            Request a new reset link
          </button>
        )}
      </div>
    </>
  );
}
