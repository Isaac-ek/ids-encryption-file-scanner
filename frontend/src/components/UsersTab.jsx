import React, { useState } from "react";
import { UserPlus, Pencil, Trash2, Copy, Check, KeyRound } from "lucide-react";
import { Badge, Dialog, label } from "./ui";

export default function UsersTab({
  users,
  currentUser,
  api,
  run,
  refresh,
  notify,
  busy,
}) {
  const [editing, setEditing] = useState(null),
    [removing, setRemoving] = useState(null),
    [credentials, setCredentials] = useState(null),
    [copied, setCopied] = useState(false);
  async function save(event) {
    event.preventDefault();
    const values = Object.fromEntries(new FormData(event.currentTarget));
    const creating = !editing.username;
    if (!values.password) delete values.password;
    const username = creating ? values.username : editing.username;
    const success = await run(async () => {
      await api(
        `/auth/users${creating ? "" : "/" + encodeURIComponent(username)}`,
        { method: creating ? "POST" : "PUT", json: values },
      );
      await refresh();
      notify(
        creating
          ? "Account created. Share the sign-in details directly with this person."
          : "Account updated.",
      );
      return true;
    });
    if (success) {
      if (creating) setCredentials({ username, password: values.password });
      setEditing(null);
    }
  }
  return (
    <>
      <div className="section-toolbar">
        <p className="muted">
          Manage who can sign in and what they can access.
        </p>
        <button
          className="button primary"
          onClick={() => setEditing({ name: "", role: "user" })}
        >
          <UserPlus size={16} />
          Add user
        </button>
      </div>
      <section className="panel">
        <div className="panel-heading">
          <h2>
            Workspace members <span className="count">{users.length}</span>
          </h2>
          <span className="muted text-small">
            Administrator-managed accounts
          </span>
        </div>
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Member</th>
                <th>Username</th>
                <th>Access</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {users.map((person) => (
                <tr key={person.id}>
                  <td>
                    <div className="person">
                      <span className="avatar">
                        {person.name.slice(0, 2).toUpperCase()}
                      </span>
                      <div>
                        <strong>{person.name}</strong>
                        {person.username === currentUser.username && (
                          <span className="muted text-small">You</span>
                        )}
                      </div>
                    </div>
                  </td>
                  <td className="mono">{person.username}</td>
                  <td>
                    <Badge
                      tone={person.role === "admin" ? "strong" : "neutral"}
                    >
                      {label(person.role)}
                    </Badge>
                  </td>
                  <td>
                    <div className="row-actions">
                      <button
                        className="button small secondary"
                        onClick={() => setEditing(person)}
                      >
                        <Pencil size={14} />
                        Edit
                      </button>
                      <button
                        className="icon-button danger-text"
                        disabled={
                          person.username === currentUser.username || busy
                        }
                        aria-label={`Delete ${person.username}`}
                        title={
                          person.username === currentUser.username
                            ? "Your active account cannot be deleted"
                            : "Remove account"
                        }
                        onClick={() => setRemoving(person)}
                      >
                        <Trash2 size={16} />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
      <div className="access-explainer">
        <div>
          <h3>Administrators</h3>
          <p>
            Manage accounts and rules, run website checks, and inspect audit
            history.
          </p>
        </div>
        <div>
          <h3>Members</h3>
          <p>
            Inspect events, test model records, check files, and use file
            protection.
          </p>
        </div>
      </div>
      {editing && (
        <Dialog
          title={editing.username ? "Edit member" : "Create an account"}
          onClose={() => setEditing(null)}
        >
          <form onSubmit={save}>
            <label>
              Full name
              <input
                name="name"
                defaultValue={editing.name}
                required
                maxLength={100}
              />
            </label>
            {!editing.username && (
              <label>
                Username
                <input
                  name="username"
                  aria-label="Username"
                  aria-describedby="account-username-help"
                  required
                  minLength={3}
                  maxLength={64}
                  pattern="[A-Za-z0-9_.\-]+"
                  autoComplete="off"
                />
                <span id="account-username-help" className="field-help">
                  Letters, numbers, dots, underscores and hyphens.
                </span>
              </label>
            )}
            <label>
              Recovery email (optional)
              <input
                name="email"
                type="email"
                defaultValue={editing.email || ""}
                maxLength={254}
                autoComplete="email"
              />
              <span className="field-help">
                Password-reset links are sent to this address. Confirm it
                belongs to this member.
              </span>
            </label>
            <label>
              Access level
              <select
                name="role"
                defaultValue={editing.role}
                disabled={editing.username === currentUser.username}
              >
                <option value="user">Member</option>
                <option value="admin">Administrator</option>
              </select>
            </label>
            <label>
              {editing.username
                ? "New password (optional)"
                : "Initial password"}
              <input
                name="password"
                type="password"
                minLength={12}
                maxLength={128}
                required={!editing.username}
                autoComplete="new-password"
              />
              <span className="field-help">
                At least 12 characters.
                {editing.username
                  ? " Leave blank to keep the existing password."
                  : ""}
              </span>
            </label>
            <div className="dialog-actions">
              <button
                type="button"
                className="button secondary"
                onClick={() => setEditing(null)}
              >
                Cancel
              </button>
              <button className="button primary" disabled={busy}>
                {busy
                  ? "Saving…"
                  : editing.username
                    ? "Save changes"
                    : "Create account"}
              </button>
            </div>
          </form>
        </Dialog>
      )}
      {removing && (
        <Dialog title="Remove this account?" onClose={() => setRemoving(null)}>
          <p>
            <strong>{removing.username}</strong> will no longer be able to sign
            in. Their audit history is retained.
          </p>
          <div className="dialog-actions">
            <button
              className="button secondary"
              onClick={() => setRemoving(null)}
            >
              Cancel
            </button>
            <button
              className="button destructive"
              disabled={busy}
              onClick={() =>
                run(async () => {
                  await api(
                    "/auth/users/" + encodeURIComponent(removing.username),
                    { method: "DELETE" },
                  );
                  await refresh();
                  setRemoving(null);
                  notify("Account removed.");
                })
              }
            >
              Remove account
            </button>
          </div>
        </Dialog>
      )}
      {credentials && (
        <Dialog
          title="Account ready"
          onClose={() => {
            setCredentials(null);
            setCopied(false);
          }}
        >
          <div className="success-icon">
            <KeyRound size={22} />
          </div>
          <p>
            Share these details privately. The member can change their password
            from Account settings.
          </p>
          <dl className="credential-list">
            <div>
              <dt>Username</dt>
              <dd>{credentials.username}</dd>
            </div>
            <div>
              <dt>Initial password</dt>
              <dd className="mono">{credentials.password}</dd>
            </div>
          </dl>
          <button
            className="button secondary"
            onClick={async () => {
              try {
                await navigator.clipboard.writeText(
                  `Username: ${credentials.username}\nPassword: ${credentials.password}`,
                );
                setCopied(true);
              } catch {
                notify("Select the displayed details to copy them.");
              }
            }}
          >
            {copied ? <Check size={16} /> : <Copy size={16} />}
            {copied ? "Copied" : "Copy sign-in details"}
          </button>
        </Dialog>
      )}
    </>
  );
}

export function AccountDialog({
  api,
  run,
  busy,
  user,
  onClose,
  onToken,
  notify,
}) {
  return (
    <Dialog title="Account settings" onClose={onClose}>
      <div className="account-summary">
        <span className="avatar large">
          {user.name.slice(0, 2).toUpperCase()}
        </span>
        <div>
          <strong>{user.name}</strong>
          <p className="muted">
            {user.username} · {label(user.role)}
          </p>
        </div>
      </div>
      <p className="muted">
        Recovery email: {user.email || "Not set"}. Your workspace administrator
        can update this in People &amp; access.
      </p>
      <form
        onSubmit={(event) => {
          event.preventDefault();
          const values = Object.fromEntries(new FormData(event.currentTarget));
          run(async () => {
            const result = await api("/auth/password", {
              method: "POST",
              json: values,
            });
            onToken(result.access_token);
            notify(result.message);
            onClose();
          });
        }}
      >
        <h3>Change your password</h3>
        <label>
          Current password
          <input
            name="current_password"
            type="password"
            required
            autoComplete="current-password"
          />
        </label>
        <label>
          New password
          <input
            name="new_password"
            aria-label="New password"
            aria-describedby="own-password-help"
            type="password"
            minLength={12}
            maxLength={128}
            required
            autoComplete="new-password"
          />
          <span id="own-password-help" className="field-help">
            At least 12 characters.
          </span>
        </label>
        <div className="dialog-actions">
          <button className="button primary" disabled={busy}>
            Update password
          </button>
        </div>
      </form>
    </Dialog>
  );
}
