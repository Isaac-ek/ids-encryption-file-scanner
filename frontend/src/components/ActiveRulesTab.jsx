import React, { useState } from "react";
import { Plus, Pencil, Trash2 } from "lucide-react";
import { Badge, Dialog, Empty } from "./ui";
export default function ActiveRulesTab({
  rules,
  canManage,
  api,
  run,
  refresh,
  notify,
  busy,
}) {
  const [editing, setEditing] = useState(null),
    [removing, setRemoving] = useState(null);
  async function save(event) {
    event.preventDefault();
    const form = Object.fromEntries(new FormData(event.currentTarget));
    const success = await run(async () => {
      await api("/alerts/rules" + (editing.id ? "/" + editing.id : ""), {
        method: editing.id ? "PUT" : "POST",
        json: {
          ...form,
          threshold: form.threshold ? Number(form.threshold) : null,
          enabled: editing.enabled ?? true,
        },
      });
      await refresh();
      notify("Rule saved.");
      return true;
    });
    if (success) setEditing(null);
  }
  return (
    <>
      <div className="section-toolbar">
        <p className="muted">Manage your saved detection-rule configuration.</p>
        {canManage && (
          <button
            className="button primary"
            onClick={() => setEditing({ type: "ip", enabled: true })}
          >
            <Plus size={16} />
            Add rule
          </button>
        )}
      </div>
      <section className="panel">
        <div className="panel-heading">
          <h2>
            Saved rules <span className="count">{rules.length}</span>
          </h2>
        </div>
        {rules.length ? (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Rule</th>
                  <th>Type</th>
                  <th>Pattern</th>
                  <th>Threshold</th>
                  <th>Status</th>
                  {canManage && <th>Actions</th>}
                </tr>
              </thead>
              <tbody>
                {rules.map((rule) => (
                  <tr key={rule.id}>
                    <td>
                      <strong>{rule.name}</strong>
                    </td>
                    <td>
                      {rule.type === "ip"
                        ? "IP address"
                        : rule.type === "port"
                          ? "Port"
                          : "Bandwidth"}
                    </td>
                    <td className="mono">{rule.value}</td>
                    <td>{rule.threshold ?? "—"}</td>
                    <td>
                      {canManage ? (
                        <button
                          className={`toggle ${rule.enabled ? "on" : ""}`}
                          role="switch"
                          aria-checked={rule.enabled}
                          aria-label={`Enable ${rule.name}`}
                          disabled={busy}
                          onClick={() =>
                            run(async () => {
                              await api("/alerts/rules/" + rule.id, {
                                method: "PUT",
                                json: { ...rule, enabled: !rule.enabled },
                              });
                              await refresh();
                            })
                          }
                        >
                          <span />
                        </button>
                      ) : (
                        <Badge>{rule.enabled ? "Enabled" : "Disabled"}</Badge>
                      )}
                    </td>
                    {canManage && (
                      <td>
                        <div className="row-actions">
                          <button
                            className="icon-button"
                            aria-label={`Edit ${rule.name}`}
                            onClick={() => setEditing(rule)}
                          >
                            <Pencil size={16} />
                          </button>
                          <button
                            className="icon-button danger-text"
                            aria-label={`Delete ${rule.name}`}
                            onClick={() => setRemoving(rule)}
                          >
                            <Trash2 size={16} />
                          </button>
                        </div>
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <Empty title="No saved rules">
            Add an IP, port, or bandwidth configuration to keep your rules
            together.
          </Empty>
        )}
      </section>
      <div className="note-row">
        <p>
          These are saved configurations. They do not change your
          operating-system firewall or retrain the intrusion model.
        </p>
      </div>
      {editing && (
        <Dialog
          title={editing.id ? "Edit rule" : "Create a rule"}
          onClose={() => setEditing(null)}
        >
          <form onSubmit={save}>
            <label>
              Rule name
              <input
                name="name"
                defaultValue={editing.name || ""}
                required
                maxLength={100}
              />
            </label>
            <label>
              Rule type
              <select name="type" defaultValue={editing.type}>
                <option value="ip">IP address</option>
                <option value="port">Port</option>
                <option value="bandwidth">Bandwidth</option>
              </select>
            </label>
            <label>
              Pattern value
              <input
                name="value"
                defaultValue={editing.value || ""}
                required
                maxLength={200}
              />
            </label>
            <label>
              Threshold (optional)
              <input
                name="threshold"
                type="number"
                min={0}
                max={2147483647}
                defaultValue={editing.threshold ?? ""}
              />
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
                Save rule
              </button>
            </div>
          </form>
        </Dialog>
      )}
      {removing && (
        <Dialog title="Delete this rule?" onClose={() => setRemoving(null)}>
          <p>
            The saved configuration for <strong>{removing.name}</strong> will be
            removed.
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
                  await api("/alerts/rules/" + removing.id, {
                    method: "DELETE",
                  });
                  await refresh();
                  setRemoving(null);
                  notify("Rule deleted.");
                })
              }
            >
              Delete rule
            </button>
          </div>
        </Dialog>
      )}
    </>
  );
}
