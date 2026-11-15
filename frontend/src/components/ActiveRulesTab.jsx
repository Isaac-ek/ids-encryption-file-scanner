import React, { useState } from "react";
import { Trash2 } from "lucide-react";

export default function ActiveRulesTab({
  rules,
  canManage,
  handleAddRule,
  handleDeleteRule,
}) {
  const [creating, setCreating] = useState(false);
  return (
    <section className="card">
      <div className="section-heading">
        <h2>Saved rules</h2>
        {canManage && (
          <button
            className="btn btn-secondary"
            onClick={() => setCreating(!creating)}
          >
            {creating ? "Cancel" : "Add rule"}
          </button>
        )}
      </div>
      {creating && (
        <form
          onSubmit={async (event) => {
            event.preventDefault();
            const form = new FormData(event.currentTarget);
            const success = await handleAddRule(Object.fromEntries(form));
            if (success) setCreating(false);
          }}
        >
          <label>
            Rule name
            <input name="name" required maxLength={100} />
          </label>
          <label>
            Rule type
            <select name="type">
              <option value="ip">IP address</option>
              <option value="port">Port</option>
              <option value="bandwidth">Bandwidth</option>
            </select>
          </label>
          <label>
            Pattern value
            <input name="value" required maxLength={200} />
          </label>
          <label>
            Threshold (optional)
            <input name="threshold" type="number" min="0" />
          </label>
          <button className="btn btn-primary">Save rule</button>
        </form>
      )}
      <div className="table-container">
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Type</th>
              <th>Pattern</th>
              <th>Threshold</th>
              <th>Status</th>
              {canManage && <th>Action</th>}
            </tr>
          </thead>
          <tbody>
            {rules.length ? (
              rules.map((rule) => (
                <tr key={rule.id}>
                  <td>{rule.name}</td>
                  <td>{rule.type}</td>
                  <td>{rule.value}</td>
                  <td>{rule.threshold ?? "—"}</td>
                  <td>{rule.enabled ? "Enabled" : "Disabled"}</td>
                  {canManage && (
                    <td>
                      <button
                        className="logout-btn"
                        aria-label={`Delete ${rule.name}`}
                        onClick={() => handleDeleteRule(rule.id)}
                      >
                        <Trash2 size={16} />
                      </button>
                    </td>
                  )}
                </tr>
              ))
            ) : (
              <tr>
                <td colSpan={canManage ? 6 : 5}>No saved rules.</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </section>
  );
}
