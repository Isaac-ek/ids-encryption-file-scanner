import React, { useState } from "react";
import {
  Activity,
  ArrowRight,
  Download,
  FileSearch,
  Globe,
  Lock,
  Play,
  Search,
  ShieldCheck,
  SlidersHorizontal,
} from "lucide-react";
import {
  Badge,
  Empty,
  EventTable,
  dateTime,
  number,
  label,
  saveData,
} from "./ui";
import { Metric } from "./ModelTab";

export function OverviewTab({ overview, files, model, onGo, onInspect }) {
  const items = [
    ["sensor", "Live sensor"],
    ["model-replay", "Model replays"],
    ["sensor-simulation", "Sensor simulations"],
  ];
  return (
    <>
      <div className="metrics-grid four">
        <Metric
          title="Recorded events"
          value={number(overview?.total_events)}
          note={`${number(overview?.last_24_hours)} in the last 24 hours`}
          icon={Activity}
        />
        <Metric
          title="Encrypted backups"
          value={files ? number(files.encrypted_files.length) : "—"}
          note="Stored in this workspace"
          icon={Lock}
        />
        <Metric
          title="Website checks"
          value={number(overview?.website_checks)}
          note="Saved assessment reports"
          icon={Globe}
        />
        <Metric
          title="File inspections"
          value={number(overview?.file_checks)}
          note="Saved local check results"
          icon={FileSearch}
        />
      </div>
      <div className="quick-actions">
        <button onClick={() => onGo("web")}>
          <span className="quick-icon">
            <Globe size={19} />
          </span>
          <span>
            <strong>Check a website</strong>
            <small>Review an authorized target</small>
          </span>
          <ArrowRight size={16} />
        </button>
        <button onClick={() => onGo("files")}>
          <span className="quick-icon">
            <Lock size={19} />
          </span>
          <span>
            <strong>Protect a file</strong>
            <small>Encrypt, download, or recover</small>
          </span>
          <ArrowRight size={16} />
        </button>
        <button onClick={onInspect}>
          <span className="quick-icon">
            <Play size={18} />
          </span>
          <span>
            <strong>Test the detector</strong>
            <small>Inspect a labelled sample record</small>
          </span>
          <ArrowRight size={16} />
        </button>
      </div>
      <div className="overview-grid">
        <section className="panel">
          <div className="panel-heading">
            <h2>Recent activity</h2>
            <button className="text-button" onClick={() => onGo("events")}>
              All events <ArrowRight size={14} />
            </button>
          </div>
          {overview ? (
            <EventTable events={overview.recent} />
          ) : (
            <div className="list-empty" role="status">
              Loading recent activity…
            </div>
          )}
        </section>
        <section className="panel">
          <div className="panel-heading">
            <h2>Activity sources</h2>
          </div>
          <div className="source-list">
            {items.map(([key, name]) => (
              <div key={key}>
                <span>
                  <span
                    className={`origin-dot ${key === "sensor" ? "live" : ""}`}
                  />
                  {name}
                </span>
                <strong>
                  {number(
                    overview?.origins?.[key] ?? (overview ? 0 : undefined),
                  )}
                </strong>
              </div>
            ))}
          </div>
          <div className="sensor-note">
            <span className="eyebrow">Last sensor event</span>
            <strong>
              {overview?.latest_sensor_event
                ? dateTime(overview.latest_sensor_event)
                : overview
                  ? "No live sensor event recorded"
                  : "Loading activity…"}
            </strong>
            <p>
              Live packet capture runs on the configured host sensor. Replays
              remain separately labelled.
            </p>
          </div>
          <div className="model-foot">
            <span
              className={`status-dot ${model?.available ? "online" : ""}`}
            />
            <div>
              <strong>
                {!model
                  ? "Loading model…"
                  : model.available
                    ? model.model_type
                    : "Model not available"}
              </strong>
              <span>
                {model?.available
                  ? `${model.features} features · saved classifier`
                  : !model
                    ? "Reading the saved classifier"
                    : "Check the model bundle"}
              </span>
            </div>
            <button
              className="icon-button"
              aria-label="Open model performance"
              onClick={() => onGo("model")}
            >
              <ArrowRight size={16} />
            </button>
          </div>
        </section>
      </div>
    </>
  );
}
export function EventsTab({
  events,
  filters,
  onFilters,
  onInspect,
  onExport,
  busy,
}) {
  const [draft, setDraft] = useState(filters);
  const update = (name, value) =>
    setDraft((old) => ({ ...old, [name]: value }));
  const pages = Math.max(1, Math.ceil((events?.total || 0) / 25));
  return (
    <>
      <div className="section-toolbar">
        <p className="muted">
          Filter recorded sensor events and model predictions.
        </p>
        <div className="row-actions">
          <button
            className="button secondary"
            disabled={busy}
            onClick={() => onExport("csv")}
          >
            <Download size={15} />
            CSV
          </button>
          <button
            className="button secondary"
            disabled={busy}
            onClick={() => onExport("json")}
          >
            JSON
          </button>
          <button className="button primary" onClick={onInspect}>
            <Play size={15} />
            Test a record
          </button>
        </div>
      </div>
      <section className="panel">
        <form
          className="filter-bar"
          onSubmit={(event) => {
            event.preventDefault();
            onFilters({ ...draft, page: 1 });
          }}
        >
          <label>
            Recorded date
            <input
              type="date"
              value={draft.date || ""}
              onChange={(event) => update("date", event.target.value)}
            />
          </label>
          <label>
            Prediction
            <select
              value={draft.alert_type || ""}
              onChange={(event) => update("alert_type", event.target.value)}
            >
              <option value="">All results</option>
              {["Normal", "DoS", "Probe", "R2L", "U2R", "Malware Detected"].map(
                (value) => (
                  <option key={value}>{value}</option>
                ),
              )}
            </select>
          </label>
          <label>
            Origin
            <select
              value={draft.origin || ""}
              onChange={(event) => update("origin", event.target.value)}
            >
              <option value="">All origins</option>
              {["sensor", "model-replay", "sensor-simulation", "file-scan"].map(
                (value) => (
                  <option key={value} value={value}>
                    {label(value)}
                  </option>
                ),
              )}
            </select>
          </label>
          <label>
            Source
            <input
              placeholder="IP or source"
              value={draft.src || ""}
              onChange={(event) => update("src", event.target.value)}
            />
          </label>
          <label>
            Destination
            <input
              placeholder="IP or destination"
              value={draft.dst || ""}
              onChange={(event) => update("dst", event.target.value)}
            />
          </label>
          <button className="button secondary" disabled={busy}>
            <Search size={15} />
            Apply
          </button>
          <button
            type="button"
            className="text-button"
            onClick={() => {
              const empty = { page: 1 };
              setDraft(empty);
              onFilters(empty);
            }}
          >
            Reset
          </button>
        </form>
        <EventTable events={events?.items} />
        <div className="pagination">
          <span>{number(events?.total)} matching events</span>
          <div className="row-actions">
            <span>
              Page {filters.page || 1} of {pages}
            </span>
            <button
              className="button small secondary"
              disabled={busy || (filters.page || 1) <= 1}
              onClick={() =>
                onFilters({ ...filters, page: (filters.page || 1) - 1 })
              }
            >
              Previous
            </button>
            <button
              className="button small secondary"
              disabled={busy || (filters.page || 1) >= pages}
              onClick={() =>
                onFilters({ ...filters, page: (filters.page || 1) + 1 })
              }
            >
              Next
            </button>
          </div>
        </div>
      </section>
      <p className="footnote">
        Exports contain up to 10,000 matching records. A model replay is not
        live packet capture.
      </p>
    </>
  );
}
export function WebsiteTab({
  scope,
  scans,
  api,
  run,
  refresh,
  notify,
  busy,
  canManage,
}) {
  const [selected, setSelected] = useState(null);
  const current = selected || scans[0];
  return (
    <div className="assessment-layout">
      <div className="assessment-input">
        <section className="panel padded">
          <div className="section-icon">
            <Globe size={21} />
          </div>
          <h2>Check an authorized website</h2>
          <p className="muted">
            Review headers, TLS, CORS, redirects, mixed content, and exposed
            terms.
          </p>
          {canManage ? (
            <form
              onSubmit={(event) => {
                event.preventDefault();
                const values = new FormData(event.currentTarget);
                run(async () => {
                  const result = await api("/scans/run", {
                    method: "POST",
                    json: {
                      url: values.get("url"),
                      authorized: values.has("authorized"),
                      paths: values.has("paths"),
                      ports: values.has("ports"),
                      reflected_input: values.has("reflected_input"),
                      keywords: values.get("keywords"),
                    },
                  });
                  setSelected(result);
                  await refresh();
                  notify(`Website check #${result.id} saved.`);
                });
              }}
            >
              <label>
                Target URL
                <input
                  name="url"
                  type="url"
                  required
                  placeholder="https://your-domain.com"
                />
              </label>
              <details className="advanced-options">
                <summary>
                  <SlidersHorizontal size={14} />
                  Additional checks
                </summary>
                <div className="advanced-body">
                  <label className="check-label">
                    <input name="paths" type="checkbox" />
                    Common exposed paths
                  </label>
                  <label className="check-label">
                    <input name="ports" type="checkbox" />
                    Common TCP ports
                  </label>
                  <label className="check-label">
                    <input name="reflected_input" type="checkbox" />
                    Reflected input in GET forms
                  </label>
                  <label>
                    Additional keywords
                    <input
                      name="keywords"
                      maxLength={300}
                      placeholder="Optional, comma-separated"
                    />
                  </label>
                </div>
              </details>
              <label className="check-label authorization">
                <input type="checkbox" name="authorized" required />I am
                authorized to check this target
              </label>
              <button className="button primary" disabled={busy}>
                {busy ? "Checking website…" : "Run website check"}
                <ArrowRight size={15} />
              </button>
            </form>
          ) : (
            <p className="inline-note">
              An administrator can start website checks.
            </p>
          )}
          <p className="footnote">
            Findings are observations to investigate. Approve each hostname below, including any hostname a site redirects to.
          </p>
          <details className="advanced-options" open={!scope?.effective_hostnames?.length}>
            <summary>Approved websites <span className="count">{scope?.effective_hostnames?.length || 0}</span></summary>
            <div className="advanced-body">
              <p className="muted text-small">Add sites you own or have permission to assess. Approval covers the exact hostname; subdomains are separate.</p>
              {scope?.effective_hostnames?.length ? <ul>{scope.effective_hostnames.map((host) => <li key={host} className="mono">{host}</li>)}</ul> : <p className="inline-note">Approve a website here before your first check.</p>}
              {canManage && <form key={scope?.hostnames?.join(",") || "empty"} onSubmit={(event) => {
                event.preventDefault();
                const fields = new FormData(event.currentTarget);
                run(async () => {
                  await api("/scans/scope", {method: "PUT", json: {hostnames: String(fields.get("hostnames") || "").split(/[\s,]+/).filter(Boolean), authorized: fields.has("scope_authorized")}});
                  await refresh();
                  notify("Approved websites updated.");
                });
              }}>
                <label>Website URLs or hostnames<textarea name="hostnames" rows={3} defaultValue={scope?.hostnames?.join("\n") || ""} placeholder="your-domain.com&#10;www.your-domain.com" maxLength={8000} /></label>
                <label className="check-label"><input name="scope_authorized" type="checkbox" required />I own or have permission to assess these sites</label>
                <button className="button secondary" disabled={busy || !scope}>Save approved websites</button>
              </form>}
            </div>
          </details>
        </section>
        <section className="panel">
          <div className="panel-heading">
            <h2>
              Saved checks <span className="count">{scans.length}</span>
            </h2>
          </div>
          {scans.length ? (
            <div className="history-list">
              {scans.map((scan) => (
                <button
                  className={current?.id === scan.id ? "selected" : ""}
                  key={scan.id}
                  onClick={() => setSelected(scan)}
                >
                  <strong>{scan.target}</strong>
                  <span>
                    #{scan.id} · {dateTime(scan.created_at)}
                  </span>
                  <Badge
                    tone={
                      scan.status === "completed_with_errors"
                        ? "warning"
                        : "neutral"
                    }
                  >
                    {label(scan.status)}
                  </Badge>
                </button>
              ))}
            </div>
          ) : (
            <div className="list-empty">No website checks yet.</div>
          )}
        </section>
      </div>
      <section className="panel assessment-result">
        {current ? (
          <>
            <div className="panel-heading">
              <div>
                <span className="eyebrow">Check #{current.id}</span>
                <h2>Website findings</h2>
                <p className="muted wrap text-small">{current.target}</p>
              </div>
              <Badge>{label(current.status)}</Badge>
            </div>
            <div className="finding-list">
              {current.findings.map((finding, index) => (
                <div className="finding" key={index}>
                  <Badge
                    tone={
                      finding.level === "error"
                        ? "danger"
                        : finding.level === "warn"
                          ? "warning"
                          : "neutral"
                    }
                  >
                    {finding.level === "warn"
                      ? "Review"
                      : finding.level === "error"
                        ? "Error"
                        : "Info"}
                  </Badge>
                  <p>{finding.message}</p>
                </div>
              ))}
            </div>
          </>
        ) : (
          <Empty title="Your report will appear here" icon={Globe}>
            Run a check or choose a saved report to inspect its findings.
          </Empty>
        )}
      </section>
    </div>
  );
}
export function FileChecksTab({
  checks,
  status,
  api,
  run,
  refresh,
  notify,
  busy,
}) {
  const [selected, setSelected] = useState(null),
    [file, setFile] = useState(null);
  const current = selected || checks[0];
  return (
    <div className="assessment-layout">
      <div className="assessment-input">
        <section className="panel padded">
          <div className="section-icon">
            <FileSearch size={21} />
          </div>
          <h2>Inspect a file</h2>
          <p className="muted">
            Check a test signature, review code patterns, and use ClamAV when it
            is installed.
          </p>
          <form
            onSubmit={(event) => {
              event.preventDefault();
              if (!file) return;
              run(async () => {
                const body = new FormData();
                body.append("file", file);
                const result = await api("/file-checks/run", {
                  method: "POST",
                  body,
                });
                setSelected(result);
                await refresh();
                notify(`File inspection #${result.id} saved.`);
              });
            }}
          >
            <label className="upload-zone">
              File to inspect
              <input
                type="file"
                required
                onChange={(event) => setFile(event.target.files[0])}
              />
              <span className="field-help">
                Up to {status?.max_upload_bytes ? `${status.max_upload_bytes / (1024 * 1024)} MB` : "the host limit"}. The temporary file is discarded after inspection.
              </span>
            </label>
            <button className="button primary" disabled={busy || !file}>
              {busy ? "Inspecting…" : "Run file inspection"}
              <ArrowRight size={15} />
            </button>
          </form>
          <div className="engine-status">
            <span>ClamAV engine</span>
            <Badge tone={status?.clamav_available ? "positive" : "neutral"}>
              {status?.clamav_available ? "Available" : "Not installed"}
            </Badge>
          </div>
          {!status?.clamav_available && (
            <p className="footnote">
              Only limited signature and pattern checks are available on this
              host. A result is never presented as a clean antivirus scan.
            </p>
          )}
        </section>
        <section className="panel">
          <div className="panel-heading">
            <h2>Recent inspections</h2>
          </div>
          {checks.length ? (
            <div className="history-list">
              {checks.map((check) => (
                <button
                  key={check.id}
                  className={current?.id === check.id ? "selected" : ""}
                  onClick={() => setSelected(check)}
                >
                  <strong>{check.filename}</strong>
                  <span>{dateTime(check.created_at)}</span>
                  <Badge
                    tone={
                      check.status === "detected"
                        ? "danger"
                        : check.status === "review"
                          ? "warning"
                          : "neutral"
                    }
                  >
                    {label(check.status)}
                  </Badge>
                </button>
              ))}
            </div>
          ) : (
            <div className="list-empty">No file inspections yet.</div>
          )}
        </section>
      </div>
      <section className="panel assessment-result">
        {current ? (
          <>
            <div className="panel-heading">
              <div>
                <span className="eyebrow">Inspection #{current.id}</span>
                <h2>{current.filename}</h2>
                <p className="muted text-small">
                  {number(current.bytes)} bytes · {dateTime(current.created_at)}
                </p>
              </div>
              <Badge
                tone={
                  current.status === "detected"
                    ? "danger"
                    : current.status === "review"
                      ? "warning"
                      : "neutral"
                }
              >
                {label(current.status)}
              </Badge>
            </div>
            <div className="finding-list">
              {current.checks.map((check) => (
                <div key={check.name} className="inspection-check">
                  <div className="section-toolbar">
                    <strong>{check.name}</strong>
                    <Badge
                      tone={
                        check.status === "detected"
                          ? "danger"
                          : check.status === "review"
                            ? "warning"
                            : "neutral"
                      }
                    >
                      {label(check.status)}
                    </Badge>
                  </div>
                  <p className="muted">{check.detail}</p>
                </div>
              ))}
            </div>
            <div className="report-footer">
              <span className="eyebrow">SHA-256</span>
              <code className="wrap">{current.sha256}</code>
              <p className="footnote">{current.note}</p>
            </div>
          </>
        ) : (
          <Empty title="Ready to inspect" icon={FileSearch}>
            Upload a file or select an earlier result. No uploaded file is
            executed.
          </Empty>
        )}
      </section>
    </div>
  );
}
export function AuditTab({ audit, filters, onFilters }) {
  const [draft, setDraft] = useState(filters);
  const update = (key, value) => setDraft((old) => ({ ...old, [key]: value }));
  return (
    <>
      <div className="section-toolbar">
        <p className="muted">
          Account changes, file operations, and investigation history.
        </p>
        <button
          className="button secondary"
          onClick={() => saveData(audit?.logs || [], "audit-entries.json")}
          disabled={!audit}
        >
          <Download size={15} />
          Export shown entries
        </button>
      </div>
      <div
        className={`audit-verification ${audit?.is_valid === false ? "invalid" : ""}`}
      >
        <ShieldCheck size={20} />
        <div>
          <strong>
            {!audit
              ? "Checking audit history…"
              : audit.is_valid
                ? "Stored audit chain verified"
                : `Chain mismatch at entry ${audit.tamper_index_id}`}
          </strong>
          <p>
            This verifies the stored hash chain. It is not an external signature
            or an immutable ledger.
          </p>
        </div>
      </div>
      <section className="panel">
        <form
          className="filter-bar audit-filters"
          onSubmit={(event) => {
            event.preventDefault();
            onFilters(draft);
          }}
        >
          <label>
            Action
            <input
              value={draft.action || ""}
              onChange={(event) => update("action", event.target.value)}
              placeholder="e.g. add_user"
            />
          </label>
          <label>
            Actor
            <input
              value={draft.admin_user || ""}
              onChange={(event) => update("admin_user", event.target.value)}
              placeholder="Username"
            />
          </label>
          <label>
            Target user
            <input
              value={draft.target_user || ""}
              onChange={(event) => update("target_user", event.target.value)}
              placeholder="Username"
            />
          </label>
          <label>
            Recorded date
            <input
              type="date"
              value={draft.date || ""}
              onChange={(event) => update("date", event.target.value)}
            />
          </label>
          <button className="button secondary">
            <Search size={15} />
            Apply
          </button>
          <button
            className="text-button"
            type="button"
            onClick={() => {
              setDraft({});
              onFilters({});
            }}
          >
            Reset
          </button>
        </form>
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Recorded</th>
                <th>Actor</th>
                <th>Action</th>
                <th>Target</th>
                <th>Details</th>
              </tr>
            </thead>
            <tbody>
              {audit?.logs.map((entry) => (
                <tr key={entry.id}>
                  <td className="muted nowrap">{dateTime(entry.timestamp)}</td>
                  <td>{entry.admin || "System"}</td>
                  <td>
                    <span className="action-name">
                      {entry.action.replaceAll("_", " ")}
                    </span>
                  </td>
                  <td>{entry.target_user || "—"}</td>
                  <td>
                    <details>
                      <summary className="text-button">View details</summary>
                      <pre className="audit-detail">{entry.details}</pre>
                    </details>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {audit && !audit.logs.length && (
            <Empty title="No matching audit entries" />
          )}
        </div>
        <div className="pagination">
          <span>
            Latest {audit?.logs.length ?? "—"} matching entries · maximum 500
          </span>
        </div>
      </section>
    </>
  );
}
