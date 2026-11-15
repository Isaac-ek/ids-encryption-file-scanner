import React, { useCallback, useEffect, useState } from "react";
import {
  Activity,
  Globe,
  Lock,
  Database,
  LogOut,
  RefreshCw,
  Shield,
  Settings2,
} from "lucide-react";
import EncryptedFilesTab from "./components/EncryptedFilesTab";
import ActiveRulesTab from "./components/ActiveRulesTab";
import PreviewModal from "./components/PreviewModal";

const sections = [
  { id: "events", label: "Events", Icon: Activity },
  { id: "web", label: "Website checks", Icon: Globe },
  { id: "files", label: "Files", Icon: Lock },
  { id: "audit", label: "Audit", Icon: Database },
];
export default function App() {
  const [token, setToken] = useState(
    () => sessionStorage.getItem("securestream-token") || "",
  );
  const [user, setUser] = useState(null);
  const [tab, setTab] = useState("events");
  const [data, setData] = useState({
    events: [],
    rules: [],
    sensitive_files: [],
    encrypted_files: [],
    scans: [],
    model: null,
    audit: null,
  });
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  const [connection, setConnection] = useState("Disconnected");
  const [preview, setPreview] = useState(null);
  const [features, setFeatures] = useState("");
  const [scanResult, setScanResult] = useState(null);
  const logout = useCallback(() => {
    sessionStorage.removeItem("securestream-token");
    setToken("");
    setUser(null);
    setData({
      events: [],
      rules: [],
      sensitive_files: [],
      encrypted_files: [],
      scans: [],
      model: null,
      audit: null,
    });
    setFeatures("");
    setScanResult(null);
  }, []);
  const request = useCallback(
    async (path, options = {}) => {
      const response = await fetch("/api" + path, {
        ...options,
        headers: {
          ...options.headers,
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
      });
      if (response.status === 401) logout();
      const body = await response.json().catch(() => ({}));
      if (!response.ok)
        throw new Error(
          typeof body.detail === "string"
            ? body.detail
            : `Request failed (${response.status})`,
        );
      return body;
    },
    [token, logout],
  );
  const refresh = useCallback(async () => {
    if (!user) return;
    if (tab === "events") {
      const [events, model] = await Promise.all([
        request("/alerts/threat-alerts?per_page=50"),
        request("/detector/status"),
      ]);
      setData((d) => ({ ...d, events, model }));
    } else if (tab === "files") {
      const files = await request("/encryption/files");
      setData((d) => ({ ...d, ...files }));
    } else if (tab === "web") {
      const scans = await request("/scans");
      setData((d) => ({ ...d, scans }));
    } else if (tab === "audit") {
      setData((d) => ({ ...d, audit: null }));
      const audit = await request("/alerts/audit-logs");
      setData((d) => ({ ...d, audit }));
    } else if (tab === "rules") {
      const rules = await request("/alerts/rules");
      setData((d) => ({ ...d, rules }));
    }
  }, [user, tab, request]);
  useEffect(() => {
    if (token)
      request("/auth/me")
        .then(setUser)
        .catch((e) => setError(e.message));
  }, [token, request]);
  useEffect(() => {
    refresh().catch((e) => setError(e.message));
  }, [refresh]);
  useEffect(() => {
    if (!token || !user) return;
    let stopped = false,
      socket,
      timer,
      ping;
    const connect = () => {
      setConnection("Connecting");
      socket = new WebSocket(
        `${location.protocol === "https:" ? "wss" : "ws"}://${location.host}/api/ws/alerts`,
      );
      socket.onopen = () => {
        socket.send(JSON.stringify({ token }));
        ping = setInterval(() => {
          if (socket.readyState === WebSocket.OPEN) socket.send("ping");
        }, 20000);
      };
      socket.onmessage = (event) => {
        try {
          const payload = JSON.parse(event.data);
          if (payload.type === "ready") setConnection("Connected");
          if (payload.type === "threat_alert")
            setData((d) => ({
              ...d,
              events: [payload.data, ...d.events].slice(0, 50),
            }));
        } catch {
          /* malformed frames do not become events */
        }
      };
      socket.onclose = () => {
        clearInterval(ping);
        setConnection("Disconnected");
        if (!stopped) timer = setTimeout(connect, 3000);
      };
      socket.onerror = () => socket.close();
    };
    connect();
    return () => {
      stopped = true;
      clearTimeout(timer);
      clearInterval(ping);
      socket?.close();
    };
  }, [token, user]);
  async function action(task) {
    setBusy(true);
    setError("");
    setMessage("");
    try {
      await task();
      return true;
    } catch (e) {
      setError(e.message);
      return false;
    } finally {
      setBusy(false);
    }
  }
  async function fileOperation(kind, filename) {
    await action(async () => {
      const result = await request("/encryption/" + kind, {
        method: "POST",
        body: new URLSearchParams({ filename }),
      });
      setMessage(
        result.message + (result.sha256 ? ` · SHA-256 ${result.sha256}` : ""),
      );
      await refresh();
    });
  }
  if (!token || !user)
    return (
      <div className="auth-page">
        <main className="auth-card">
          <Shield size={30} />
          <p className="eyebrow">Security workspace</p>
          <h1>SecureStream</h1>
          <p className="muted">
            Intrusion detection, website checks, and file protection.
          </p>
          {error && (
            <p role="alert" className="notice error">
              {error}
            </p>
          )}
          <form
            onSubmit={(event) => {
              event.preventDefault();
              const form = new FormData(event.currentTarget);
              action(async () => {
                const result = await request("/auth/login", {
                  method: "POST",
                  body: new URLSearchParams({
                    username: form.get("username"),
                    password: form.get("password"),
                  }),
                });
                sessionStorage.setItem(
                  "securestream-token",
                  result.access_token,
                );
                setToken(result.access_token);
              });
            }}
          >
            <label>
              Username
              <input name="username" autoComplete="username" required />
            </label>
            <label>
              Password
              <input
                name="password"
                type="password"
                autoComplete="current-password"
                required
              />
            </label>
            <button disabled={busy} className="btn btn-primary">
              {busy ? "Signing in…" : "Sign in"}
            </button>
          </form>
          <p className="muted small">
            Use an operator account created by your administrator.
          </p>
        </main>
      </div>
    );
  return (
    <div className="app-container">
      <aside className="sidebar">
        <div className="brand-section">
          <Shield size={25} />
          <span className="brand-name">SecureStream</span>
        </div>
        <p className="sidebar-caption">Security workspace</p>
        <nav aria-label="Main navigation" className="nav-links">
          {sections
            .filter((s) => s.id !== "audit" || user.role === "admin")
            .map(({ id, label, Icon }) => (
              <button
                key={id}
                className={`nav-item ${tab === id ? "active" : ""}`}
                aria-current={tab === id ? "page" : undefined}
                onClick={() => {
                  setTab(id);
                  setError("");
                  setMessage("");
                }}
              >
                <Icon size={18} />
                {label}
              </button>
            ))}
        </nav>
        <div className="secondary-navigation">
          <button
            className={`nav-item ${tab === "rules" ? "active" : ""}`}
            onClick={() => setTab("rules")}
          >
            <Settings2 size={17} />
            Saved rules
          </button>
        </div>
        <div className="user-profile-section">
          <div className="user-info">
            <span className="user-name">{user.name}</span>
            <span className="user-role">{user.role}</span>
          </div>
          <button aria-label="Sign out" className="logout-btn" onClick={logout}>
            <LogOut size={18} />
          </button>
        </div>
      </aside>
      <main className="main-content">
        <header className="page-header">
          <div>
            <p className="eyebrow">
              SecureStream /{" "}
              {sections.find((s) => s.id === tab)?.label || "Saved rules"}
            </p>
            <h1>
              {tab === "events"
                ? "Intrusion events"
                : tab === "web"
                  ? "Website checks"
                  : tab === "files"
                    ? "File protection"
                    : tab === "audit"
                      ? "Audit history"
                      : "Saved detection rules"}
            </h1>
          </div>
          <button
            disabled={busy}
            className="btn btn-secondary"
            onClick={() => action(refresh)}
          >
            <RefreshCw size={15} />
            Refresh
          </button>
        </header>
        {error && (
          <p role="alert" className="notice error">
            {error}
          </p>
        )}
        {message && (
          <p role="status" className="notice">
            {message}
          </p>
        )}
        <fieldset disabled={busy} className="workspace-controls">
          {tab === "events" && (
            <>
              <section className="overview-strip">
                <div>
                  <span className="muted small">Stored events shown</span>
                  <strong>{data.events.length}</strong>
                </div>
                <div>
                  <span className="muted small">Trained model</span>
                  <strong>
                    {data.model?.available
                      ? data.model.model_type
                      : "Unavailable"}
                  </strong>
                </div>
                <div>
                  <span className="muted small">Alert stream</span>
                  <strong>{connection}</strong>
                </div>
              </section>
              <p className="context-note">
                Stream status shows the API connection. Live packet capture
                requires the separately configured IDS sensor. Replayed records
                are labelled below.
              </p>
              <div className="event-layout">
                <section className="card">
                  <div className="section-heading">
                    <h2>Recent events</h2>
                    <span className="muted small">
                      Latest 50 · persisted history
                    </span>
                  </div>
                  <div className="table-container">
                    <table>
                      <thead>
                        <tr>
                          <th>Time</th>
                          <th>Result</th>
                          <th>Origin</th>
                          <th>Source → destination</th>
                        </tr>
                      </thead>
                      <tbody>
                        {data.events.length ? (
                          data.events.map((e) => (
                            <tr key={e.id}>
                              <td className="small">
                                {new Date(e.timestamp).toLocaleString()}
                              </td>
                              <td>
                                <span
                                  className={`badge ${e.alert_type === "Normal" ? "badge-success" : "badge-warning"}`}
                                >
                                  {e.alert_type}
                                </span>
                              </td>
                              <td className="small">{e.origin || "sensor"}</td>
                              <td className="small">
                                {e.source_ip} → {e.destination_ip}
                              </td>
                            </tr>
                          ))
                        ) : (
                          <tr>
                            <td colSpan="4">
                              No events received. This does not establish that
                              the network is safe.
                            </td>
                          </tr>
                        )}
                      </tbody>
                    </table>
                  </div>
                </section>
                <section className="card">
                  <h2>Inspect a connection</h2>
                  <p className="muted small">
                    Run supplied NSL-KDD features through the saved model and
                    scaler. This does not generate network traffic or encrypt
                    files.
                  </p>
                  <button
                    className="btn btn-secondary"
                    onClick={() =>
                      action(async () => {
                        const sample = await request("/detector/sample");
                        setFeatures(JSON.stringify(sample.features, null, 2));
                      })
                    }
                  >
                    Load sample record
                  </button>
                  <form
                    onSubmit={(event) => {
                      event.preventDefault();
                      action(async () => {
                        const result = await request("/detector/predict", {
                          method: "POST",
                          headers: { "Content-Type": "application/json" },
                          body: JSON.stringify({
                            features: JSON.parse(features),
                          }),
                        });
                        setMessage(
                          `Model result: ${result.label} · ${result.model_type} · saved event #${result.event_id}`,
                        );
                        await refresh();
                      });
                    }}
                  >
                    <label>
                      Connection features (JSON)
                      <textarea
                        value={features}
                        onChange={(e) => setFeatures(e.target.value)}
                        rows={9}
                        required
                        spellCheck="false"
                      />
                    </label>
                    <button className="btn btn-primary">
                      {busy ? "Running…" : "Run model prediction"}
                    </button>
                  </form>
                  {data.model?.available && (
                    <details className="model-details">
                      <summary>Model bundle & evaluation</summary>
                      <p className="small muted">
                        {data.model.features} input features · artifact SHA-256
                      </p>
                      <code className="small break-word">
                        {data.model.artifact_sha256}
                      </code>
                      {data.model.evaluation ? (
                        <>
                          <p className="small muted">
                            Offline held-out dataset evaluation; not
                            live-network accuracy.
                          </p>
                          <pre>
                            {JSON.stringify(
                              data.model.evaluation.metrics,
                              null,
                              2,
                            )}
                          </pre>
                        </>
                      ) : (
                        <p className="small muted">
                          No matching evaluation report published for this
                          artifact.
                        </p>
                      )}
                    </details>
                  )}
                </section>
              </div>
            </>
          )}
          {tab === "web" && (
            <>
              <div className="web-layout">
                <section className="card">
                  <h2>Check an authorized website</h2>
                  <p className="muted small">
                    Only hostnames configured by your administrator can be
                    scanned. Findings are checks to investigate, not proof of
                    exploitability.
                  </p>
                  {user.role === "admin" ? (
                    <form
                      onSubmit={(event) => {
                        event.preventDefault();
                        const form = new FormData(event.currentTarget);
                        action(async () => {
                          const result = await request("/scans/run", {
                            method: "POST",
                            headers: { "Content-Type": "application/json" },
                            body: JSON.stringify({
                              url: form.get("url"),
                              authorized: form.has("authorized"),
                              ports: form.has("ports"),
                              paths: form.has("paths"),
                              reflected_input: form.has("reflected_input"),
                              keywords: form.get("keywords") || "",
                            }),
                          });
                          setScanResult(result);
                          setMessage(
                            `Website check #${result.id} saved · ${result.status.replaceAll("_", " ")}`,
                          );
                          await refresh();
                        });
                      }}
                    >
                      <label>
                        Target URL
                        <input
                          name="url"
                          type="url"
                          placeholder="https://your-authorized-domain.com"
                          required
                        />
                      </label>
                      <label>
                        Additional keywords
                        <input
                          name="keywords"
                          placeholder="Optional, comma-separated"
                          maxLength={300}
                        />
                      </label>
                      <div className="check-list">
                        <label>
                          <input type="checkbox" name="paths" />
                          Check common paths
                        </label>
                        <label>
                          <input type="checkbox" name="ports" />
                          Check common TCP ports
                        </label>
                        <label>
                          <input type="checkbox" name="reflected_input" />
                          Check reflected input in GET forms
                        </label>
                        <label>
                          <input type="checkbox" name="authorized" required />I
                          am authorized to check this target
                        </label>
                      </div>
                      <button className="btn btn-primary">
                        {busy ? "Checking website…" : "Run website check"}
                      </button>
                    </form>
                  ) : (
                    <p>Only administrators can start website checks.</p>
                  )}
                  <p className="context-note">
                    Includes headers, TLS for HTTPS, CORS, redirects, mixed
                    content, and keyword checks. Requests are bounded and
                    redirects remain within configured scan scope.
                  </p>
                </section>
                <section className="card">
                  <h2>Saved checks</h2>
                  <div className="scan-history">
                    {data.scans.length ? (
                      data.scans.map((run) => (
                        <button
                          key={run.id}
                          className={`scan-history-item ${scanResult?.id === run.id ? "selected" : ""}`}
                          onClick={() => setScanResult(run)}
                        >
                          <strong>{run.target}</strong>
                          <span>
                            #{run.id} ·{" "}
                            {new Date(run.created_at).toLocaleString()} ·{" "}
                            {run.status.replaceAll("_", " ")}
                          </span>
                        </button>
                      ))
                    ) : (
                      <p className="muted">No saved website checks yet.</p>
                    )}
                  </div>
                </section>
              </div>
              {scanResult && (
                <section className="card scan-findings">
                  <div className="section-heading">
                    <h2>Results · check #{scanResult.id}</h2>
                    <span className="muted small">{scanResult.target}</span>
                  </div>
                  {scanResult.findings.map((finding, index) => (
                    <div key={index} className={`finding ${finding.level}`}>
                      <span className="badge">{finding.level}</span>
                      <p>{finding.message}</p>
                    </div>
                  ))}
                </section>
              )}
            </>
          )}
          {tab === "files" && (
            <>
              <p className="context-note">
                Upload a sample file, encrypt it, then restore it. Encryption
                removes the plaintext only after saving the encrypted copy.
                Restoring keeps the encrypted backup. Maximum upload: 8 MB.
              </p>
              <EncryptedFilesTab
                sensitiveFiles={data.sensitive_files}
                encryptedFiles={data.encrypted_files}
                handleUpload={(event) => {
                  const file = event.target.files?.[0];
                  if (file)
                    action(async () => {
                      const body = new FormData();
                      body.append("file", file);
                      const result = await request("/encryption/upload", {
                        method: "POST",
                        body,
                      });
                      setMessage(
                        `Uploaded ${file.name} · SHA-256 ${result.sha256}`,
                      );
                      await refresh();
                    });
                }}
                handleEncrypt={(filename) => fileOperation("encrypt", filename)}
                handleDecrypt={(filename) => fileOperation("decrypt", filename)}
                handlePreview={(type, filename, trigger) =>
                  action(async () =>
                    setPreview({
                      filename,
                      trigger,
                      ...(await request(
                        `/encryption/preview?type=${type}&filename=${encodeURIComponent(filename)}`,
                      )),
                    }),
                  )
                }
              />
            </>
          )}
          {tab === "audit" && (
            <section className="card">
              <h2>Audit chain verification</h2>
              <p
                className={`notice ${data.audit?.is_valid === false ? "error" : ""}`}
              >
                {data.audit === null
                  ? "Not verified yet"
                  : data.audit.is_valid
                    ? "Stored audit chain verified"
                    : "Audit chain mismatch at entry " +
                      data.audit.tamper_index_id}
              </p>
              <p className="muted small">
                This checks the stored hash chain. It is not an external
                signature or a guarantee against a database administrator
                rewriting the full chain.
              </p>
              <div className="table-container">
                <table>
                  <thead>
                    <tr>
                      <th>Time</th>
                      <th>Actor</th>
                      <th>Action</th>
                      <th>Details</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.audit?.logs?.map((log) => (
                      <tr key={log.id}>
                        <td className="small">{log.timestamp}</td>
                        <td>{log.admin || "System"}</td>
                        <td>{log.action}</td>
                        <td className="small break-word">{log.details}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
          )}
          {tab === "rules" && (
            <>
              <p className="context-note">
                Saved rule configuration. These records do not modify your
                operating-system firewall or automatically retrain the model.
              </p>
              <ActiveRulesTab
                rules={data.rules}
                canManage={user.role === "admin"}
                handleAddRule={(rule) =>
                  action(async () => {
                    await request("/alerts/rules", {
                      method: "POST",
                      headers: { "Content-Type": "application/json" },
                      body: JSON.stringify({
                        ...rule,
                        threshold: rule.threshold
                          ? Number(rule.threshold)
                          : null,
                        enabled: true,
                      }),
                    });
                    await refresh();
                  })
                }
                handleDeleteRule={(id) =>
                  action(async () => {
                    await request("/alerts/rules/" + id, { method: "DELETE" });
                    await refresh();
                  })
                }
              />
            </>
          )}
        </fieldset>
        <PreviewModal
          showPreviewModal={!!preview}
          setShowPreviewModal={(open) => {
            if (!open) setPreview(null);
          }}
          previewContent={preview}
          returnFocus={preview?.trigger}
        />
      </main>
    </div>
  );
}
