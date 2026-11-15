import React, { useCallback, useEffect, useRef, useState } from "react";
import {
  Activity,
  ArrowUpRight,
  ChevronDown,
  FileSearch,
  Globe,
  LayoutDashboard,
  Lock,
  LogOut,
  Menu,
  RefreshCw,
  Settings2,
  Shield,
  Users,
  X,
  Database,
  BarChart3,
} from "lucide-react";
import AuthForms from "./components/AuthForms";
import EncryptedFilesTab from "./components/EncryptedFilesTab";
import ActiveRulesTab from "./components/ActiveRulesTab";
import UsersTab, { AccountDialog } from "./components/UsersTab";
import ModelTab, { RecordInspector } from "./components/ModelTab";
import {
  OverviewTab,
  EventsTab,
  WebsiteTab,
  FileChecksTab,
  AuditTab,
} from "./components/WorkspaceTabs";
import { Brand, Dialog, saveData, FeedbackContext } from "./components/ui";

const pages = [
  {
    id: "overview",
    label: "Overview",
    title: "Workspace overview",
    description:
      "Recorded activity, current tools, and a place to start investigating.",
    icon: LayoutDashboard,
    group: "Workspace",
  },
  {
    id: "events",
    label: "Network events",
    title: "Network events",
    icon: Activity,
    group: "Workspace",
  },
  {
    id: "web",
    label: "Website checks",
    title: "Website checks",
    icon: Globe,
    group: "Workspace",
  },
  {
    id: "files",
    label: "Files",
    title: "File protection",
    icon: Lock,
    group: "Workspace",
  },
  {
    id: "scanner",
    label: "File scanner",
    title: "File inspection",
    icon: FileSearch,
    group: "Workspace",
  },
  {
    id: "model",
    label: "Model performance",
    title: "Model performance",
    icon: BarChart3,
    group: "Analysis",
  },
  {
    id: "users",
    label: "Users",
    title: "People & access",
    icon: Users,
    group: "Administration",
    admin: true,
  },
  {
    id: "rules",
    label: "Rules",
    title: "Detection rules",
    icon: Settings2,
    group: "Administration",
  },
  {
    id: "audit",
    label: "Audit history",
    title: "Audit history",
    icon: Database,
    group: "Administration",
    admin: true,
  },
];
const emptyData = () => ({
  overview: null,
  files: null,
  model: null,
  samples: [],
  events: null,
  scans: [],
  scanScope: null,
  fileChecks: [],
  scannerStatus: null,
  users: [],
  rules: [],
  audit: null,
});
const queryString = (object) =>
  new URLSearchParams(
    Object.entries(object).filter(([, value]) => value !== "" && value != null),
  ).toString();
function takeResetToken() {
  if (!location.hash.startsWith("#reset-password")) return "";
  const value =
    new URLSearchParams(location.hash.split("?")[1] || "").get("token") ||
    "invalid";
  history.replaceState(null, "", location.pathname + location.search);
  return value;
}
// Read and remove the fragment before rendering or loading account data.
const initialResetToken = takeResetToken();
export default function App() {
  const [resetToken, setResetToken] = useState(initialResetToken);
  const [token, setToken] = useState(
    () => sessionStorage.getItem("securestream-token") || "",
  );
  const [user, setUser] = useState(null),
    [tab, setTab] = useState(() =>
      pages.some((page) => page.id === location.hash.slice(1))
        ? location.hash.slice(1)
        : "overview",
    );
  const [data, setData] = useState(emptyData),
    [busy, setBusy] = useState(false),
    [loading, setLoading] = useState(false),
    [notice, setNotice] = useState(null),
    [connection, setConnection] = useState("Disconnected"),
    [runtime, setRuntime] = useState(null),
    [revision, setRevision] = useState(0);
  const [eventFilters, setEventFilters] = useState({ page: 1 }),
    [auditFilters, setAuditFilters] = useState({}),
    [mobileOpen, setMobileOpen] = useState(false),
    [profile, setProfile] = useState(false),
    [inspector, setInspector] = useState(null),
    [preview, setPreview] = useState(null);
  const inFlight = useRef(false);
  const eventQuery = queryString(eventFilters),
    auditQuery = queryString(auditFilters);
  const setSession = useCallback((value) => {
    if (value) sessionStorage.setItem("securestream-token", value);
    else sessionStorage.removeItem("securestream-token");
    setToken(value);
  }, []);
  const logout = useCallback(() => {
    setSession("");
    setUser(null);
    setData(emptyData());
    setInspector(null);
    setPreview(null);
    setProfile(false);
  }, [setSession]);
  const notify = useCallback(
    (message, tone = "success") => setNotice({ message, tone }),
    [],
  );
  const api = useCallback(
    async (path, options = {}) => {
      const { json, raw, ...rest } = options;
      const response = await fetch("/api" + path, {
        ...rest,
        body: json !== undefined ? JSON.stringify(json) : rest.body,
        headers: {
          ...(json !== undefined ? { "Content-Type": "application/json" } : {}),
          ...rest.headers,
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
      });
      if (!response.ok) {
        const body = await response.json().catch(() => ({}));
        const message =
          typeof body.detail === "string"
            ? body.detail
            : Array.isArray(body.detail)
              ? body.detail
                  .map(
                    (item) =>
                      `${item.loc.filter((value) => value !== "body").join(".")}: ${item.msg}`,
                  )
                  .join(" · ")
              : `Request failed (${response.status})`;
        if (
          response.status === 401 &&
          sessionStorage.getItem("securestream-token") === token
        )
          logout();
        const error = new Error(message);
        error.status = response.status;
        throw error;
      }
      return raw ? response : response.json();
    },
    [token, logout],
  );
  const run = useCallback(
    async (task) => {
      if (inFlight.current) return null;
      inFlight.current = true;
      setBusy(true);
      setNotice(null);
      try {
        return await task();
      } catch (error) {
        notify(error.message, "error");
        return null;
      } finally {
        inFlight.current = false;
        setBusy(false);
      }
    },
    [notify],
  );
  const go = useCallback((id) => {
    location.hash = id;
    setTab(id);
    setMobileOpen(false);
    setNotice(null);
  }, []);
  useEffect(() => {
    const handler = () => {
      if (location.hash.startsWith("#reset-password")) {
        setResetToken(takeResetToken());
        setNotice(null);
        return;
      }
      const id = location.hash.slice(1);
      setTab(pages.some((page) => page.id === id) ? id : "overview");
      setNotice(null);
    };
    addEventListener("hashchange", handler);
    return () => removeEventListener("hashchange", handler);
  }, []);
  useEffect(() => {
    if (!token) return;
    let cancelled = false;
    api("/health")
      .then((value) => {
        if (!cancelled) setRuntime(value);
      })
      .catch(() => {});
    api("/auth/me")
      .then((account) => {
        if (!cancelled) setUser(account);
      })
      .catch((error) => {
        if (!cancelled) notify(error.message, "error");
      });
    return () => {
      cancelled = true;
    };
  }, [token, api, notify]);
  useEffect(() => {
    if (
      user &&
      pages.find((page) => page.id === tab)?.admin &&
      user.role !== "admin"
    )
      go("overview");
  }, [tab, user, go]);
  const refresh = useCallback(async () => {
    if (!user) return;
    setLoading(true);
    try {
      if (tab === "overview") {
        const [overview, files, model] = await Promise.all([
          api("/workspace/overview"),
          api("/encryption/files"),
          api("/detector/status"),
        ]);
        setData((old) => ({ ...old, overview, files, model }));
      } else if (tab === "events") {
        const events = await api("/workspace/events?" + eventQuery);
        setData((old) => ({ ...old, events }));
      } else if (tab === "web") {
        const [scans, scanScope] = await Promise.all([
          api("/scans"),
          api("/scans/scope"),
        ]);
        setData((old) => ({ ...old, scans, scanScope }));
      } else if (tab === "files") {
        const files = await api("/encryption/files");
        setData((old) => ({ ...old, files }));
      } else if (tab === "scanner") {
        const [fileChecks, scannerStatus] = await Promise.all([
          api("/file-checks"),
          api("/file-checks/status"),
        ]);
        setData((old) => ({ ...old, fileChecks, scannerStatus }));
      } else if (tab === "model") {
        const model = await api("/detector/status");
        setData((old) => ({ ...old, model }));
      } else if (tab === "users" && user.role === "admin") {
        const users = await api("/auth/users");
        setData((old) => ({ ...old, users }));
      } else if (tab === "rules") {
        const rules = await api("/alerts/rules");
        setData((old) => ({ ...old, rules }));
      } else if (tab === "audit" && user.role === "admin") {
        setData((old) => ({ ...old, audit: null }));
        const audit = await api("/alerts/audit-logs?" + auditQuery);
        setData((old) => ({ ...old, audit }));
      }
    } finally {
      setLoading(false);
    }
  }, [api, user, tab, eventQuery, auditQuery]);
  useEffect(() => {
    refresh().catch((error) => notify(error.message, "error"));
  }, [refresh, revision, notify]);
  useEffect(() => {
    if (!token || !user || !runtime) return;
    if (runtime.event_updates === "polling") {
      setConnection("Synced every 15s");
      const sync = () => {
        if (!document.hidden) setRevision((old) => old + 1);
      };
      const interval = setInterval(sync, 15000);
      document.addEventListener("visibilitychange", sync);
      return () => {
        clearInterval(interval);
        document.removeEventListener("visibilitychange", sync);
      };
    }
    let stopped = false,
      socket,
      retry,
      heartbeat,
      update;
    const connect = () => {
      setConnection("Connecting");
      socket = new WebSocket(
        `${location.protocol === "https:" ? "wss" : "ws"}://${location.host}/api/ws/alerts`,
      );
      socket.onopen = () => {
        socket.send(JSON.stringify({ token }));
        heartbeat = setInterval(() => {
          if (socket.readyState === WebSocket.OPEN) socket.send("ping");
        }, 20000);
      };
      socket.onmessage = (event) => {
        try {
          const message = JSON.parse(event.data);
          if (message.type === "ready") setConnection("Connected");
          if (message.type === "threat_alert" && !update)
            update = setTimeout(() => {
              update = null;
              setRevision((old) => old + 1);
            }, 500);
        } catch {
          /* Ignore non-JSON heartbeat frames. */
        }
      };
      socket.onclose = (event) => {
        clearInterval(heartbeat);
        setConnection("Disconnected");
        if (!stopped) {
          if (event.code === 1008) api("/auth/me").catch(() => {});
          retry = setTimeout(connect, 3000);
        }
      };
      socket.onerror = () => socket.close();
    };
    connect();
    return () => {
      stopped = true;
      clearTimeout(retry);
      clearTimeout(update);
      clearInterval(heartbeat);
      socket?.close();
    };
  }, [token, user?.username, api, runtime]);
  async function openInspector() {
    const trigger = document.activeElement;
    await run(async () => {
      if (!data.samples.length) {
        const result = await api("/detector/samples");
        setData((old) => ({ ...old, samples: result.cases }));
      }
      setInspector({ trigger });
    });
  }
  async function fileOperation(kind, filename) {
    return run(async () => {
      const result = await api("/encryption/" + kind, {
        method: "POST",
        body: new URLSearchParams({ filename }),
      });
      notify(
        result.message + (result.sha256 ? ` · SHA-256 ${result.sha256}` : ""),
      );
      await refresh();
      return true;
    });
  }
  async function bulkFiles(kind, filenames) {
    return run(async () => {
      let completed = 0;
      const failures = [];
      for (const filename of filenames) {
        try {
          await api("/encryption/" + kind, {
            method: "POST",
            body: new URLSearchParams({ filename }),
          });
          completed++;
        } catch (error) {
          if (error.status === 401) throw error;
          failures.push(`${filename}: ${error.message}`);
        }
      }
      await refresh();
      notify(
        `${completed} file${completed === 1 ? "" : "s"} ${kind === "encrypt" ? "encrypted" : "restored"}.${failures.length ? " " + failures.length + " could not be processed. " + failures[0] : ""}`,
        failures.length ? "warning" : "success",
      );
      return failures.length === 0;
    });
  }
  async function download(path, filename) {
    return run(async () => {
      const response = await api(path, { raw: true });
      saveData(await response.blob(), filename);
    });
  }
  const current = pages.find((page) => page.id === tab) || pages[0];
  const visible = pages.filter((page) => !page.admin || user?.role === "admin");
  if (resetToken || !token || !user)
    return (
      <div className="login-layout">
        <aside className="login-story">
          <Brand />
          <div className="login-message">
            <span className="eyebrow">One workspace. A clearer view.</span>
            <h1>
              Know what’s happening.
              <br />
              <span>Keep control of what matters.</span>
            </h1>
            <p>
              Inspect network activity, check your websites, and protect the
              files you need to keep.
            </p>
            <div className="login-capabilities">
              <span>
                <Activity size={16} />
                Intrusion detection
              </span>
              <span>
                <Globe size={16} />
                Website checks
              </span>
              <span>
                <Lock size={16} />
                File protection
              </span>
            </div>
          </div>
          <div className="login-bottom">
            <span className="status-dot online" />
            SecureStream / IDS X Enc
          </div>
        </aside>
        <main className="login-main">
          <div className="login-card">
            <div className="login-mobile-brand">
              <Brand />
            </div>
            <AuthForms
              key={resetToken || "login"}
              api={api}
              run={run}
              busy={busy}
              notice={notice}
              notify={notify}
              resetToken={resetToken}
              onSession={setSession}
              onResetDone={() => {
                logout();
                setResetToken("");
              }}
            />
          </div>
        </main>
      </div>
    );
  return (
    <FeedbackContext.Provider value={notice}>
      <div className="workspace">
        <aside className="sidebar">
          <div className="sidebar-top">
            <Brand />
            <button
              className="icon-button mobile-menu-button"
              aria-label={mobileOpen ? "Close navigation" : "Open navigation"}
              aria-expanded={mobileOpen}
              aria-controls="workspace-navigation"
              onClick={() => setMobileOpen(!mobileOpen)}
            >
              {mobileOpen ? <X size={20} /> : <Menu size={20} />}
            </button>
          </div>
          <div
            className={`sidebar-body ${mobileOpen ? "open" : ""}`}
            id="workspace-navigation"
          >
            <nav aria-label="Main navigation">
              {["Workspace", "Analysis", "Administration"].map((group) => (
                <div className="nav-group" key={group}>
                  <span className="nav-label">{group}</span>
                  {visible
                    .filter((page) => page.group === group)
                    .map(({ id, label, icon: Icon }) => (
                      <button
                        key={id}
                        className={`nav-item ${tab === id ? "active" : ""}`}
                        aria-current={tab === id ? "page" : undefined}
                        onClick={() => go(id)}
                      >
                        <Icon size={17} strokeWidth={1.7} />
                        <span>{label}</span>
                        {id === "users" && (
                          <span className="nav-admin" aria-hidden="true">
                            Admin
                          </span>
                        )}
                      </button>
                    ))}
                </div>
              ))}
            </nav>
            <div className="sidebar-bottom">
              <div className="workspace-note">
                <Shield size={17} />
                <div>
                  <strong>One security workspace</strong>
                  <span>IDS, checks & file protection</span>
                </div>
              </div>
              <button className="signout" onClick={logout}>
                <LogOut size={16} />
                Sign out
              </button>
            </div>
          </div>
        </aside>
        <div className="workspace-main">
          <header className="topbar">
            <div className="breadcrumbs">
              <span>{user.workspace_name || "Workspace"}</span>
              <span className="breadcrumb-divider">/</span>
              <strong>{current.label}</strong>
            </div>
            <div className="topbar-actions">
              <span
                className="stream-status"
                title="Workspace updates; live capture requires a separately running host sensor."
              >
                <span
                  className={`status-dot ${connection === "Connected" || connection === "Synced every 15s" ? "online" : ""}`}
                />
                <span>
                  Updates <strong>{connection}</strong>
                </span>
              </span>
              <span className="topbar-divider" />
              <button
                className="account-button"
                aria-label="Account settings"
                onClick={() => setProfile(true)}
              >
                <span className="avatar">
                  {user.name.slice(0, 2).toUpperCase()}
                </span>
                <span className="account-name">
                  {user.name}
                  <ChevronDown size={13} />
                </span>
              </button>
            </div>
          </header>
          <main className="page-content" aria-busy={loading}>
            <div className="page-heading">
              <div>
                <span className="eyebrow">{current.group}</span>
                <h1>{current.title}</h1>
                {current.description && (
                  <p className="muted">{current.description}</p>
                )}
              </div>
              <button
                className="button secondary refresh-button"
                disabled={busy || loading}
                onClick={() => run(refresh)}
              >
                <RefreshCw size={15} className={loading ? "spinning" : ""} />
                <span>Refresh</span>
              </button>
            </div>
            {notice && (
              <div
                className={`notice ${notice.tone}`}
                role={notice.tone === "error" ? "alert" : "status"}
              >
                <span>{notice.message}</span>
                <button
                  className="icon-button"
                  aria-label="Dismiss message"
                  onClick={() => setNotice(null)}
                >
                  <X size={15} />
                </button>
              </div>
            )}
            {tab === "overview" && (
              <OverviewTab
                overview={data.overview}
                files={data.files}
                model={data.model}
                onGo={go}
                onInspect={openInspector}
              />
            )}
            {tab === "events" && (
              <EventsTab
                events={data.events}
                filters={eventFilters}
                onFilters={setEventFilters}
                onInspect={openInspector}
                busy={busy}
                onExport={(format) =>
                  download(
                    "/workspace/events/export?" +
                      queryString({ ...eventFilters, page: undefined, format }),
                    `security-events.${format}`,
                  )
                }
              />
            )}
            {tab === "web" && (
              <WebsiteTab
                scope={data.scanScope}
                scans={data.scans}
                api={api}
                run={run}
                refresh={refresh}
                notify={notify}
                busy={busy}
                canManage={user.role === "admin"}
              />
            )}
            {tab === "scanner" && (
              <FileChecksTab
                checks={data.fileChecks}
                status={data.scannerStatus}
                api={api}
                run={run}
                refresh={refresh}
                notify={notify}
                busy={busy}
              />
            )}
            {tab === "files" && (
              <EncryptedFilesTab
                maxUploadBytes={
                  data.files?.max_upload_bytes || runtime?.max_upload_bytes
                }
                sensitiveFiles={data.files?.sensitive_files || []}
                encryptedFiles={data.files?.encrypted_files || []}
                busy={busy}
                handleUpload={(event) => {
                  const file = event.target.files?.[0];
                  if (file)
                    run(async () => {
                      const body = new FormData();
                      body.append("file", file);
                      const result = await api("/encryption/upload", {
                        method: "POST",
                        body,
                      });
                      notify(
                        `Uploaded ${file.name} · SHA-256 ${result.sha256}`,
                      );
                      await refresh();
                    });
                }}
                handleEncrypt={(filename) => fileOperation("encrypt", filename)}
                handleDecrypt={(filename) => fileOperation("decrypt", filename)}
                handleBulk={bulkFiles}
                handleDownload={(type, filename) =>
                  download(
                    "/encryption/download?" + queryString({ type, filename }),
                    filename,
                  )
                }
                handlePreview={(type, filename, trigger) =>
                  run(async () =>
                    setPreview({
                      filename,
                      trigger,
                      ...(await api(
                        "/encryption/preview?" +
                          queryString({ type, filename }),
                      )),
                    }),
                  )
                }
              />
            )}
            {tab === "model" && (
              <ModelTab model={data.model} onInspect={openInspector} />
            )}
            {tab === "users" && user.role === "admin" && (
              <UsersTab
                users={data.users}
                currentUser={user}
                api={api}
                run={run}
                refresh={refresh}
                notify={notify}
                busy={busy}
              />
            )}
            {tab === "rules" && (
              <ActiveRulesTab
                rules={data.rules}
                canManage={user.role === "admin"}
                api={api}
                run={run}
                refresh={refresh}
                notify={notify}
                busy={busy}
              />
            )}
            {tab === "audit" && user.role === "admin" && (
              <AuditTab
                audit={data.audit}
                filters={auditFilters}
                onFilters={setAuditFilters}
              />
            )}
            <footer className="page-footer">
              <span>SecureStream</span>
              <span>IDS · Website checks · File protection</span>
            </footer>
          </main>
        </div>
        {profile && (
          <AccountDialog
            user={user}
            api={api}
            run={run}
            busy={busy}
            notify={notify}
            onToken={setSession}
            onClose={() => setProfile(false)}
          />
        )}
        {inspector && (
          <RecordInspector
            samples={data.samples}
            api={api}
            run={run}
            busy={busy}
            notify={notify}
            onClose={() => setInspector(null)}
            onPrediction={refresh}
            returnFocus={inspector.trigger}
          />
        )}
        {preview && (
          <Dialog
            title={"File preview: " + preview.filename}
            returnFocus={preview.trigger}
            onClose={() => setPreview(null)}
            wide
          >
            <pre className="file-preview">{preview.content}</pre>
            <p className="footnote">
              Preview is limited to the first portion of the file. Encrypted
              content is shown as hexadecimal bytes.
            </p>
          </Dialog>
        )}
      </div>
    </FeedbackContext.Provider>
  );
}
