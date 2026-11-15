import React, {
  useEffect,
  useId,
  useRef,
  createContext,
  useContext,
} from "react";
import { X, Shield } from "lucide-react";

export const FeedbackContext = createContext(null);
export const dateTime = (value) =>
  value
    ? new Date(value).toLocaleString(undefined, {
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit",
      })
    : "—";
export const number = (value) =>
  typeof value === "number" ? value.toLocaleString() : "—";
export const percent = (value) =>
  typeof value === "number" ? `${(value * 100).toFixed(1)}%` : "—";
export const label = (value) =>
  ({
    "model-replay": "Model replay",
    "sensor-simulation": "Sensor simulation",
    sensor: "Live sensor",
    "file-scan": "File check",
    no_findings: "No findings",
    no_match: "No match",
    limited: "Limited inspection",
    review: "Needs review",
    detected: "Detected",
    completed: "Completed",
    completed_with_errors: "Completed with errors",
    unavailable: "Unavailable",
    error: "Error",
    user: "Member",
    admin: "Administrator",
  })[value] || value;
export function Brand() {
  return (
    <div className="brand">
      <span className="brand-mark">
        <Shield size={20} strokeWidth={1.6} />
      </span>
      <span>
        SecureStream<span className="brand-sub">Security workspace</span>
      </span>
    </div>
  );
}
export function Badge({ children, tone = "neutral" }) {
  return <span className={`badge ${tone}`}>{children}</span>;
}
export function Empty({ title, children, icon: Icon = Shield }) {
  return (
    <div className="empty-state">
      <span className="empty-icon">
        <Icon size={21} strokeWidth={1.4} />
      </span>
      <h3>{title}</h3>
      {children && <p>{children}</p>}
    </div>
  );
}
export function Dialog({
  title,
  children,
  onClose,
  wide = false,
  returnFocus,
}) {
  const ref = useRef(null),
    heading = useId();
  const feedback = useContext(FeedbackContext),
    initialFeedback = useRef(feedback);
  useEffect(() => {
    const previous = returnFocus || document.activeElement;
    const el = ref.current;
    el.showModal();
    return () => {
      el.close();
      requestAnimationFrame(() => previous?.focus());
    };
  }, [returnFocus]);
  return (
    <dialog
      ref={ref}
      aria-labelledby={heading}
      className={`dialog ${wide ? "dialog-wide" : ""}`}
      onCancel={(event) => {
        event.preventDefault();
        onClose();
      }}
      onClick={(event) => {
        if (event.target === ref.current) onClose();
      }}
    >
      <div className="dialog-heading">
        <h2 id={heading}>{title}</h2>
        <button
          className="icon-button"
          aria-label="Close dialog"
          onClick={onClose}
        >
          <X size={18} />
        </button>
      </div>
      {feedback?.tone === "error" && feedback !== initialFeedback.current && (
        <div className="notice error" role="alert">
          {feedback.message}
        </div>
      )}
      {children}
    </dialog>
  );
}
export function EventTable({ events = [] }) {
  return (
    <div className="table-scroll">
      <table>
        <thead>
          <tr>
            <th>Recorded</th>
            <th>Prediction / event</th>
            <th>Origin</th>
            <th>Source</th>
            <th>Destination</th>
          </tr>
        </thead>
        <tbody>
          {events.map((event) => (
            <tr key={event.id}>
              <td className="nowrap muted">{dateTime(event.timestamp)}</td>
              <td>
                <Badge
                  tone={event.alert_type === "Normal" ? "positive" : "warning"}
                >
                  {event.alert_type}
                </Badge>
              </td>
              <td>
                <span
                  className={`origin-dot ${event.origin === "sensor" ? "live" : ""}`}
                />
                {label(event.origin)}
              </td>
              <td className="mono">{event.source_ip}</td>
              <td className="mono">{event.destination_ip}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {!events.length && (
        <Empty title="No matching events">
          Events from your sensor and model replays will appear here.
        </Empty>
      )}
    </div>
  );
}
export function saveData(content, filename, type = "application/json") {
  const url = URL.createObjectURL(
    content instanceof Blob
      ? content
      : new Blob(
          [
            typeof content === "string"
              ? content
              : JSON.stringify(content, null, 2),
          ],
          { type },
        ),
  );
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
