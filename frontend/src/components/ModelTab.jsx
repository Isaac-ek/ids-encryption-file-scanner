import React, { useState } from "react";
import { FlaskConical, ArrowUpRight, Check, FileJson } from "lucide-react";
import { Badge, Dialog, Empty, number, percent } from "./ui";
export function RecordInspector({
  samples,
  api,
  run,
  busy,
  onClose,
  onPrediction,
  notify,
  returnFocus,
}) {
  const [selected, setSelected] = useState(samples[0]?.id || ""),
    [features, setFeatures] = useState(""),
    [result, setResult] = useState(null);
  const sample = samples.find((item) => item.id === selected);
  return (
    <Dialog
      title="Inspect a connection record"
      onClose={onClose}
      returnFocus={returnFocus}
      wide
    >
      <div className="inspector-intro">
        <Badge>Model replay</Badge>
        <p className="muted">
          Run public sample features through the saved model. The dataset label
          and the model prediction are shown separately.
        </p>
      </div>
      <form
        onSubmit={(event) => {
          event.preventDefault();
          run(async () => {
            const prediction = await api("/detector/predict", {
              method: "POST",
              json: { features: JSON.parse(features) },
            });
            setResult(prediction);
            notify(
              `Model result: ${prediction.label} · saved event #${prediction.event_id}`,
            );
            await onPrediction();
          });
        }}
      >
        <div className="sample-controls">
          <label>
            Sample dataset label
            <select
              value={selected}
              onChange={(event) => {
                setSelected(event.target.value);
                setResult(null);
              }}
            >
              {samples.map((item) => (
                <option key={item.id} value={item.id}>
                  {item.label}
                </option>
              ))}
            </select>
          </label>
          <button
            type="button"
            className="button secondary"
            disabled={!sample}
            onClick={() => {
              setFeatures(JSON.stringify(sample.features, null, 2));
              setResult(null);
            }}
          >
            <FileJson size={15} />
            Load sample record
          </button>
        </div>
        <label>
          Connection features (JSON)
          <textarea
            className="code-input"
            value={features}
            onChange={(event) => {
              setFeatures(event.target.value);
              setResult(null);
            }}
            rows={11}
            required
            spellCheck={false}
          />
        </label>
        {result && (
          <div className="prediction-result">
            <div>
              <span className="eyebrow">Model prediction</span>
              <strong>{result.label}</strong>
            </div>
            <div>
              <span className="eyebrow">Saved as</span>
              <strong>Event #{result.event_id}</strong>
            </div>
            <span className="muted text-small">
              {result.model_type} · {result.feature_count} features
            </span>
          </div>
        )}
        <div className="dialog-actions">
          <button type="button" className="button secondary" onClick={onClose}>
            Close
          </button>
          <button className="button primary" disabled={busy}>
            {busy ? "Running…" : "Run model prediction"}
            <ArrowUpRight size={15} />
          </button>
        </div>
      </form>
      <p className="footnote">
        This predicts supplied features; it does not capture packets, generate
        an attack, or encrypt files.
      </p>
    </Dialog>
  );
}
export default function ModelTab({ model, onInspect }) {
  if (!model?.available)
    return (
      <section className="panel">
        <Empty title="Model unavailable">
          Check the configured model bundle and its runtime dependencies.
        </Empty>
      </section>
    );
  const report = model.evaluation,
    metrics = report?.metrics,
    classes = metrics?.classification;
  const confusion = metrics?.confusion_matrix;
  const normalTotal = confusion?.[0]?.reduce((a, b) => a + b, 0);
  const falseRate = normalTotal ? 1 - confusion[0][0] / normalTotal : null;
  return (
    <>
      <div className="section-toolbar">
        <p className="muted">
          Inspect the saved classifier and its published offline evaluation.
        </p>
        <button className="button primary" onClick={onInspect}>
          <FlaskConical size={16} />
          Test a record
        </button>
      </div>
      <div className="model-identity panel">
        <div className="model-symbol">XG</div>
        <div>
          <div className="inline-heading">
            <h2>{model.model_type}</h2>
            <Badge tone="positive">Loaded</Badge>
          </div>
          <p className="muted">
            {model.features} input features · preserved model, scaler and
            feature ordering
          </p>
        </div>
      </div>
      {metrics ? (
        <>
          <div className="metrics-grid">
            <Metric
              title="Accuracy"
              value={percent(metrics.accuracy)}
              note={`${number(report.records)} test records`}
            />
            <Metric
              title="Macro F1"
              value={classes["macro avg"]["f1-score"].toFixed(3)}
              note="Equal weight across five classes"
            />
            <Metric
              title="Normal false-alert rate"
              value={percent(falseRate)}
              note="From the offline confusion matrix"
            />
          </div>
          <section className="panel">
            <div className="panel-heading">
              <div>
                <h2>Performance by class</h2>
                <p className="muted text-small">
                  {report.dataset} · offline test set
                </p>
              </div>
              <Badge>Offline benchmark</Badge>
            </div>
            <div className="table-scroll">
              <table>
                <thead>
                  <tr>
                    <th>Class</th>
                    <th>Precision</th>
                    <th>Recall</th>
                    <th>F1 score</th>
                    <th>Test records</th>
                  </tr>
                </thead>
                <tbody>
                  {["Normal", "DoS", "Probe", "R2L", "U2R"].map((name) => (
                    <tr key={name}>
                      <td>
                        <strong>{name}</strong>
                      </td>
                      <td>{percent(classes[name].precision)}</td>
                      <td>
                        <div className="recall-cell">
                          <span>{percent(classes[name].recall)}</span>
                          <span
                            className="meter"
                            role="img"
                            aria-label={`${name} recall ${percent(classes[name].recall)}`}
                          >
                            <span
                              style={{ width: percent(classes[name].recall) }}
                              className={
                                classes[name].recall < 0.5 ? "low" : ""
                              }
                            />
                          </span>
                        </div>
                      </td>
                      <td>{classes[name]["f1-score"].toFixed(3)}</td>
                      <td>{number(classes[name].support)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
          <div className="note-row">
            <p>
              Low R2L and U2R recall is visible here. These results measure the
              offline dataset; real network detection also depends on
              packet-to-feature extraction and traffic conditions.
            </p>
          </div>
        </>
      ) : (
        <section className="panel">
          <Empty title="No matching evaluation">
            The loaded artifact does not have a matching published evaluation
            report.
          </Empty>
        </section>
      )}
      <details className="panel technical-details">
        <summary>Artifact details & reproducibility</summary>
        <div className="details-body">
          <dl className="metadata-list">
            {Object.entries(model.bundle_sha256 || {}).map(([name, hash]) => (
              <div key={name}>
                <dt>{name}</dt>
                <dd className="mono">{hash}</dd>
              </div>
            ))}
          </dl>
          {report && (
            <>
              <p className="muted text-small">Dataset SHA-256</p>
              <code className="wrap">{report.dataset_sha256}</code>
              <p className="muted text-small">Evaluation environment</p>
              <pre>{JSON.stringify(report.environment, null, 2)}</pre>
            </>
          )}
        </div>
      </details>
    </>
  );
}
export function Metric({ title, value, note, icon: Icon }) {
  return (
    <div className="metric panel">
      <div className="metric-label">
        {title}
        {Icon && <Icon size={16} />}
      </div>
      <strong className="metric-value">{value}</strong>
      <span className="muted text-small">{note}</span>
    </div>
  );
}
