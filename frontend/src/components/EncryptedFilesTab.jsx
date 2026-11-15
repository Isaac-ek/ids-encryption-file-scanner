import React, { useRef, useState } from "react";
import {
  Upload,
  File,
  Lock,
  Unlock,
  Eye,
  Download,
  Check,
  FolderOpen,
} from "lucide-react";
import { Badge, Empty } from "./ui";

export default function EncryptedFilesTab({
  maxUploadBytes,
  sensitiveFiles,
  encryptedFiles,
  handleUpload,
  handleEncrypt,
  handleDecrypt,
  handlePreview,
  handleDownload,
  handleBulk,
  busy,
}) {
  const [kind, setKind] = useState("sensitive"),
    [selected, setSelected] = useState([]);
  const input = useRef(null);
  const files = kind === "sensitive" ? sensitiveFiles : encryptedFiles;
  const eligible = (name) =>
    kind === "sensitive"
      ? !encryptedFiles.includes(name + ".enc")
      : !sensitiveFiles.includes(name.slice(0, -4));
  const toggle = (name) =>
    setSelected((old) =>
      old.includes(name) ? old.filter((item) => item !== name) : [...old, name],
    );
  const changeTab = (value) => {
    setKind(value);
    setSelected([]);
  };
  return (
    <>
      <div className="section-toolbar">
        <p className="muted">
          Protect a file, inspect its contents, or recover the original.
        </p>
        <input
          ref={input}
          className="visually-hidden"
          aria-label="Upload sample file"
          type="file"
          onChange={(event) => {
            handleUpload(event);
            event.target.value = "";
          }}
        />
        <button
          className="button primary"
          onClick={() => input.current.click()}
          disabled={busy}
        >
          <Upload size={16} />
          Upload file
        </button>
      </div>
      <section className="panel">
        <div className="panel-heading">
          <div className="segmented">
            <button
              aria-pressed={kind === "sensitive"}
              onClick={() => changeTab("sensitive")}
            >
              Originals <span>{sensitiveFiles.length}</span>
            </button>
            <button
              aria-pressed={kind === "encrypted"}
              onClick={() => changeTab("encrypted")}
            >
              Encrypted backups <span>{encryptedFiles.length}</span>
            </button>
          </div>
          <span className="muted text-small">
            AES-256-GCM · Max. upload {maxUploadBytes ? `${maxUploadBytes / (1024 * 1024)} MB` : "loading…"}
          </span>
        </div>
        {selected.length > 0 && (
          <div className="selection-bar">
            <span>{selected.length} selected</span>
            <button
              className="button small primary"
              disabled={busy}
              onClick={async () => {
                await handleBulk(
                  kind === "sensitive" ? "encrypt" : "decrypt",
                  selected,
                );
                setSelected([]);
              }}
            >
              {kind === "sensitive" ? <Lock size={14} /> : <Unlock size={14} />}{" "}
              {kind === "sensitive" ? "Encrypt selected" : "Restore selected"}
            </button>
            <button className="text-button" onClick={() => setSelected([])}>
              Clear selection
            </button>
          </div>
        )}
        {files.length ? (
          <div className="table-scroll">
            <table className="files-table">
              <thead>
                <tr>
                  <th className="checkbox-cell">
                    <input
                      type="checkbox"
                      aria-label="Select all eligible files"
                      checked={
                        files.filter(eligible).length > 0 &&
                        files
                          .filter(eligible)
                          .every((name) => selected.includes(name))
                      }
                      onChange={(event) =>
                        setSelected(
                          event.target.checked ? files.filter(eligible) : [],
                        )
                      }
                    />
                  </th>
                  <th>File name</th>
                  <th>Storage</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {files.map((name) => (
                  <tr key={name}>
                    <td>
                      <input
                        type="checkbox"
                        aria-label={`Select ${name}`}
                        disabled={!eligible(name)}
                        checked={selected.includes(name)}
                        onChange={() => toggle(name)}
                      />
                    </td>
                    <td>
                      <div className="file-name">
                        <span className="file-icon">
                          {kind === "sensitive" ? (
                            <File size={18} />
                          ) : (
                            <Lock size={18} />
                          )}
                        </span>
                        <strong>{name}</strong>
                      </div>
                    </td>
                    <td>
                      <Badge
                        tone={kind === "sensitive" ? "neutral" : "positive"}
                      >
                        {kind === "sensitive" ? "Original" : "Encrypted"}
                      </Badge>
                    </td>
                    <td>
                      <div className="row-actions">
                        <button
                          className="icon-button"
                          aria-label={
                            kind === "sensitive"
                              ? `Preview ${name}`
                              : `Hex preview ${name}`
                          }
                          title="Preview"
                          onClick={(event) =>
                            handlePreview(kind, name, event.currentTarget)
                          }
                        >
                          <Eye size={16} />
                        </button>
                        <button
                          className="icon-button"
                          aria-label={`Download ${name}`}
                          title="Download"
                          onClick={() => handleDownload(kind, name)}
                        >
                          <Download size={16} />
                        </button>
                        {eligible(name) ? (
                          <button
                            className="button small secondary"
                            disabled={busy}
                            onClick={async () => {
                              const success = await (kind === "sensitive"
                                ? handleEncrypt(name)
                                : handleDecrypt(name));
                              if (success)
                                changeTab(
                                  kind === "sensitive"
                                    ? "encrypted"
                                    : "sensitive",
                                );
                            }}
                          >
                            {kind === "sensitive" ? (
                              <Lock size={14} />
                            ) : (
                              <Unlock size={14} />
                            )}{" "}
                            {kind === "sensitive" ? "Encrypt" : "Restore"}
                          </button>
                        ) : (
                          <span className="restored-label">
                            <Check size={14} />
                            {kind === "sensitive"
                              ? "Backup exists"
                              : "Restored"}
                          </span>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <Empty
            title={
              kind === "sensitive"
                ? "No original files"
                : "No encrypted backups"
            }
            icon={FolderOpen}
          >
            {kind === "sensitive"
              ? "Upload a file to start. Existing encrypted backups can be restored from the other tab."
              : "Encrypt an uploaded file to create its protected backup."}
          </Empty>
        )}
      </section>
      <div className="note-row">
        <Lock size={16} />
        <p>
          Encryption removes the original after the encrypted copy is saved and
          audited. Restoring retains the encrypted backup.
        </p>
      </div>
    </>
  );
}
