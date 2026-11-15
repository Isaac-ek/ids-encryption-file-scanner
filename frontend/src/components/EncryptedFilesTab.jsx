import React, { useState } from "react";
import {
  UploadCloud,
  Lock,
  Unlock,
  Eye,
  FileText,
  ShieldCheck,
  ShieldAlert,
} from "lucide-react";

export default function EncryptedFilesTab({
  sensitiveFiles,
  encryptedFiles,
  handleUpload,
  handleEncrypt,
  handleDecrypt,
  handlePreview,
}) {
  const [isDragOver, setIsDragOver] = useState(false);

  const onDragOver = (e) => {
    e.preventDefault();
    setIsDragOver(true);
  };

  const onDragLeave = () => {
    setIsDragOver(false);
  };

  const onDrop = (e) => {
    e.preventDefault();
    setIsDragOver(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      const mockEvent = { target: { files: e.dataTransfer.files } };
      handleUpload(mockEvent);
    }
  };

  return (
    <div className="encrypted-files-view">
      {/* Upload Zone */}
      <div className="card" style={{ marginBottom: "2rem" }}>
        <h3
          style={{
            marginBottom: "1rem",
            display: "flex",
            alignItems: "center",
            gap: "0.5rem",
          }}
        >
          <UploadCloud size={18} color="var(--accent-primary)" /> Upload a file
        </h3>
        <div
          className={`dropzone ${isDragOver ? "dropzone-active" : ""}`}
          role="button"
          tabIndex={0}
          aria-label="Choose file to upload"
          onKeyDown={(e) => {
            if (e.key === "Enter" || e.key === " ") {
              e.preventDefault();
              document.getElementById("file-upload-input").click();
            }
          }}
          onClick={() => document.getElementById("file-upload-input").click()}
          onDragOver={onDragOver}
          onDragLeave={onDragLeave}
          onDrop={onDrop}
          style={{
            border: isDragOver
              ? "2px dashed var(--accent-primary)"
              : "1px dashed var(--border-color)",
            backgroundColor: isDragOver
              ? "rgba(99, 102, 241, 0.04)"
              : "rgba(255, 255, 255, 0.01)",
            padding: "2.5rem",
            textAlign: "center",
            borderRadius: "10px",
            cursor: "pointer",
            transition: "all var(--transition-normal)",
          }}
        >
          <UploadCloud
            className="dropzone-icon"
            size={40}
            style={{
              color: isDragOver
                ? "var(--accent-primary)"
                : "var(--text-secondary)",
              marginBottom: "0.75rem",
              transition: "transform var(--transition-normal)",
            }}
          />
          <p style={{ fontWeight: "500", marginBottom: "0.25rem" }}>
            Choose a sample file to protect
          </p>
          <span style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>
            Maximum file size: 8 MB
          </span>
          <input
            type="file"
            id="file-upload-input"
            aria-label="Upload sample file"
            style={{ display: "none" }}
            onChange={handleUpload}
          />
        </div>
      </div>

      {/* Isolation Columns */}
      <div className="card-grid" style={{ gap: "2rem" }}>
        {/* Plaintext Files column */}
        <div className="card" style={{ minHeight: "400px" }}>
          <h3
            style={{
              marginBottom: "1.25rem",
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
            }}
          >
            <span
              style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}
            >
              <Unlock size={18} color="var(--accent-success)" /> Original files
            </span>
            <span className="badge badge-success">
              {sensitiveFiles.length} files
            </span>
          </h3>
          {sensitiveFiles.length === 0 ? (
            <div
              style={{
                display: "flex",
                flexDirection: "column",
                alignItems: "center",
                justifyContent: "center",
                height: "220px",
                color: "var(--text-muted)",
              }}
            >
              <ShieldCheck
                size={32}
                style={{ marginBottom: "0.5rem", opacity: 0.5 }}
              />
              <p style={{ fontSize: "0.85rem" }}>No original files</p>
            </div>
          ) : (
            <div
              className="file-list"
              style={{
                display: "flex",
                flexDirection: "column",
                gap: "0.75rem",
              }}
            >
              {sensitiveFiles.map((f) => (
                <div
                  className="file-card"
                  key={f}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                    padding: "0.75rem 1rem",
                    border: "1px solid var(--border-color)",
                    borderRadius: "8px",
                    backgroundColor: "rgba(255,255,255,0.01)",
                  }}
                >
                  <div
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: "0.75rem",
                      overflow: "hidden",
                    }}
                  >
                    <FileText
                      size={18}
                      color="var(--accent-success)"
                      style={{ flexShrink: 0 }}
                    />
                    <span
                      style={{
                        fontSize: "0.85rem",
                        fontWeight: "500",
                        whiteSpace: "nowrap",
                        textOverflow: "ellipsis",
                        overflow: "hidden",
                      }}
                      title={f}
                    >
                      {f}
                    </span>
                  </div>
                  <div
                    style={{ display: "flex", gap: "0.5rem", flexShrink: 0 }}
                  >
                    <button
                      className="btn btn-secondary btn-sm"
                      onClick={(event) =>
                        handlePreview("sensitive", f, event.currentTarget)
                      }
                      style={{
                        padding: "0.3rem 0.6rem",
                        fontSize: "0.75rem",
                        gap: "4px",
                      }}
                    >
                      <Eye size={12} /> Preview
                    </button>
                    <button
                      className="btn btn-danger btn-sm"
                      onClick={() => handleEncrypt(f)}
                      style={{
                        padding: "0.3rem 0.6rem",
                        fontSize: "0.75rem",
                        gap: "4px",
                      }}
                    >
                      <Lock size={12} /> Encrypt
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Encrypted Quarantine files column */}
        <div className="card" style={{ minHeight: "400px" }}>
          <h3
            style={{
              marginBottom: "1.25rem",
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
            }}
          >
            <span
              style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}
            >
              <Lock size={18} color="var(--accent-danger)" /> Encrypted backups
              (.enc)
            </span>
            <span className="badge badge-danger">
              {encryptedFiles.length} files
            </span>
          </h3>
          {encryptedFiles.length === 0 ? (
            <div
              style={{
                display: "flex",
                flexDirection: "column",
                alignItems: "center",
                justifyContent: "center",
                height: "220px",
                color: "var(--text-muted)",
              }}
            >
              <ShieldCheck
                size={32}
                style={{ marginBottom: "0.5rem", opacity: 0.5 }}
              />
              <p style={{ fontSize: "0.85rem" }}>No encrypted backups</p>
            </div>
          ) : (
            <div
              className="file-list"
              style={{
                display: "flex",
                flexDirection: "column",
                gap: "0.75rem",
              }}
            >
              {encryptedFiles.map((f) => (
                <div
                  className="file-card"
                  key={f}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                    padding: "0.75rem 1rem",
                    border: "1px solid rgba(244, 63, 94, 0.1)",
                    borderRadius: "8px",
                    backgroundColor: "rgba(244, 63, 94, 0.01)",
                  }}
                >
                  <div
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: "0.75rem",
                      overflow: "hidden",
                    }}
                  >
                    <Lock
                      size={18}
                      color="var(--accent-danger)"
                      style={{ flexShrink: 0 }}
                    />
                    <span
                      style={{
                        fontSize: "0.85rem",
                        fontWeight: "500",
                        whiteSpace: "nowrap",
                        textOverflow: "ellipsis",
                        overflow: "hidden",
                      }}
                      title={f}
                    >
                      {f}
                    </span>
                  </div>
                  <div
                    style={{ display: "flex", gap: "0.5rem", flexShrink: 0 }}
                  >
                    <button
                      className="btn btn-secondary btn-sm"
                      onClick={(event) =>
                        handlePreview("encrypted", f, event.currentTarget)
                      }
                      style={{
                        padding: "0.3rem 0.6rem",
                        fontSize: "0.75rem",
                        gap: "4px",
                      }}
                    >
                      <Eye size={12} /> Hex Preview
                    </button>
                    <button
                      className="btn btn-primary btn-sm"
                      onClick={() => handleDecrypt(f)}
                      style={{
                        padding: "0.3rem 0.6rem",
                        fontSize: "0.75rem",
                        gap: "4px",
                      }}
                    >
                      <Unlock size={12} /> Restore
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
