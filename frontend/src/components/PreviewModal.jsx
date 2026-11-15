import React, { useEffect, useRef } from "react";

export default function PreviewModal({
  showPreviewModal,
  setShowPreviewModal,
  previewContent,
  returnFocus,
}) {
  const dialog = useRef(null);
  useEffect(() => {
    if (!showPreviewModal) return;
    const previous = returnFocus || document.activeElement;
    dialog.current.showModal();
    return () => {
      dialog.current?.close();
      previous?.focus();
    };
  }, [showPreviewModal, returnFocus]);
  return (
    <dialog
      ref={dialog}
      className="preview-dialog"
      aria-labelledby="preview-heading"
      onCancel={() => setShowPreviewModal(false)}
    >
      {previewContent && (
        <>
          <div className="modal-header">
            <h2 id="preview-heading">
              File preview: {previewContent.filename}
            </h2>
            <button
              className="btn btn-secondary"
              aria-label="Close preview"
              onClick={() => setShowPreviewModal(false)}
            >
              Close
            </button>
          </div>
          <pre>{previewContent.content}</pre>
        </>
      )}
    </dialog>
  );
}
