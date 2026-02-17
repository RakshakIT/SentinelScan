export default function ScanHistory({ reports, onSelect }) {
  if (reports.length === 0) {
    return <div className="empty">No previous scans.</div>;
  }

  return (
    <ul className="scan-list">
      {reports.map((r) => (
        <li key={r.scan_id}>
          <div>
            <span className="scan-id">{r.scan_id}</span>
            <span style={{ marginLeft: "1rem", color: "#94a3b8", fontSize: "0.8rem" }}>
              {r.source || "upload"} — {r.summary.total} issues ({r.files_scanned}{" "}
              files)
            </span>
          </div>
          <button
            className="btn btn-primary"
            style={{ padding: "0.35rem 0.85rem", fontSize: "0.8rem" }}
            onClick={() => onSelect(r)}
          >
            View
          </button>
        </li>
      ))}
    </ul>
  );
}
