export default function SummaryCards({ summary, filesScanned }) {
  return (
    <div className="summary">
      <div className="stat">
        <div className="value">{filesScanned}</div>
        <div className="label">Files Scanned</div>
      </div>
      <div className="stat">
        <div className="value">{summary.total}</div>
        <div className="label">Total Issues</div>
      </div>
      <div className="stat high">
        <div className="value">{summary.high}</div>
        <div className="label">High</div>
      </div>
      <div className="stat medium">
        <div className="value">{summary.medium}</div>
        <div className="label">Medium</div>
      </div>
      <div className="stat low">
        <div className="value">{summary.low}</div>
        <div className="label">Low</div>
      </div>
    </div>
  );
}
