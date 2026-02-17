import { useState } from "react";

const SEVERITY_ORDER = { High: 0, Medium: 1, Low: 2 };

export default function VulnTable({ vulnerabilities }) {
  const [filter, setFilter] = useState("All");

  const filtered =
    filter === "All"
      ? vulnerabilities
      : vulnerabilities.filter((v) => v.severity === filter);

  const sorted = [...filtered].sort(
    (a, b) => (SEVERITY_ORDER[a.severity] ?? 3) - (SEVERITY_ORDER[b.severity] ?? 3)
  );

  return (
    <div>
      <div className="filters">
        {["All", "High", "Medium", "Low"].map((level) => (
          <button
            key={level}
            className={`filter-btn${filter === level ? " active" : ""}`}
            onClick={() => setFilter(level)}
          >
            {level}
            {level !== "All" &&
              ` (${vulnerabilities.filter((v) => v.severity === level).length})`}
          </button>
        ))}
      </div>

      {sorted.length === 0 ? (
        <div className="empty">No vulnerabilities found.</div>
      ) : (
        <div style={{ overflowX: "auto" }}>
          <table className="vuln-table">
            <thead>
              <tr>
                <th>Severity</th>
                <th>Rule</th>
                <th>Title</th>
                <th>File</th>
                <th>Line</th>
                <th>Details</th>
              </tr>
            </thead>
            <tbody>
              {sorted.map((v, i) => (
                <tr key={i}>
                  <td>
                    <span
                      className={`severity-badge ${v.severity.toLowerCase()}`}
                    >
                      {v.severity}
                    </span>
                  </td>
                  <td>{v.rule_id}</td>
                  <td>{v.title}</td>
                  <td style={{ fontFamily: "monospace", fontSize: "0.8rem" }}>
                    {v.file}
                  </td>
                  <td>{v.line}</td>
                  <td>
                    <div style={{ fontSize: "0.8rem", color: "#94a3b8" }}>
                      {v.description}
                    </div>
                    {v.snippet && <code className="snippet">{v.snippet}</code>}
                    {v.recommendation && (
                      <div
                        style={{
                          fontSize: "0.78rem",
                          color: "#22c55e",
                          marginTop: "0.35rem",
                        }}
                      >
                        Fix: {v.recommendation}
                      </div>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
