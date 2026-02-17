import { useCallback, useEffect, useState } from "react";
import FileUpload from "./components/FileUpload";
import RepoInput from "./components/RepoInput";
import SummaryCards from "./components/SummaryCards";
import VulnTable from "./components/VulnTable";
import ScanHistory from "./components/ScanHistory";
import { scanFiles, scanRepo, fetchReports } from "./services/api";

export default function App() {
  const [tab, setTab] = useState("upload");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [report, setReport] = useState(null);
  const [history, setHistory] = useState([]);
  const [pendingFiles, setPendingFiles] = useState([]);

  useEffect(() => {
    fetchReports().then(setHistory).catch(() => {});
  }, [report]);

  const handleUpload = useCallback(async () => {
    if (!pendingFiles.length) return;
    setLoading(true);
    setError(null);
    try {
      const result = await scanFiles(pendingFiles);
      setReport(result);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, [pendingFiles]);

  const handleRepo = useCallback(async (url) => {
    setLoading(true);
    setError(null);
    try {
      const result = await scanRepo(url);
      setReport(result);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, []);

  return (
    <div className="app">
      <header>
        <h1>SentinelScan</h1>
        <span className="subtitle">Secure Code Scanner</span>
      </header>

      {/* Scan input area */}
      <div className="card">
        <div className="tabs">
          <button
            className={`tab${tab === "upload" ? " active" : ""}`}
            onClick={() => setTab("upload")}
          >
            Upload Files
          </button>
          <button
            className={`tab${tab === "repo" ? " active" : ""}`}
            onClick={() => setTab("repo")}
          >
            GitHub Repo
          </button>
          <button
            className={`tab${tab === "history" ? " active" : ""}`}
            onClick={() => setTab("history")}
          >
            History
          </button>
        </div>

        {error && <div className="error">{error}</div>}

        {tab === "upload" && (
          <div>
            <FileUpload onFiles={setPendingFiles} />
            <div style={{ marginTop: "1rem" }}>
              <button
                className="btn btn-primary"
                disabled={!pendingFiles.length || loading}
                onClick={handleUpload}
              >
                {loading && <span className="spinner" />}
                Scan Files
              </button>
            </div>
          </div>
        )}

        {tab === "repo" && <RepoInput onSubmit={handleRepo} loading={loading} />}

        {tab === "history" && (
          <ScanHistory reports={history} onSelect={setReport} />
        )}
      </div>

      {/* Results area */}
      {report && (
        <>
          <div className="card">
            <h2>
              Scan Results
              <span
                style={{
                  fontWeight: 400,
                  fontSize: "0.85rem",
                  color: "#94a3b8",
                  marginLeft: "0.75rem",
                }}
              >
                ID: {report.scan_id}
              </span>
            </h2>
            <SummaryCards
              summary={report.summary}
              filesScanned={report.files_scanned}
            />
          </div>

          <div className="card">
            <h2>Vulnerabilities</h2>
            <VulnTable vulnerabilities={report.vulnerabilities} />
          </div>
        </>
      )}
    </div>
  );
}
