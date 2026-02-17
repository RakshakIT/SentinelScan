import { useState } from "react";

export default function RepoInput({ onSubmit, loading }) {
  const [url, setUrl] = useState("");

  const handleSubmit = (e) => {
    e.preventDefault();
    if (url.trim()) onSubmit(url.trim());
  };

  return (
    <form onSubmit={handleSubmit}>
      <div className="form-group">
        <label htmlFor="repo-url">GitHub Repository URL</label>
        <input
          id="repo-url"
          type="url"
          placeholder="https://github.com/owner/repo"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
        />
      </div>
      <button className="btn btn-primary" type="submit" disabled={!url.trim() || loading}>
        {loading && <span className="spinner" />}
        Scan Repository
      </button>
    </form>
  );
}
