const BASE = "/api";

export async function scanFiles(files) {
  const form = new FormData();
  for (const file of files) {
    form.append("files", file);
  }
  const res = await fetch(`${BASE}/scan/upload`, {
    method: "POST",
    body: form,
  });
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

export async function scanRepo(repoUrl) {
  const res = await fetch(`${BASE}/scan/repo`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ repo_url: repoUrl }),
  });
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

export async function fetchReports() {
  const res = await fetch(`${BASE}/reports`);
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

export async function fetchReport(scanId) {
  const res = await fetch(`${BASE}/reports/${scanId}`);
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}
