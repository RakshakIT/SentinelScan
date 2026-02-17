# SentinelScan

A full-stack secure code scanning platform that detects vulnerabilities in source code using AST parsing and pattern matching.

## Features

- **SQL Injection Detection** — identifies string concatenation and interpolation in SQL queries using Python AST analysis and regex patterns
- **Hardcoded Secrets** — finds passwords, API keys, tokens, AWS credentials, and private keys embedded in source code
- **Cross-Site Scripting (XSS)** — detects `innerHTML`, `document.write`, `dangerouslySetInnerHTML`, template injection, and unsafe markup rendering
- **Unsafe Functions** — flags `eval()`, `exec()`, `pickle.load()`, `os.system()`, `yaml.load()`, and other dangerous calls
- **AST-Based Analysis** — uses Python's `ast` module for accurate detection beyond simple regex matching
- **Multi-Language Regex** — regex patterns extend detection to JavaScript, TypeScript, HTML, PHP, and more
- **Severity Classification** — every finding is rated High, Medium, or Low
- **Structured Reports** — JSON reports with file, line number, code snippet, description, and remediation guidance

## Architecture

```
SentinelScan/
├── backend/                  # Python FastAPI backend
│   ├── app/
│   │   ├── api/routes.py     # REST API endpoints
│   │   ├── models/schemas.py # Pydantic data models
│   │   ├── scanners/         # Vulnerability scanners
│   │   │   ├── base.py       # Abstract scanner interface
│   │   │   ├── sql_injection.py
│   │   │   ├── secrets.py
│   │   │   ├── xss.py
│   │   │   └── unsafe_functions.py
│   │   ├── services/         # Scan orchestration
│   │   │   └── scanner_service.py
│   │   ├── utils/            # File handling utilities
│   │   │   └── file_utils.py
│   │   └── main.py           # FastAPI application entry point
│   ├── Dockerfile
│   └── requirements.txt
├── frontend/                 # React + Vite frontend
│   ├── src/
│   │   ├── components/       # UI components
│   │   ├── services/api.js   # API client
│   │   ├── styles/index.css  # Styles
│   │   ├── App.jsx           # Main application
│   │   └── main.jsx          # Entry point
│   ├── Dockerfile
│   └── nginx.conf
├── docker-compose.yml
└── README.md
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/scan/upload` | Upload files for scanning (multipart form) |
| `POST` | `/api/scan/repo` | Scan a GitHub repo by URL |
| `GET` | `/api/reports` | List all scan reports |
| `GET` | `/api/reports/{scan_id}` | Get a specific report |
| `GET` | `/api/health` | Health check |

## Setup

### Docker (recommended)

```bash
docker compose up --build
```

- Frontend: http://localhost:3000
- Backend API: http://localhost:8000
- API docs: http://localhost:8000/docs

### Manual Setup

**Backend:**

```bash
cd backend
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

**Frontend:**

```bash
cd frontend
npm install
npm run dev
```

The frontend dev server proxies `/api` requests to the backend at port 8000.

## Usage

### Web Dashboard

1. Open http://localhost:3000
2. Upload source files using drag-and-drop or enter a public GitHub repository URL
3. View the scan report with severity breakdown and vulnerability details
4. Filter results by severity level

### API

Scan uploaded files:

```bash
curl -X POST http://localhost:8000/api/scan/upload \
  -F "files=@vulnerable_app.py"
```

Scan a GitHub repository:

```bash
curl -X POST http://localhost:8000/api/scan/repo \
  -H "Content-Type: application/json" \
  -d '{"repo_url": "https://github.com/owner/repo"}'
```

### Example Response

```json
{
  "scan_id": "a1b2c3d4e5f6",
  "status": "completed",
  "files_scanned": 12,
  "summary": {
    "total": 5,
    "high": 2,
    "medium": 2,
    "low": 1
  },
  "vulnerabilities": [
    {
      "rule_id": "SQL_INJECTION",
      "title": "Potential SQL Injection",
      "severity": "High",
      "file": "app/db.py",
      "line": 42,
      "snippet": "cursor.execute(f\"SELECT * FROM users WHERE id = {user_id}\")",
      "description": "User-controlled data appears to be concatenated directly into a SQL query string.",
      "recommendation": "Use parameterized queries instead of string formatting."
    }
  ]
}
```

## License

MIT
