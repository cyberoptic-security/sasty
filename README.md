# Sasty — Static Analysis Review Tool

A local SAST review UI for scanning codebases with Semgrep, Gitleaks, and Hadolint.

## Quick Start

### Option A: Native (recommended for Windows)

**Requirements:** Python 3.11+, Node 20+

```bat
start.bat
```

Opens at `http://localhost:8000`. The frontend is served directly by the backend.

---

### Option B: Docker Compose

1. Copy `.env.example` to `.env` and set `SCAN_ROOT` to the parent folder containing your code:

```env
SCAN_ROOT=C:/Users/YourName/code
```

2. Start:

```bash
docker compose up --build
```

Opens at `http://localhost:3000`.

In the UI, enter paths as `/scans/<subfolder>` (e.g. `/scans/myproject`).

---

### Dev Mode (hot reload)

```bat
dev.bat
```

Frontend at `http://localhost:3000`, backend at `http://localhost:8000`.

---

## Tools

| Tool | Purpose | Install |
|------|---------|---------|
| Semgrep | Multi-language static analysis | Included via pip |
| Gitleaks | Secret/credential detection | Auto-downloaded from GitHub releases |
| Hadolint | Dockerfile linting | Auto-downloaded from GitHub releases |

Use the **Tools** panel in the UI to check versions and update to the latest releases.

---

## Features

- Scan any local folder with Semgrep, Gitleaks, and Hadolint
- Findings grouped by rule with individual occurrence detail
- Code context viewer with syntax highlighting (±5 lines around each finding)
- Severity filtering (CRITICAL / HIGH / MEDIUM / LOW / INFO)
- Filter by tool
- Mark individual findings as false positives
- Scan history with summary counts
- Tool version management with one-click updates
