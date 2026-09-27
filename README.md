# RECONNAITY — Security Reconnaissance Browser Extension

[![Repository checks](https://github.com/ahmedAlmaghrabi01/Security-Recon-BrowserEx-Capstone/actions/workflows/checks.yml/badge.svg)](https://github.com/ahmedAlmaghrabi01/Security-Recon-BrowserEx-Capstone/actions/workflows/checks.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

RECONNAITY is a cybersecurity capstone project that combines a Chrome browser extension with a FastAPI backend to automate passive reconnaissance, vulnerability correlation, and security reporting for an authorized domain.

> **Ethical-use notice:** Use this project only on systems you own or have explicit permission to assess. The project is intended for education, defensive security, and authorized testing.

## Highlights

- DNS, WHOIS, subdomain, technology-stack, and SSL/TLS reconnaissance
- CVE correlation backed by a local MongoDB dataset
- Executive, defensive, bug-bounty, and combined PDF reports
- Optional OpenRouter-powered report generation
- Chrome Manifest V3 browser extension
- Interactive FastAPI documentation at `/docs`

## Architecture

```text
Chrome extension
      │
      ▼
FastAPI REST API ──► Passive reconnaissance services
      │
      ├────────────► MongoDB / local NVD data
      ├────────────► OpenRouter (optional AI reports)
      └────────────► PDF report generator
```

## Technology stack

- **Backend:** Python, FastAPI, Uvicorn, aiohttp
- **Data:** MongoDB, NVD CVE archives
- **Extension:** JavaScript, HTML, CSS, Chrome Manifest V3
- **Reporting:** Markdown2, WeasyPrint
- **Analysis:** pandas, matplotlib, openpyxl

## Quick start

### Prerequisites

- Python 3.10 or newer
- MongoDB Community Server
- Google Chrome or another Chromium-based browser
- WeasyPrint system dependencies for PDF generation

### 1. Create a virtual environment

```bash
python -m venv .venv
```

Activate it on Windows:

```powershell
.venv\Scripts\Activate.ps1
```

Activate it on macOS or Linux:

```bash
source .venv/bin/activate
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure the environment

Copy `.env.example` to `.env` and replace placeholder values. The application loads this file automatically when started with `python run.py`.

| Variable | Purpose | Default |
| --- | --- | --- |
| `OPENROUTER_API_KEY` | Optional AI-generated reports | None |
| `NVD_API_KEY` | Optional NVD API access | None |
| `MONGO_URI` | MongoDB connection string | `mongodb://localhost:27017` |
| `INTERNAL_API_BASE_URL` | Base URL used by combined reports | `http://localhost:8000` |
| `ALLOWED_ORIGINS` | Comma-separated CORS allowlist | Local API origins |

Never commit a populated `.env` file or an API key.

### 4. Prepare CVE data

The archival NVD files are stored in `Original_HelprCodes/nvd_data`. Review the helper scripts in `Original_HelprCodes` and import the required data into MongoDB before using CVE correlation.

### 5. Start the API

```bash
python run.py
```

Open:

- API health check: `http://localhost:8000/health`
- Interactive documentation: `http://localhost:8000/docs`

### 6. Load the browser extension

1. Open `chrome://extensions`.
2. Enable **Developer mode**.
3. Select **Load unpacked**.
4. Choose the `frontend` directory.
5. Keep the API running at `http://localhost:8000` while using the extension.

## API groups

| Prefix | Capability |
| --- | --- |
| `/api/dns` | DNS records |
| `/api/whois` | WHOIS information |
| `/api/subdomains` | Certificate-based subdomain discovery |
| `/api/tech` | Technology fingerprinting |
| `/api/cve` and `/api/cve2` | Vulnerability correlation |
| `/api/ssl_tls` | SSL/TLS analysis |
| `/api/full` | Combined report |
| `/api/bounty` | AI-assisted offensive report |
| `/api/defense` | AI-assisted defensive roadmap |
| `/api/excutives` | Executive summary |

## Project structure

```text
app/                    FastAPI application and routers
services/               Reconnaissance and reporting logic
frontend/               Chrome extension
utils/                  PDF and database setup helpers
VisualAnalysis/         Capstone charts and analysis workbook
Demo/                   Example reports
Original_HelprCodes/    Research prototypes and NVD archives
```

## Portfolio material

The `Demo` directory contains example output reports. The repository also includes the capstone presentation and visual-analysis assets that explain the research results.

## Security and limitations

- Reconnaissance results depend on third-party services and network availability.
- AI report features require an OpenRouter key and may incur provider costs.
- CVE matching quality depends on accurate technology/version detection and imported NVD data.
- Do not expose the development API directly to the internet without authentication, HTTPS, rate limiting, and a restrictive CORS policy.
- Report vulnerabilities using the process in [SECURITY.md](SECURITY.md).

## License

Released under the [MIT License](LICENSE).
