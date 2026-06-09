# 🛡️ Malicious IP Intelligence System

Threat Intelligence & IP Reputation Analysis Web Platform

---

## Overview
The **Malicious IP Intelligence System** is a web-based console that helps analysts investigate **IPv4 addresses** using aggregated threat intelligence.

It supports:
- **Single IP investigation** (score + classification + analyst-style diagnosis + playbook)
- **Bulk ingestion** of `.csv`, `.txt`, and `.log` files (extract IPv4s → deduplicate → analyze)
- **Cache-first intelligence** with TTL to reduce repeated vendor queries
- **Watchlist** and **investigation history**
- **Report exports** (TXT, CSV, and print-optimized HTML for PDF)

> The app runs out-of-the-box in **Mock Mode** (deterministic data, no API keys required). Switch to **Live Mode** for real vendor lookups.

---

## Screens (High-level)
- Landing page (public)
- Login/Register (local) + Google OAuth (real or mock consent)
- Dashboard (stats + trends)
- Threat Analytics (breakdown + recent scans)
- IP Investigation (core console)
- File Upload + AJAX bulk analysis
- Results console (batch aggregation)
- Watchlist management
- History (search archive)
- Reports (export gallery)
- Profile + Settings

---

## Tech Stack
- **Backend**: Python **Flask** (server-rendered Jinja templates)
- **HTTP Client**: `requests`
- **Charts**: Chart.js (front-end JS)
- **Config**: `python-dotenv` to load `.env`
- **Data storage**: Flat-file **CSV** database in `database/`
- **Report generation**: `services/report_generator.py`

---

## Quick Start (Local)

### 1) Create a virtual environment
**Windows (cmd):**
```bat
python -m venv .venv
.venv\Scripts\activate
```

### 2) Install dependencies
```bat
pip install -r requirements.txt
```

### 3) Run the app
```bat
python app.py
```

Open:
- `http://localhost:5000`

---

## Configuration (.env)
Create a `.env` file in the project root.

### Supported variables
| Variable | Purpose |
|---|---|
| `SECRET_KEY` | Flask session secret (defaults to a safe internal value if omitted) |
| `PORT` | Port to run Flask on (default: `5000`) |
| `DEBUG` | Debug mode toggle (default: `True`) |
| `ABUSEIPDB_API_KEY` | Enables AbuseIPDB Live Mode when present |
| `VIRUSTOTAL_API_KEY` | Enables VirusTotal Live Mode when present |
| `GOOGLE_OAUTH_CLIENT_ID` | Enables real Google OAuth flow when present |
| `GOOGLE_OAUTH_CLIENT_SECRET` | Enables real Google OAuth flow when present |

### Mock vs Live
- If API keys are **missing/blank**, the application defaults to **Mock Mode**.
- If you enable **Live Mode** in Settings but credentials are not available, the app enforces Mock Mode.

---

## How Threat Intelligence Works

### 1) Cache-first fetch (TTL)
All intelligence retrieval goes through `services/threat_intel_cache.py`.
- Cache location: `database/threat_intel_cache.csv`
- Default TTL: **24 hours**
- Each IP is stored with JSON blobs for:
  - AbuseIPDB results
  - VirusTotal results
  - ip-api.com results
  - computed risk score + classification

### 2) Mock Mode
Mock Mode generates **deterministic** vendor-like data seeded by the target IP, so the same IP produces the same output.

### 3) Live Mode
Live Mode queries (when keys are present):
- **AbuseIPDB**: abuse reputation score
- **VirusTotal v3**: AV engine detections + tags
- **ip-api.com**: WHOIS/geo/ISP metadata

If a vendor lookup fails, the system falls back to mock data for that vendor.

---

## Risk Scoring & Classification

Implemented in `services/risk_scoring.py`.

### Score (0–100)
The system computes an aggregate score using weighted contributions:

- **AbuseIPDB contribution (50%)**
- **VirusTotal ratio contribution (35%)**
  - Uses `malicious_count / total_engines` scaled to 0–100
  - VT contribution is capped at **35**
- **Hosting/VPN profile contribution (15%)**
  - +8 if `usage_type` indicates Data Center/Hosting
  - +7 if VT tags include: `vpn`, `proxy`, `tor`, or `anonymous`

### Classification thresholds
| Risk Score | Classification |
|---:|---|
| `0 – 20` | **Safe** |
| `21 – 60` | **Suspicious** |
| `61 – 100` | **Malicious** |

The returned payload includes the classification and a breakdown.

---

## Bulk Ingestion Pipeline

Bulk upload triggers an IP extraction + analysis pipeline:
1. Upload `.csv`, `.txt`, or `.log` via `/file-upload`
2. Extract IPv4s using regex:
   - `\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`
3. Deduplicate extracted IPs
4. Analyze each IP through `/api/analyze-single` (AJAX streaming)
5. Batch results appear in `/results`
6. Reports can be exported from `/reports`

---

## Watchlist & History

### Watchlist
- Persistent CSV register: `database/watchlist.csv`
- Manual add/remove from the investigation UI
- **Auto-watchlist**: when risk score meets the threshold (default is `75`) the IP is added automatically.

### History
- Persistent CSV archive: `database/investigation_history.csv`
- Stores all investigations with metadata including:
  - risk score
  - classification
  - threat summary
  - vendor-derived fields (as available)
  - source (`manual` vs batch id)

---

## Reports & Exports

Report generation is implemented in `services/report_generator.py` and exported by routes in `app.py`.

### Individual Reports
- **TXT** (security audit style)
- **Print-optimized HTML** for the “Save as PDF” workflow
  - Generated under `reports/pdf/`

### Bulk Reports
- **CSV** batch register
- **TXT** batch ingestion summary
- **Print-optimized HTML** batch audit (PDF workflow)

### Where exports are stored
- `reports/pdf/` (HTML print pages)
- `reports/csv/` (CSV exports)
- `reports/txt/` (TXT exports)

---

## Testing

The repo includes `test_pipeline.py`.

Run:
```bat
python test_pipeline.py
```

It validates core subsystems:
- User auth & credential hashing
- Mock threat intelligence + risk scoring pipeline
- Watchlist CRUD operations
- Report compilation (TXT/CSV)

---

## Known Limitations / Notes
- Supports **IPv4** extraction (IPv6 not implemented).
- Flat-file CSV storage is optimized for a demo/academic setup, not high concurrency.
- VirusTotal and AbuseIPDB behavior depends on configured API keys and external availability.

---

## Future Enhancements
- IPv6 support
- Replace CSV storage with SQLite/PostgreSQL
- Scheduled background watchlist re-scans + alerts
- Email/SIEM integrations (CEF/Syslog)
- Rate limiting + RBAC
- Map visualization for geo locations
- Docker deployment

---

👨‍💻 Developed By

Koyyada Rohith

🔐 Cybersecurity Enthusiast | 🎓 B.Tech CSE | 🚀 Building Projects in Cybersecurity, Collaboration & Technology

📌 Version

Version 1.0

## 📄 License

This project is proprietary software. All rights reserved.
