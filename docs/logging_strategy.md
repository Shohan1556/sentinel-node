# Initial Data Acquisition & Logging Strategy – Week 1

## 1. Overview
This project implements a lightweight authentication backend with comprehensive request logging. Every HTTP interaction—including login attempts (successful/failed), API calls, and errors—is captured and written to structured log files. These logs serve as the primary data source for later anomaly detection (e.g., brute-force attacks).

The system generates two key log streams:
- **`data/raw/auth.log`**: Security-focused log mimicking Linux `auth.log` format (for SSH-style analysis).
- **`data/raw/logback.log`**: Full application trace log (request path, IP, timestamp, status) for forensic auditing.

## 2. Log Generation Approach

### A. Backend System Design
- Built in **Python (FastAPI)** for rapid development and built-in async support.
- Exposes:
  - `POST /login` → validates credentials (hardcoded for demo)
  - `GET /protected` → requires valid session/token
- All endpoints are wrapped with **middleware** that logs every request before processing.

### B. Log Content & Format

#### `auth.log` (Security Events Only)
Mimics standard Unix authentication log format for compatibility with existing security tooling:

- **Generated for every HTTP request**
- Includes: timestamp, IP, method/path, status code, response time

## 3. Log Storage & Rotation
- Logs are written to `data/raw/`:
  - `auth.log`
  - `logback.log`
- Files are **append-only**; no rotation in MVP (simplifies parsing).
- Directory structure ensures easy ingestion in later phases (Week 3+).

## 4. Data Acquisition Plan
| Phase | Source | Method |
|------|--------|--------|
| **Week 1–2** | Synthetic logs | Backend generates logs during local testing |
| **Week 3 (MVP)** | Real client requests | Use `curl`/Postman to simulate login attempts |
| **Week 4+** | Automated scripts | `scripts/simulate_bruteforce.py` sends 10+ failed logins |

> ✅ **No external datasets needed** — the system **generates its own ground-truth logs**, ensuring full control and reproducibility.

## 5. Validation & Risks

### Validation
- Log entries will be verified by:
  - Manual inspection of `auth.log` after test runs
  - Parsing scripts (Week 3) that count failed logins per IP
  - Unit tests asserting correct log format

### Risks & Mitigations
| Risk | Mitigation |
|------|-----------|
| Log file permission issues on Linux | Run app in user space; write to project-local `data/` dir |
| Inconsistent timestamp formats | Use UTC and ISO 8601 in `logback.log`; mimic syslog in `auth.log` |
| Over-logging impacting performance | Disable debug logs in production config (future refinement) |

## 6. Alignment with Assessment Criteria
- ✅ **Realistic logging strategy** aligned with Cybersecurity specialisation  
- ✅ **Self-contained data generation** → no dependency on external systems  
- ✅ **Structured, parseable formats** → enables Week 3 detection logic  
- ✅ **Evidence-ready**: logs are human-readable and machine-parsable  