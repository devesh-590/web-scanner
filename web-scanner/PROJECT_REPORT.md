# WebSec Scanner — Project Report

---

## 1. Project Overview

**Project Name:** WebSec Scanner  
**Type:** Web Security Auditing Tool  
**Tech Stack:** Python 3.12, Flask, Requests, Jinja2  
**Interface:** Browser-based Web UI (localhost:5000)  
**Code Files:** 1 (single all-in-one `app.py`)  

WebSec Scanner is an automated security auditing tool that analyses any publicly accessible website for common HTTP security misconfigurations. It checks security response headers and probes for CORS (Cross-Origin Resource Sharing) vulnerabilities, then presents findings in a styled space-themed web report with an overall security grade.

---

## 2. Objectives

- Automate the process of checking a website's HTTP security headers
- Detect CORS misconfiguration vulnerabilities across multiple attack vectors
- Present findings in a clear, colour-coded report accessible via a web browser
- Assign a meaningful security grade (A–F) based on the severity of findings
- Keep the entire codebase in a single, portable Python file

---

## 3. System Architecture

```
User (Browser)
     │
     ▼
app.py  (Flask Web Server — port 5000)
     │
     ├── ENGINE       → Fetches URL + probes CORS origins (HTTP requests)
     ├── HEADERS AUDIT → Audits 9 security headers, returns findings
     ├── CORS AUDIT   → Classifies CORS probe results by severity
     ├── REPORTER     → Builds styled HTML report with space background
     └── FLASK ROUTES → GET / (home form)  |  POST /scan (run + show results)
```

The entire application lives in a **single file** (`app.py`) with clearly separated sections:
- Each logical concern is grouped under a section comment (`# ══ ENGINE ══`, etc.)
- No external template files — HTML is generated inline
- Space-themed CSS background (stars + nebula gradients) built purely in CSS

---

## 4. Code Sections in app.py

### 4.1 ENGINE
- `ScanResult` class — stores all data collected for one scan
- `scan()` function — sends HTTP GET to target, collects response headers
- Probes 3 attacker-controlled origins for CORS testing:
  - `https://evil.com`
  - `null`
  - `https://attacker.example.com`

### 4.2 HEADERS AUDIT
Checks 9 security-relevant HTTP response headers:

| Header | Risk if Missing |
|---|---|
| Content-Security-Policy | XSS attacks |
| Strict-Transport-Security | MITM / protocol downgrade |
| X-Frame-Options | Clickjacking |
| X-Content-Type-Options | MIME sniffing |
| Referrer-Policy | URL data leakage |
| Permissions-Policy | Unrestricted browser feature access |
| X-XSS-Protection | Legacy XSS (informational) |
| Server | Technology fingerprinting |
| X-Powered-By | Framework fingerprinting |

### 4.3 CORS AUDIT
Classifies each CORS probe result into one of 6 scenarios:

| Scenario | Severity |
|---|---|
| Arbitrary origin reflected + `ACAC: true` | CRITICAL |
| Null origin reflected + `ACAC: true` | CRITICAL |
| Arbitrary origin reflected (no credentials) | HIGH |
| Null origin accepted | HIGH |
| Wildcard + credentials | HIGH |
| Wildcard `*` only | MEDIUM |
| Origin correctly rejected | PASS |

### 4.4 REPORTER
- Builds a fully styled dark space-themed HTML report
- CSS-only space background: deep black + purple/blue nebula gradients + 20 CSS stars
- Glassmorphism card effect on home page (backdrop blur)
- Severity badges, stat pills, data table for headers, cards for CORS findings
- Calculates overall security grade (A/B/C/D/F)

### 4.5 FLASK WEB APP
Two routes:
- `GET /` — renders the scan form (space-themed home page)
- `POST /scan` — runs full scan pipeline, returns styled HTML report with "← Scan Another URL" button

---

## 5. Security Grade System

| Grade | Condition |
|---|---|
| **F** | Any CRITICAL finding |
| **D** | Any HIGH finding |
| **C** | Any MEDIUM finding |
| **B** | Any LOW finding |
| **A** | Only INFO or PASS findings |

---

## 6. Technologies Used

| Technology | Version | Purpose |
|---|---|---|
| Python | 3.12 | Core language |
| Flask | 3.1+ | Web server / routing |
| Requests | 2.31+ | HTTP scanning |
| urllib3 | 2.0+ | HTTP connection handling |
| Jinja2 | 3.1+ | HTML templating (home page) |

---

## 7. How to Run

```bash
# Install dependencies
pip install -r requirements.txt

# Start the web server
python app.py

# Open in browser
http://localhost:5000
```

---

## 8. UI Design

### Home Page
- Deep space black background with purple/blue nebula glow
- 20 scattered CSS stars across the viewport
- Glassmorphism login card (frosted glass blur effect)
- URL input + timeout setting + Run Scan button

### Results Page
- Same space background carries through
- Security Grade badge (large letter A–F, colour-coded)
- Scan metadata (target URL, HTTP status, timestamp)
- Severity summary pills (count per level)
- Security headers table (header, status badge, current value, finding, recommendation)
- CORS finding cards (per probed origin, with full technical explanation)
- "← Scan Another URL" back button

---

## 9. Limitations

- Only scans publicly accessible URLs (no login/session support)
- CORS probing uses GET requests only (no OPTIONS preflight simulation)
- Does not scan JavaScript, cookies, or page content — HTTP headers only
- Timeout defaults to 10 seconds per request

---

## 10. Future Improvements

- Add authentication support (cookie/token injection)
- Add OPTIONS preflight CORS probing
- Export PDF reports
- Scan history / dashboard
- Scheduled / recurring scans
- Deploy as a hosted public service

---

## 11. Conclusion

WebSec Scanner successfully automates a task that security engineers typically perform manually — checking HTTP response headers and CORS configuration. The entire tool is contained in a single portable Python file, making it easy to share and run anywhere. The space-themed web UI and grading system give an instant, visually engaging summary of a site's security posture.
