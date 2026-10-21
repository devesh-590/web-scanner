# 🛡️ WebSec Scanner

An automated web security auditing tool that scans any website for **security header misconfigurations** and **CORS vulnerabilities**, then displays a full styled report in your browser with a space-themed UI.

---

## Features

- ✅ Audits **9 critical security headers** (CSP, HSTS, X-Frame-Options, and more)
- ✅ Probes for **CORS misconfigurations** (origin reflection, null origin bypass, wildcard abuse)
- ✅ Assigns an overall **Security Grade (A–F)**
- ✅ Beautiful **space-themed web UI** — stars + nebula background
- ✅ Severity levels: `CRITICAL` → `HIGH` → `MEDIUM` → `LOW` → `INFO` → `PASS`
- ✅ **Single file** — entire app in one `app.py`

---

## Installation

### 1. Clone the repository
```bash
git clone https://github.com/yourusername/web-scanner.git
cd web-scanner
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

---

## Usage

```bash
python app.py
```
Then open **http://localhost:5000** in your browser, type any URL, and click **Run Scan**.

---

## Project Structure

```
web-scanner/
├── app.py              # All-in-one Flask web app — the only code file
├── requirements.txt    # Python dependencies
├── README.md           # This file
└── PROJECT_REPORT.md   # Full project documentation
```

---

## Security Checks

### Security Headers Audited
| Header | What it protects against |
|---|---|
| `Content-Security-Policy` | XSS attacks |
| `Strict-Transport-Security` | Protocol downgrade / MITM |
| `X-Frame-Options` | Clickjacking |
| `X-Content-Type-Options` | MIME sniffing |
| `Referrer-Policy` | URL leakage |
| `Permissions-Policy` | Unrestricted browser features |
| `X-XSS-Protection` | Legacy XSS filter |
| `Server` | Technology fingerprinting |
| `X-Powered-By` | Framework fingerprinting |

### CORS Flaws Detected
| Flaw | Severity |
|---|---|
| Arbitrary origin reflected + credentials enabled | CRITICAL |
| Null origin reflected + credentials enabled | CRITICAL |
| Arbitrary origin reflected (no credentials) | HIGH |
| Null origin accepted | HIGH |
| Wildcard + credentials (invalid combo) | HIGH |
| Wildcard origin (`*`) | MEDIUM |

---

## Tech Stack

- **Python 3.12**
- **Flask** — web framework
- **Requests** — HTTP scanning
- **urllib3** — HTTP connection handling
- **Jinja2** — HTML templating

---

## License

MIT License — free to use, modify, and distribute.
