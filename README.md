# Perimeter — Network Security Dashboard

A web app that scans network devices/services, matches detected software
against known CVEs (via the NVD API), flags risky configurations (e.g.
plaintext protocols, exposed admin ports), and rolls it all up into a
per-device risk score.

## Why it's built this way

The app runs in one of two modes, controlled by `APP_MODE`:

- **`demo` (default)** — uses realistic sample network data. This is what
  a public/hosted deployment should always run in. It never touches a
  real network, so it's safe to link from a resume or portfolio.
- **`local`** — enables a real TCP scan against a host you provide. This
  is intended to be run on your own machine, against your own network
  only. A publicly hosted server has no legitimate reason to offer
  scanning of arbitrary IPs, so this mode is not exposed on the live demo.

**Only ever scan hosts/networks you own or have explicit permission to
test.** Unauthorized network scanning can violate the law (e.g. the U.S.
Computer Fraud and Abuse Act) and most ISP/hosting terms of service, even
when the scan itself is harmless.

## Setup

```bash
pip install -r requirements.txt

# Demo mode (default)
python app.py

# Local scan mode
APP_MODE=local python app.py
```

Then open `http://localhost:5000`.

Optional: set `NVD_API_KEY` (free from the [NVD API](https://nvd.nist.gov/developers/request-an-api-key))
to raise the CVE lookup rate limit — the app works without one, just slower
under heavy use.

## How it works

1. **Scan** — `scanner/network_scan.py` (local) or `scanner/demo_data.py`
   (demo) produces a list of devices, each with open ports and best-effort
   service/version detection (banner grabbing).
2. **CVE matching** — `security/cve_lookup.py` queries the public NVD API
   for each detected product/version and returns matching CVEs with
   severity.
3. **Config rules** — `security/rules.py` flags inherently risky choices
   (e.g. Telnet, exposed RDP/VNC) that a CVE database wouldn't catch on
   its own.
4. **Scoring** — findings are weighted by severity into a 0–100 risk score
   per device, shown on the dashboard gauge and device cards.

## Project structure

```
app.py                  Flask app + API routes
config.py                Mode toggle, scan settings
scanner/
  demo_data.py            Sample data for demo mode
  network_scan.py          Real TCP scan for local mode
security/
  cve_lookup.py             NVD CVE API client
  rules.py                   Config red-flag rules + scoring
templates/index.html         Dashboard page
static/css/style.css          Styling
static/js/dashboard.js         Frontend scan + render logic
```

## Roadmap / possible extensions

- Scan history stored in SQLite, with a trend view over time
- ARP-based host discovery for a full subnet (local mode only)
- Export findings as a PDF report
- Auth so the live demo can save per-user scan history
