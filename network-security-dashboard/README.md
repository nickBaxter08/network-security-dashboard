# Perimeter — Network Security Dashboard

**Live demo:** https://perimeter-dashboard.onrender.com/ (runs in demo
mode with sample data — free-tier hosting, so it may take 30–60 seconds
to wake up on the first request after a period of inactivity)

A web app that scans network devices/services, verifies what's actually
running behind each open port, matches detected software against known
CVEs (via the NVD API), flags risky configurations, and rolls it all up
into a per-device risk score with history over time.

## Why it's built this way

The app runs in one of two modes, controlled at startup by `APP_MODE`:

- **`demo` (default)** — uses realistic sample network data. This is what
  a public/hosted deployment should always run in. It never touches a
  real network, so it's safe to link from a resume or portfolio.
- **`local`** — enables a real TCP scan against a host you provide. This
  is intended to be run on your own machine, against your own network
  only. A publicly hosted server has no legitimate reason to offer
  scanning of arbitrary IPs, so this mode is not exposed on the live demo.

There's also an **in-app toggle** to switch between demo/local without
restarting the server — but it's disabled by default and gated behind a
separate setting, `ALLOW_MODE_TOGGLE`. **Never set this to `true` on a
publicly hosted deployment** — doing so would let any visitor flip a
public server into scanning an IP of their choosing, which is exactly the
kind of unauthorized-scanning risk described below. It's meant only for
your own convenience when running the app locally:

```bash
ALLOW_MODE_TOGGLE=true python app.py
```

With that set, a "Switch mode" button appears in the dashboard header.
Without it (the default, and always the case on the live demo), the app
stays locked to whatever `APP_MODE` it started with.

**Only ever scan hosts/networks you own or have explicit permission to
test.** Unauthorized network scanning can violate the law (e.g. the U.S.
Computer Fraud and Abuse Act) and most ISP/hosting terms of service, even
when the scan itself is harmless. This also applies to addresses that
merely *route through* infrastructure you don't own — see the CGNAT note
below for a real example of why that distinction matters.

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

## Deployment

The live demo runs on [Render](https://render.com)'s free tier via the
included `Procfile` (`gunicorn app:app`). The only environment variable
set there is `APP_MODE=demo` — `ALLOW_MODE_TOGGLE` is intentionally left
unset so the public deployment can never be switched into scanning a real
network (see above).

To deploy your own copy: connect the repo, set the build command to
`pip install -r requirements.txt`, the start command to
`gunicorn app:app --bind 0.0.0.0:$PORT`, and add `APP_MODE=demo` as an
environment variable.

## How it works

1. **Scan** — `scanner/network_scan.py` (local) or `scanner/demo_data.py`
   (demo) checks a fixed list of common ports in parallel and produces a
   list of devices with whatever responded.
2. **Protocol verification** — `scanner/protocol_check.py` sends a small,
   protocol-appropriate probe to each open port (e.g. an HTTP `HEAD`
   request, reading an SSH/FTP banner) and checks for a real signature
   before calling a service "verified." A successful TCP handshake alone
   is not treated as proof — see below for why.
3. **CVE matching** — `security/cve_lookup.py` queries the public NVD API
   for each detected product/version and returns matching CVEs with
   severity.
4. **Config rules** — `security/rules.py` flags inherently risky choices
   (e.g. Telnet, exposed RDP/VNC) that a CVE database wouldn't catch on
   its own. Findings from unverified services are still shown, but
   weighted less in the score, since confidence in what's actually
   running is lower.
5. **Scoring** — findings are combined with diminishing returns rather
   than summed directly (`security/rules.py:score_device`): each finding
   is treated as an independent probability of raising risk, combined as
   `1 - product(1 - impact)`. This means one critical finding alone
   still produces a high score, but several low/medium findings on one
   device don't automatically saturate to 100 the way plain addition
   would.
6. **History** — every scan is saved to `scan_history.db` (SQLite) via
   `db.py`, giving a running log of past scans and how risk changed over
   time, shown at the bottom of the dashboard.

## Why protocol verification exists — a real false positive

While testing this against my own public IP, a raw TCP-connect scan
reported five open ports — FTP, SSH, Telnet, SMTP, and HTTP — all with no
banner text, and the dashboard scored it a 71 ("critical"). That result
turned out to be misleading in two ways:

1. **The address itself wasn't uniquely mine.** Comparing the scanned IP
   against my router's actual WAN IP (visible in the router's own admin
   page) showed a mismatch — I was behind CGNAT, meaning that public
   address is shared ISP infrastructure, not equipment I control or have
   permission to test.
2. **The "open" ports likely weren't real services at all.** Every one of
   them responded to a bare TCP handshake but sent zero banner data —
   unusual for genuine FTP/SSH/Telnet servers, which normally identify
   themselves immediately. That pattern is consistent with an ISP-level
   transparent proxy or middlebox answering connections, not five
   different insecure services actually running.

This is what motivated `scanner/protocol_check.py`: a port responding to
a TCP handshake is necessary but not sufficient evidence of what's behind
it. Re-running the same scan after adding real protocol probes correctly
reported those findings as **unconfirmed** instead of asserting real
services were present.

Ports without a lightweight, dependency-free way to verify here (RDP,
SMB — both use binary handshakes) are deliberately left unverified rather
than guessed at.

## Project structure

```
app.py                       Flask app + API routes
config.py                     Mode settings (APP_MODE, ALLOW_MODE_TOGGLE)
db.py                          SQLite scan history storage
Procfile                        Start command for deployment (gunicorn)
scanner/
  demo_data.py                  Sample data for demo mode
  network_scan.py                 Real TCP scan for local mode (parallelized)
  protocol_check.py                Protocol-level verification per port
security/
  cve_lookup.py                     NVD CVE API client
  rules.py                            Config red-flag rules + diminishing-returns scoring
templates/index.html                  Dashboard page + mode toggle UI
static/css/style.css                   Styling
static/js/dashboard.js                  Frontend scan, render, and mode-switch logic
```

## Roadmap / possible extensions

- ARP-based host discovery for a full subnet (local mode only)
- Export findings as a PDF report
- Auth so a hosted version can save per-user scan history
- Binary-protocol verification for RDP/SMB
