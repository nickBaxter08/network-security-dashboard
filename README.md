# Perimeter — Network Security Dashboard

A web app that scans network devices/services, verifies what's actually
running behind each open port, matches detected software against known
CVEs (via the NVD API), flags risky configurations, and rolls it all up
into a per-device risk score with history over time.

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
config.py                     Mode toggle, scan settings
db.py                          SQLite scan history storage
scanner/
  demo_data.py                  Sample data for demo mode
  network_scan.py                 Real TCP scan for local mode (parallelized)
  protocol_check.py                Protocol-level verification per port
security/
  cve_lookup.py                     NVD CVE API client
  rules.py                            Config red-flag rules + diminishing-returns scoring
templates/index.html                  Dashboard page
static/css/style.css                   Styling
static/js/dashboard.js                  Frontend scan + render logic
```

## Roadmap / possible extensions

- Live deployment (demo mode) with a public link
- ARP-based host discovery for a full subnet (local mode only)
- Export findings as a PDF report
- Auth so a hosted version can save per-user scan history
- Binary-protocol verification for RDP/SMB

## DISCLAIMER
Anthropic's Claude put all of this code together as you see it, none of this was written by hand
