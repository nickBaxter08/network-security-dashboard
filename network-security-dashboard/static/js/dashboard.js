const form = document.getElementById('scan-form');
const btn = document.getElementById('scan-btn');
const resultsList = document.getElementById('results-list');
const scanMeta = document.getElementById('scan-meta');
const gaugeFill = document.getElementById('gauge-fill');
const gaugeScore = document.getElementById('gauge-score');

const historyList = document.getElementById('history-list');

const modeBadge = document.getElementById('mode-badge');
const modeToggleBtn = document.getElementById('mode-toggle-btn');
const scanSubtext = document.getElementById('scan-subtext');
const targetInputWrap = document.getElementById('target-input-wrap');

const LOCAL_SUBTEXT = 'Enter a host on your own network to scan. Only scan devices you own or have explicit permission to test.';
const DEMO_SUBTEXT = 'Running on sample data — this deployment never scans a real network. Run locally to scan your own LAN.';

function applyMode(mode) {
  modeBadge.textContent = `${mode} mode`;
  modeBadge.className = `mode-badge mode-${mode}`;

  const isLocal = mode === 'local';
  targetInputWrap.classList.toggle('hidden', !isLocal);
  document.getElementById('target-input').required = isLocal;
  scanSubtext.textContent = isLocal ? LOCAL_SUBTEXT : DEMO_SUBTEXT;
  modeToggleBtn.textContent = isLocal ? 'Switch to demo' : 'Switch to local';
}

async function initMode() {
  try {
    const res = await fetch('/api/mode');
    const data = await res.json();
    applyMode(data.mode);
    modeToggleBtn.classList.toggle('hidden', !data.toggle_allowed);
  } catch {
    // leave server-rendered initial state as-is if this fails
  }
}

modeToggleBtn.addEventListener('click', async () => {
  const nextMode = modeBadge.textContent.startsWith('local') ? 'demo' : 'local';
  modeToggleBtn.disabled = true;
  try {
    const res = await fetch('/api/mode', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mode: nextMode }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Could not switch mode');
    applyMode(data.mode);
    resultsList.innerHTML = '<p class="empty-state">Run a scan to see devices, services, and flagged issues here.</p>';
    scanMeta.textContent = 'No scan run yet';
    updateGauge(0);
  } catch (err) {
    alert(err.message);
  } finally {
    modeToggleBtn.disabled = false;
  }
});

initMode();

const GAUGE_CIRCUMFERENCE = 251;

const RISK_COLOR = {
  clean: '#4FD1C5',
  low: '#7FB88F',
  medium: '#F0B429',
  high: '#F4795B',
  critical: '#E5484D',
};

function riskLabel(score) {
  if (score >= 70) return 'critical';
  if (score >= 40) return 'high';
  if (score >= 15) return 'medium';
  if (score > 0) return 'low';
  return 'clean';
}

async function loadHistory() {
  try {
    const res = await fetch('/api/history');
    const rows = await res.json();
    if (!rows.length) {
      historyList.innerHTML = '<p class="empty-state">No scans recorded yet.</p>';
      return;
    }
    historyList.innerHTML = rows.map(renderHistoryRow).join('');
  } catch {
    historyList.innerHTML = '<p class="empty-state">Couldn\'t load history.</p>';
  }
}

function renderHistoryRow(row) {
  const label = riskLabel(row.max_risk_score);
  const time = new Date(row.scanned_at * 1000).toLocaleString();
  return `
    <div class="history-row">
      <span class="history-time">${time}</span>
      <span class="history-target">${row.target}</span>
      <span class="history-mode">${row.mode}</span>
      <span class="risk-pill risk-${label}">${row.max_risk_score}</span>
    </div>
  `;
}

loadHistory();

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  const targetInput = document.getElementById('target-input');
  const body = targetInput ? { target: targetInput.value.trim() } : {};

  btn.disabled = true;
  btn.textContent = 'Scanning…';

  try {
    const res = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.error || 'Scan failed');
    }
    renderResults(data);
    loadHistory();
  } catch (err) {
    resultsList.innerHTML = `<p class="empty-state">${err.message}</p>`;
  } finally {
    btn.disabled = false;
    btn.textContent = 'Run scan';
  }
});

function renderResults(data) {
  const devices = data.devices || [];
  scanMeta.textContent = `${devices.length} device(s) · ${data.target} · ${new Date(data.scanned_at * 1000).toLocaleTimeString()}`;

  if (devices.length === 0) {
    resultsList.innerHTML = '<p class="empty-state">No devices found.</p>';
    updateGauge(0);
    return;
  }

  const maxScore = Math.max(...devices.map(d => d.risk_score));
  updateGauge(maxScore);

  resultsList.innerHTML = devices.map(renderDevice).join('');
}

function renderDevice(device) {
  const services = (device.services || []).map(renderService).join('');
  const emptyMessage = device.unreachable_note
    ? `<p class="empty-state">${device.unreachable_note}</p>`
    : '<p class="empty-state">No open services detected.</p>';
  return `
    <div class="device-card">
      <div class="device-head">
        <span class="device-name">${device.ip}<span class="hostname">${device.hostname || ''}</span></span>
        <span class="risk-pill risk-${device.risk_label}">${device.risk_label} · ${device.risk_score}</span>
      </div>
      ${services || emptyMessage}
    </div>
  `;
}

function renderService(service) {
  const findings = [
    ...(service.cves || []).map(c => ({
      severity: (c.severity || 'unknown').toLowerCase(),
      message: `${c.id} — ${c.summary}`,
    })),
    ...(service.config_findings || []).map(f => ({
      severity: f.severity,
      message: f.message,
    })),
  ];

  const findingsHtml = findings
    .map(f => `<div class="finding sev-${f.severity}">${f.message}</div>`)
    .join('');

  const confidenceTag = service.verified
    ? '<span class="confidence-tag confidence-verified">verified</span>'
    : '<span class="confidence-tag confidence-unverified">unconfirmed</span>';

  return `
    <div class="service-row">
      <span class="service-port">:${service.port} ${service.name}</span>
      <div class="service-body">
        <div>${service.product || 'unknown service'}${service.version ? ' ' + service.version : ''} ${confidenceTag}</div>
        ${findingsHtml}
      </div>
    </div>
  `;
}

function updateGauge(score) {
  const pct = Math.min(score, 100) / 100;
  const offset = GAUGE_CIRCUMFERENCE * (1 - pct);
  gaugeFill.style.strokeDashoffset = offset;

  const label = score >= 70 ? 'critical' : score >= 40 ? 'high' : score >= 15 ? 'medium' : score > 0 ? 'low' : 'clean';
  gaugeFill.style.stroke = RISK_COLOR[label];
  gaugeScore.textContent = score;
  gaugeScore.style.color = RISK_COLOR[label];
}
