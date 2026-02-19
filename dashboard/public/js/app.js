/**
 * Enterprise SOC Dashboard - Main Application Logic
 * Handles navigation, data loading, alert triage, and investigation search.
 */

const API_BASE = '';

// ========================================
// Navigation
// ========================================

const navItems = document.querySelectorAll('.nav-item');
const views = document.querySelectorAll('.view');
const pageTitle = document.getElementById('page-title');
const pageSubtitle = document.getElementById('page-subtitle');

const viewConfig = {
    overview: { title: 'Security Overview', subtitle: 'Real-time threat monitoring and alert summary' },
    alerts: { title: 'Alert Triage', subtitle: 'Classify, investigate, and respond to security alerts' },
    investigation: { title: 'Log Investigation', subtitle: 'Search and correlate events across all log sources' },
    mitre: { title: 'MITRE ATT&CK Mapping', subtitle: 'Detected techniques mapped to the ATT&CK framework' },
    timeline: { title: 'Attack Timeline', subtitle: 'Chronological reconstruction of the attack chain' }
};

navItems.forEach(item => {
    item.addEventListener('click', () => {
        const viewName = item.dataset.view;
        navItems.forEach(n => n.classList.remove('active'));
        item.classList.add('active');
        views.forEach(v => v.classList.remove('active'));
        document.getElementById(`view-${viewName}`).classList.add('active');
        const config = viewConfig[viewName];
        pageTitle.textContent = config.title;
        pageSubtitle.textContent = config.subtitle;
    });
});

// Update datetime
function updateDateTime() {
    const now = new Date();
    document.getElementById('datetime').textContent = now.toLocaleString('en-US', {
        weekday: 'short', month: 'short', day: 'numeric',
        hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false
    });
}
setInterval(updateDateTime, 1000);
updateDateTime();

// ========================================
// Data Loading
// ========================================

let alertsData = [];
let eventsData = [];
let statsData = {};
let mitreData = [];
let timelineData = {};

async function fetchJSON(endpoint) {
    try {
        const res = await fetch(`${API_BASE}${endpoint}`);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        return await res.json();
    } catch (err) {
        console.error(`Failed to fetch ${endpoint}:`, err);
        return null;
    }
}

async function loadAllData() {
    const [alerts, stats, events, mitre, timeline] = await Promise.all([
        fetchJSON('/api/alerts'),
        fetchJSON('/api/stats'),
        fetchJSON('/api/events?limit=10000'),
        fetchJSON('/api/mitre'),
        fetchJSON('/api/timeline')
    ]);

    alertsData = alerts || [];
    statsData = stats || {};
    eventsData = events?.events || [];
    mitreData = mitre || [];
    timelineData = timeline || {};

    updateOverview();
    renderAlertsList();
    renderTimeline();
    renderMitreMatrix();
    initCharts();
}

// ========================================
// Overview
// ========================================

function updateOverview() {
    document.getElementById('stat-critical').textContent = statsData.alerts_by_severity?.CRITICAL || 0;
    document.getElementById('stat-high').textContent = statsData.alerts_by_severity?.HIGH || 0;
    document.getElementById('stat-events').textContent = (statsData.total_events_processed || 0).toLocaleString();
    document.getElementById('stat-sources').textContent = Object.keys(statsData.alerts_by_tactic || {}).length || 7;
    document.getElementById('alert-badge').textContent = alertsData.length;

    // Recent alerts table
    const tbody = document.getElementById('recent-alerts-body');
    tbody.innerHTML = '';
    const criticalHigh = alertsData.filter(a => a.severity === 'CRITICAL' || a.severity === 'HIGH').slice(0, 10);
    criticalHigh.forEach(alert => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>${alert.alert_id}</td>
            <td><span class="severity-badge ${alert.severity.toLowerCase()}">${alert.severity}</span></td>
            <td>${alert.rule_name}</td>
            <td><span class="tag mitre">${alert.mitre_technique}</span></td>
            <td>${formatTimestamp(alert.timestamp)}</td>
            <td><span class="status-badge ${alert.triage_status.toLowerCase().replace('_', '-')}">${alert.triage_status}</span></td>
        `;
        tbody.appendChild(tr);
    });
}

// ========================================
// Alert Triage
// ========================================

function renderAlertsList() {
    const container = document.getElementById('alerts-list');
    const severityFilter = document.getElementById('filter-severity').value;
    const statusFilter = document.getElementById('filter-status').value;
    const tacticFilter = document.getElementById('filter-tactic').value;

    let filtered = alertsData;
    if (severityFilter) filtered = filtered.filter(a => a.severity === severityFilter);
    if (statusFilter) filtered = filtered.filter(a => a.triage_status === statusFilter);
    if (tacticFilter) filtered = filtered.filter(a => a.mitre_tactic === tacticFilter);

    container.innerHTML = '';

    if (filtered.length === 0) {
        container.innerHTML = '<p class="empty-state">No alerts match the current filters.</p>';
        return;
    }

    filtered.forEach(alert => {
        const card = document.createElement('div');
        card.className = `alert-card ${alert.severity.toLowerCase()}`;
        card.innerHTML = `
            <div class="alert-card-header">
                <div class="alert-card-title">
                    <span class="severity-badge ${alert.severity.toLowerCase()}">${alert.severity}</span>
                    ${alert.rule_name}
                </div>
                <span class="status-badge ${alert.triage_status.toLowerCase().replace('_', '-')}">${alert.triage_status}</span>
            </div>
            <div class="alert-card-meta">
                <span>🆔 ${alert.alert_id}</span>
                <span>⚔️ ${alert.mitre_technique} - ${alert.mitre_tactic}</span>
                <span>🕐 ${formatTimestamp(alert.timestamp)}</span>
            </div>
            <div class="alert-card-description">${alert.description}</div>
            <div class="alert-card-actions">
                <button class="btn btn-danger" onclick="triageAlert('${alert.alert_id}', 'RESOLVED', 'TRUE_POSITIVE')">✓ True Positive</button>
                <button class="btn btn-success" onclick="triageAlert('${alert.alert_id}', 'RESOLVED', 'FALSE_POSITIVE')">✗ False Positive</button>
                <button class="btn btn-warning" onclick="triageAlert('${alert.alert_id}', 'IN_PROGRESS', null)">⚡ Investigate</button>
                <button class="btn btn-outline" onclick="toggleDetail('${alert.alert_id}')">📋 Details</button>
            </div>
            <div class="alert-detail-expanded" id="detail-${alert.alert_id}">
                <div class="detail-section">
                    <h4>Recommended Response</h4>
                    <pre>${alert.recommended_response || 'N/A'}</pre>
                </div>
                <div class="detail-section">
                    <h4>Evidence</h4>
                    <pre>${JSON.stringify(alert.evidence, null, 2)}</pre>
                </div>
                <div class="detail-section">
                    <h4>MITRE ATT&CK</h4>
                    <pre>Technique: ${alert.mitre_technique} - ${alert.mitre_name}
Tactic: ${alert.mitre_tactic}</pre>
                </div>
            </div>
        `;
        container.appendChild(card);
    });

    // Populate tactic filter
    const tacticSelect = document.getElementById('filter-tactic');
    if (tacticSelect.options.length <= 1) {
        const tactics = [...new Set(alertsData.map(a => a.mitre_tactic))].sort();
        tactics.forEach(tactic => {
            const opt = document.createElement('option');
            opt.value = tactic;
            opt.textContent = tactic;
            tacticSelect.appendChild(opt);
        });
    }
}

function toggleDetail(alertId) {
    const detail = document.getElementById(`detail-${alertId}`);
    if (detail) {
        detail.classList.toggle('show');
    }
}

async function triageAlert(alertId, status, classification) {
    try {
        await fetch(`${API_BASE}/api/alerts/${alertId}/triage`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ status, classification })
        });
        // Refresh data
        alertsData = await fetchJSON('/api/alerts') || [];
        renderAlertsList();
        updateOverview();
    } catch (err) {
        console.error('Failed to triage alert:', err);
    }
}

// Filter event listeners
document.getElementById('filter-severity').addEventListener('change', renderAlertsList);
document.getElementById('filter-status').addEventListener('change', renderAlertsList);
document.getElementById('filter-tactic').addEventListener('change', renderAlertsList);

// ========================================
// Investigation / Search
// ========================================

document.getElementById('search-btn').addEventListener('click', performSearch);
document.getElementById('search-query').addEventListener('keypress', (e) => {
    if (e.key === 'Enter') performSearch();
});

async function performSearch() {
    const query = document.getElementById('search-query').value.trim().toLowerCase();
    const sourceFilter = document.getElementById('search-source').value;
    const resultsContainer = document.getElementById('search-results');
    const resultsCount = document.getElementById('results-count');

    if (!query) return;

    const allEvents = (await fetchJSON('/api/events?limit=10000'))?.events || [];

    let results = allEvents.filter(e => {
        const raw = (e.raw || '').toLowerCase();
        const detailsStr = JSON.stringify(e.details || {}).toLowerCase();
        const matchesQuery = raw.includes(query) || detailsStr.includes(query);
        const matchesSource = !sourceFilter || e.source === sourceFilter;
        return matchesQuery && matchesSource;
    });

    resultsCount.textContent = `${results.length} results`;
    resultsContainer.innerHTML = '';

    if (results.length === 0) {
        resultsContainer.innerHTML = '<p class="empty-state">No events match your search query.</p>';
        return;
    }

    results.slice(0, 100).forEach(event => {
        const item = document.createElement('div');
        item.className = 'result-item';

        let contentStr = '';
        if (event.details) {
            contentStr = Object.entries(event.details)
                .filter(([k, v]) => v && v !== 'unknown')
                .map(([k, v]) => `${k}: ${v}`)
                .join(' | ');
        }
        // Highlight the query
        const highlightedContent = contentStr.replace(
            new RegExp(`(${escapeRegex(query)})`, 'gi'),
            '<span class="highlight">$1</span>'
        );

        item.innerHTML = `
            <div class="result-source">${event.source} · ${event.event_type} · <span class="severity-badge ${(event.severity || 'low').toLowerCase()}">${event.severity}</span></div>
            <div class="result-content">${formatTimestamp(event.timestamp)} — ${highlightedContent}</div>
        `;
        resultsContainer.appendChild(item);
    });
}

// ========================================
// Timeline
// ========================================

function renderTimeline() {
    const container = document.getElementById('timeline-container');
    if (!timelineData.attacks || timelineData.attacks.length === 0) {
        container.innerHTML = '<p class="empty-state">No attack timeline data available.</p>';
        return;
    }

    // Sort attacks by start_time
    const sorted = [...timelineData.attacks].sort((a, b) =>
        new Date(a.start_time) - new Date(b.start_time)
    );

    container.innerHTML = '';
    sorted.forEach((attack, index) => {
        const severityClass = attack.severity?.toLowerCase() || 'medium';
        const event = document.createElement('div');
        event.className = `timeline-event ${severityClass}`;

        const techniqueMap = {
            'T1110.001': 'Initial Access → Brute Force',
            'T1548.003': 'Privilege Escalation → Sudo Abuse',
            'T1059.001': 'Execution → PowerShell',
            'T1053.003': 'Persistence → Cron Job',
            'T1543.002': 'Persistence → Systemd Service',
            'T1547.001': 'Persistence → Registry Run Key',
            'T1078.004': 'Initial Access → Cloud Accounts',
            'T1098.001': 'Persistence → Cloud Credentials',
            'T1071.004': 'C2 → DNS Tunneling',
            'T1048.001': 'Exfiltration → HTTP',
            'T1537': 'Exfiltration → Cloud Transfer',
        };

        const phaseName = techniqueMap[attack.mitre_technique] || attack.attack_type;

        event.innerHTML = `
            <div class="timeline-event-time">${formatTimestamp(attack.start_time)}</div>
            <div class="timeline-event-title">
                <span class="severity-badge ${severityClass}">${attack.severity}</span>
                ${phaseName}
            </div>
            <div class="timeline-event-description">
                ${attack.attack_type.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}
                ${attack.attacker_ip ? ` from ${attack.attacker_ip}` : ''}
                ${attack.target_host ? ` targeting ${attack.target_host}` : ''}
                ${attack.compromised_user ? ` (compromised: ${attack.compromised_user})` : ''}
            </div>
            <div class="timeline-event-meta">
                <span><span class="tag mitre">${attack.mitre_technique}</span></span>
                <span>Tactic: ${attack.mitre_tactic}</span>
            </div>
        `;
        container.appendChild(event);
    });
}

// ========================================
// Utilities
// ========================================

function formatTimestamp(ts) {
    if (!ts) return 'N/A';
    try {
        const date = new Date(ts);
        return date.toLocaleString('en-US', {
            month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false
        });
    } catch {
        return ts;
    }
}

function escapeRegex(string) {
    return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// ========================================
// Initialize
// ========================================
loadAllData();
