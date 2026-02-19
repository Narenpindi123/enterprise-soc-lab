const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = 3000;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Paths to data files
const ALERTS_FILE = path.join(__dirname, '..', 'alerts', 'alerts.json');
const STATS_FILE = path.join(__dirname, '..', 'alerts', 'alert_stats.json');
const NORMALIZED_EVENTS = path.join(__dirname, '..', 'logs', 'normalized_events.json');
const ATTACK_TIMELINE = path.join(__dirname, '..', 'logs', 'attack_timeline.json');

// Helper to read JSON files
function readJSON(filepath) {
    try {
        return JSON.parse(fs.readFileSync(filepath, 'utf8'));
    } catch (err) {
        console.error(`Error reading ${filepath}:`, err.message);
        return null;
    }
}

// API Routes

// Get all alerts
app.get('/api/alerts', (req, res) => {
    const alerts = readJSON(ALERTS_FILE);
    if (!alerts) return res.status(500).json({ error: 'Alerts not found. Run the SIEM engine first.' });

    // Optional filtering
    let filtered = alerts;
    if (req.query.severity) {
        filtered = filtered.filter(a => a.severity === req.query.severity.toUpperCase());
    }
    if (req.query.tactic) {
        filtered = filtered.filter(a => a.mitre_tactic === req.query.tactic);
    }
    if (req.query.status) {
        filtered = filtered.filter(a => a.triage_status === req.query.status.toUpperCase());
    }

    res.json(filtered);
});

// Get alert stats
app.get('/api/stats', (req, res) => {
    const stats = readJSON(STATS_FILE);
    if (!stats) return res.status(500).json({ error: 'Stats not found.' });
    res.json(stats);
});

// Get normalized events
app.get('/api/events', (req, res) => {
    const events = readJSON(NORMALIZED_EVENTS);
    if (!events) return res.status(500).json({ error: 'Events not found.' });

    let filtered = events;
    if (req.query.source) {
        filtered = filtered.filter(e => e.source === req.query.source);
    }
    if (req.query.severity) {
        filtered = filtered.filter(e => e.severity === req.query.severity.toUpperCase());
    }
    if (req.query.type) {
        filtered = filtered.filter(e => e.event_type === req.query.type);
    }

    // Pagination
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 50;
    const start = (page - 1) * limit;

    res.json({
        total: filtered.length,
        page,
        limit,
        events: filtered.slice(start, start + limit)
    });
});

// Get MITRE ATT&CK mapping
app.get('/api/mitre', (req, res) => {
    const alerts = readJSON(ALERTS_FILE);
    if (!alerts) return res.status(500).json({ error: 'Alerts not found.' });

    // Build MITRE mapping
    const mitreMap = {};
    alerts.forEach(alert => {
        const technique = alert.mitre_technique;
        if (!mitreMap[technique]) {
            mitreMap[technique] = {
                technique_id: technique,
                technique_name: alert.mitre_name || alert.rule_name,
                tactic: alert.mitre_tactic,
                alert_count: 0,
                severities: [],
                alerts: []
            };
        }
        mitreMap[technique].alert_count++;
        mitreMap[technique].severities.push(alert.severity);
        mitreMap[technique].alerts.push({
            alert_id: alert.alert_id,
            rule_name: alert.rule_name,
            severity: alert.severity
        });
    });

    res.json(Object.values(mitreMap));
});

// Get attack timeline
app.get('/api/timeline', (req, res) => {
    const timeline = readJSON(ATTACK_TIMELINE);
    if (!timeline) return res.status(500).json({ error: 'Timeline not found.' });
    res.json(timeline);
});

// Update alert triage status
app.put('/api/alerts/:alertId/triage', (req, res) => {
    const alerts = readJSON(ALERTS_FILE);
    if (!alerts) return res.status(500).json({ error: 'Alerts not found.' });

    const alert = alerts.find(a => a.alert_id === req.params.alertId);
    if (!alert) return res.status(404).json({ error: 'Alert not found.' });

    const { status, classification, notes } = req.body;
    if (status) alert.triage_status = status;
    if (classification) alert.triage_classification = classification;
    if (notes) alert.analyst_notes = notes;
    alert.triaged_at = new Date().toISOString();

    fs.writeFileSync(ALERTS_FILE, JSON.stringify(alerts, null, 2));
    res.json(alert);
});

// Get event sources summary
app.get('/api/sources', (req, res) => {
    const events = readJSON(NORMALIZED_EVENTS);
    if (!events) return res.status(500).json({ error: 'Events not found.' });

    const sources = {};
    events.forEach(e => {
        const src = e.source || 'unknown';
        if (!sources[src]) {
            sources[src] = { source: src, count: 0, severities: {} };
        }
        sources[src].count++;
        const sev = e.severity || 'LOW';
        sources[src].severities[sev] = (sources[src].severities[sev] || 0) + 1;
    });

    res.json(Object.values(sources));
});

// Start server
app.listen(PORT, () => {
    console.log(`\n🛡️  Enterprise SOC Dashboard running at http://localhost:${PORT}\n`);
    console.log('  Make sure you have run the following first:');
    console.log('  1. python3 attack-simulation/generate_all.py');
    console.log('  2. python3 siem-engine/alert_engine.py\n');
});
