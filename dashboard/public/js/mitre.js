/**
 * Enterprise SOC Dashboard - MITRE ATT&CK Matrix View
 * Interactive matrix showing detected techniques organized by tactic.
 */

function renderMitreMatrix() {
    const container = document.getElementById('mitre-matrix');
    const detailsPanel = document.getElementById('mitre-details');

    if (!mitreData || mitreData.length === 0) {
        container.innerHTML = '<p class="empty-state">No MITRE ATT&CK data available. Run the SIEM engine first.</p>';
        return;
    }

    // Organize techniques by tactic
    const tacticOrder = [
        'Initial Access',
        'Execution',
        'Persistence',
        'Privilege Escalation',
        'Defense Evasion',
        'Credential Access',
        'Lateral Movement',
        'Command and Control',
        'Exfiltration'
    ];

    const tacticGroups = {};
    mitreData.forEach(technique => {
        const tactic = technique.tactic;
        if (!tacticGroups[tactic]) {
            tacticGroups[tactic] = [];
        }
        tacticGroups[tactic].push(technique);
    });

    container.innerHTML = '';

    tacticOrder.forEach(tactic => {
        if (!tacticGroups[tactic]) return;

        const column = document.createElement('div');
        column.className = 'mitre-tactic-column';

        const header = document.createElement('div');
        header.className = 'mitre-tactic-header';
        header.textContent = tactic;
        column.appendChild(header);

        tacticGroups[tactic].forEach(technique => {
            const techEl = document.createElement('div');
            techEl.className = 'mitre-technique';
            techEl.innerHTML = `
                <div>
                    <div class="mitre-technique-id">${technique.technique_id}</div>
                    <div class="mitre-technique-name">${technique.technique_name}</div>
                </div>
                <span class="mitre-technique-count">${technique.alert_count}</span>
            `;
            techEl.addEventListener('click', () => showTechniqueDetail(technique, techEl));
            column.appendChild(techEl);
        });

        container.appendChild(column);
    });
}

function showTechniqueDetail(technique, element) {
    // Remove active state from all techniques
    document.querySelectorAll('.mitre-technique').forEach(t => t.classList.remove('active'));
    element.classList.add('active');

    const detailsPanel = document.getElementById('mitre-details');

    // Determine the max severity
    const severityOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
    const maxSeverity = technique.severities.sort((a, b) =>
        (severityOrder[a] || 99) - (severityOrder[b] || 99)
    )[0] || 'MEDIUM';

    detailsPanel.innerHTML = `
        <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 16px;">
            <div>
                <h3 style="font-size: 1.1rem; margin-bottom: 4px;">
                    <span class="tag mitre" style="font-size: 0.8rem; margin-right: 8px;">${technique.technique_id}</span>
                    ${technique.technique_name}
                </h3>
                <p style="color: var(--text-muted); font-size: 0.82rem;">Tactic: ${technique.tactic}</p>
            </div>
            <span class="severity-badge ${maxSeverity.toLowerCase()}">${maxSeverity}</span>
        </div>
        
        <div style="margin-bottom: 16px;">
            <h4 style="font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.08em; color: var(--text-muted); margin-bottom: 8px;">
                Associated Alerts (${technique.alert_count})
            </h4>
            <table style="width: 100%;">
                <thead>
                    <tr>
                        <th>Alert ID</th>
                        <th>Rule Name</th>
                        <th>Severity</th>
                    </tr>
                </thead>
                <tbody>
                    ${technique.alerts.map(a => `
                        <tr>
                            <td style="font-family: 'JetBrains Mono', monospace; font-size: 0.76rem;">${a.alert_id}</td>
                            <td>${a.rule_name}</td>
                            <td><span class="severity-badge ${a.severity.toLowerCase()}">${a.severity}</span></td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        </div>

        <div>
            <h4 style="font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.08em; color: var(--text-muted); margin-bottom: 8px;">
                MITRE ATT&CK Reference
            </h4>
            <a href="https://attack.mitre.org/techniques/${technique.technique_id.replace('.', '/')}/" 
               target="_blank" rel="noopener noreferrer"
               style="color: var(--text-accent); font-size: 0.82rem; text-decoration: none;">
                View on attack.mitre.org →
            </a>
        </div>
    `;
}
