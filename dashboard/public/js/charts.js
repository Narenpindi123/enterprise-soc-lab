/**
 * Enterprise SOC Dashboard - Chart Visualizations
 * Creates all Chart.js charts for the security overview dashboard.
 */

// Chart.js default configuration
Chart.defaults.color = '#94a3b8';
Chart.defaults.borderColor = 'rgba(255, 255, 255, 0.05)';
Chart.defaults.font.family = "'Inter', sans-serif";
Chart.defaults.font.size = 11;

const chartInstances = {};

function initCharts() {
    createSeverityChart();
    createTacticsChart();
    createLoginsChart();
    createSourcesChart();
    createDNSChart();
}

// ========================================
// Alert Severity Distribution (Doughnut)
// ========================================

function createSeverityChart() {
    const ctx = document.getElementById('chart-severity');
    if (!ctx) return;
    if (chartInstances.severity) chartInstances.severity.destroy();

    const severities = statsData.alerts_by_severity || {};
    const data = {
        labels: ['Critical', 'High', 'Medium', 'Low'],
        datasets: [{
            data: [
                severities.CRITICAL || 0,
                severities.HIGH || 0,
                severities.MEDIUM || 0,
                severities.LOW || 0
            ],
            backgroundColor: [
                'rgba(239, 68, 68, 0.85)',
                'rgba(249, 115, 22, 0.85)',
                'rgba(234, 179, 8, 0.85)',
                'rgba(34, 197, 94, 0.85)'
            ],
            borderColor: [
                'rgba(239, 68, 68, 1)',
                'rgba(249, 115, 22, 1)',
                'rgba(234, 179, 8, 1)',
                'rgba(34, 197, 94, 1)'
            ],
            borderWidth: 2,
            hoverOffset: 8,
            spacing: 3
        }]
    };

    chartInstances.severity = new Chart(ctx, {
        type: 'doughnut',
        data,
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '65%',
            plugins: {
                legend: {
                    position: 'right',
                    labels: {
                        usePointStyle: true,
                        pointStyle: 'circle',
                        padding: 16,
                        font: { size: 11, weight: '500' }
                    }
                },
                tooltip: {
                    backgroundColor: '#1a1f35',
                    titleColor: '#e2e8f0',
                    bodyColor: '#94a3b8',
                    borderColor: '#334155',
                    borderWidth: 1,
                    cornerRadius: 8,
                    padding: 12
                }
            }
        }
    });
}

// ========================================
// Alerts by MITRE ATT&CK Tactic (Bar)
// ========================================

function createTacticsChart() {
    const ctx = document.getElementById('chart-tactics');
    if (!ctx) return;
    if (chartInstances.tactics) chartInstances.tactics.destroy();

    const tactics = statsData.alerts_by_tactic || {};
    const labels = Object.keys(tactics);
    const values = Object.values(tactics);

    const colors = labels.map((_, i) => {
        const hue = 240 + (i * 30);
        return `hsla(${hue % 360}, 70%, 60%, 0.8)`;
    });

    chartInstances.tactics = new Chart(ctx, {
        type: 'bar',
        data: {
            labels,
            datasets: [{
                label: 'Alerts',
                data: values,
                backgroundColor: colors,
                borderColor: colors.map(c => c.replace('0.8', '1')),
                borderWidth: 1,
                borderRadius: 6,
                barThickness: 28
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            indexAxis: 'y',
            plugins: {
                legend: { display: false },
                tooltip: {
                    backgroundColor: '#1a1f35',
                    borderColor: '#334155',
                    borderWidth: 1,
                    cornerRadius: 8,
                    padding: 12
                }
            },
            scales: {
                x: {
                    grid: { color: 'rgba(255,255,255,0.03)' },
                    ticks: { stepSize: 1 }
                },
                y: {
                    grid: { display: false },
                    ticks: { font: { size: 10, weight: '500' } }
                }
            }
        }
    });
}

// ========================================
// Failed Login Attempts Over Time (Line)
// ========================================

function createLoginsChart() {
    const ctx = document.getElementById('chart-logins');
    if (!ctx) return;
    if (chartInstances.logins) chartInstances.logins.destroy();

    // Aggregate failed login events by hour
    const authFailures = eventsData.filter(e => e.event_type === 'authentication_failure');
    const hourBuckets = {};

    authFailures.forEach(e => {
        if (!e.timestamp) return;
        const date = new Date(e.timestamp);
        const hourKey = `${date.getMonth() + 1}/${date.getDate()} ${String(date.getHours()).padStart(2, '0')}:00`;
        hourBuckets[hourKey] = (hourBuckets[hourKey] || 0) + 1;
    });

    const sortedKeys = Object.keys(hourBuckets).sort();
    const values = sortedKeys.map(k => hourBuckets[k]);

    chartInstances.logins = new Chart(ctx, {
        type: 'line',
        data: {
            labels: sortedKeys,
            datasets: [{
                label: 'Failed Logins',
                data: values,
                borderColor: 'rgba(239, 68, 68, 0.9)',
                backgroundColor: 'rgba(239, 68, 68, 0.08)',
                fill: true,
                tension: 0.4,
                pointRadius: 4,
                pointHoverRadius: 7,
                pointBackgroundColor: 'rgba(239, 68, 68, 1)',
                pointBorderColor: '#0a0e1a',
                pointBorderWidth: 2,
                borderWidth: 2.5
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    labels: { usePointStyle: true, pointStyle: 'circle' }
                },
                tooltip: {
                    backgroundColor: '#1a1f35',
                    borderColor: '#334155',
                    borderWidth: 1,
                    cornerRadius: 8,
                    padding: 12
                }
            },
            scales: {
                x: {
                    grid: { color: 'rgba(255,255,255,0.03)' },
                    ticks: { maxRotation: 45, font: { size: 10 } }
                },
                y: {
                    grid: { color: 'rgba(255,255,255,0.03)' },
                    beginAtZero: true,
                    ticks: { stepSize: 10 }
                }
            },
            interaction: {
                intersect: false,
                mode: 'index'
            }
        }
    });
}

// ========================================
// Events by Log Source (Polar Area)
// ========================================

function createSourcesChart() {
    const ctx = document.getElementById('chart-sources');
    if (!ctx) return;
    if (chartInstances.sources) chartInstances.sources.destroy();

    const sourceCounts = {};
    eventsData.forEach(e => {
        const src = e.source || 'unknown';
        sourceCounts[src] = (sourceCounts[src] || 0) + 1;
    });

    const labels = Object.keys(sourceCounts);
    const values = Object.values(sourceCounts);

    const sourceColors = {
        'linux_auth': 'rgba(34, 197, 94, 0.7)',
        'windows_security': 'rgba(59, 130, 246, 0.7)',
        'windows_sysmon': 'rgba(99, 102, 241, 0.7)',
        'aws_cloudtrail': 'rgba(249, 115, 22, 0.7)',
        'aws_s3': 'rgba(239, 68, 68, 0.7)',
        'dns': 'rgba(234, 179, 8, 0.7)',
        'proxy': 'rgba(168, 85, 247, 0.7)',
    };

    const colors = labels.map(l => sourceColors[l] || 'rgba(148, 163, 184, 0.7)');

    chartInstances.sources = new Chart(ctx, {
        type: 'polarArea',
        data: {
            labels: labels.map(l => l.replace('_', ' ').replace(/\b\w/g, c => c.toUpperCase())),
            datasets: [{
                data: values,
                backgroundColor: colors,
                borderColor: colors.map(c => c.replace('0.7', '1')),
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'right',
                    labels: {
                        usePointStyle: true,
                        pointStyle: 'rectRounded',
                        padding: 12,
                        font: { size: 10 }
                    }
                },
                tooltip: {
                    backgroundColor: '#1a1f35',
                    borderColor: '#334155',
                    borderWidth: 1,
                    cornerRadius: 8
                }
            },
            scales: {
                r: {
                    grid: { color: 'rgba(255,255,255,0.03)' },
                    ticks: { display: false }
                }
            }
        }
    });
}

// ========================================
// DNS Exfiltration Indicators (Bar)
// ========================================

function createDNSChart() {
    const ctx = document.getElementById('chart-dns');
    if (!ctx) return;
    if (chartInstances.dns) chartInstances.dns.destroy();

    const dnsEvents = eventsData.filter(e => e.source === 'dns');
    const normalQueries = dnsEvents.filter(e => !e.details?.suspicious).length;
    const suspiciousQueries = dnsEvents.filter(e => e.details?.suspicious).length;

    // Also get proxy exfil data
    const proxyEvents = eventsData.filter(e => e.source === 'proxy');
    const normalWeb = proxyEvents.filter(e => !e.details?.suspicious).length;
    const suspiciousWeb = proxyEvents.filter(e => e.details?.suspicious).length;

    chartInstances.dns = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: ['DNS Queries', 'HTTP Requests'],
            datasets: [
                {
                    label: 'Normal',
                    data: [normalQueries, normalWeb],
                    backgroundColor: 'rgba(34, 197, 94, 0.6)',
                    borderColor: 'rgba(34, 197, 94, 1)',
                    borderWidth: 1,
                    borderRadius: 6
                },
                {
                    label: 'Suspicious',
                    data: [suspiciousQueries, suspiciousWeb],
                    backgroundColor: 'rgba(239, 68, 68, 0.6)',
                    borderColor: 'rgba(239, 68, 68, 1)',
                    borderWidth: 1,
                    borderRadius: 6
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    labels: { usePointStyle: true, pointStyle: 'rectRounded', padding: 14 }
                },
                tooltip: {
                    backgroundColor: '#1a1f35',
                    borderColor: '#334155',
                    borderWidth: 1,
                    cornerRadius: 8
                }
            },
            scales: {
                x: { grid: { display: false } },
                y: {
                    grid: { color: 'rgba(255,255,255,0.03)' },
                    beginAtZero: true
                }
            }
        }
    });
}
