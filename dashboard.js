// dashboard.js
document.addEventListener('DOMContentLoaded', function() {
    // Toggle Sidebar
    document.getElementById('sidebarToggle').addEventListener('click', function() {
        document.querySelector('.sidebar').classList.toggle('collapsed');
        document.querySelector('.main-content').classList.toggle('expanded');
    });

    // Load form data from localStorage
    const formData = {};
    for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        formData[key] = localStorage.getItem(key);
    }

    // Update dashboard elements
    updateDashboardData(formData);
    createDonutChart(formData);
});

function updateDashboardData(data) {
    // Update quick stats
    document.getElementById('riskLevel').textContent = data.residual_risk || 'N/A';
    document.getElementById('threatCount').textContent = data.threat_category ? '1 Active' : 'None';
    document.getElementById('controlCount').textContent = data.existing_controls || 'N/A';

    // Update system details
    document.getElementById('assetName').textContent = data.asset_name || 'N/A';
    document.getElementById('assetType').textContent = data.asset_type || 'N/A';
    document.getElementById('systemOwner').textContent = data.system_owner || 'N/A';

    // Update threat assessment
    document.getElementById('threatSource').textContent = data.threat_source || 'N/A';
    document.getElementById('vulnerabilityLevel').textContent = data.exploitability_level || 'N/A';
    document.getElementById('impactLevel').textContent = data.impact_level || 'N/A';
}

function createDonutChart(data) {
    const ctx = document.createElement('canvas');
    document.getElementById('donutChart').appendChild(ctx);

    new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Impact', 'Likelihood', 'Residual Risk'],
            datasets: [{
                data: [
                    getRiskValue(data.impact_level),
                    getRiskValue(data.likelihood_level),
                    getRiskValue(data.residual_risk)
                ],
                backgroundColor: ['#4a90e2', '#2ecc71', '#e74c3c']
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom'
                }
            },
            cutout: '70%'
        }
    });
}

function getRiskValue(level) {
    const values = {
        'Very Low': 20,
        'Low': 40,
        'Medium': 60,
        'High': 80,
        'Very High': 100
    };
    return values[level] || 0;
}