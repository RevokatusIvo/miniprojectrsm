// dashboard.js
document.addEventListener('DOMContentLoaded', function() {
    // Get assessment ID from URL
    const pathParts = window.location.pathname.split('/');
    const assessmentId = pathParts[pathParts.length - 1];

    // Toggle Sidebar
    document.getElementById('sidebarToggle').addEventListener('click', function() {
        document.querySelector('.sidebar').classList.toggle('collapsed');
        document.querySelector('.main-content').classList.toggle('expanded');
    });

    // Fetch assessment data
    fetchAssessmentData(assessmentId);
});

async function fetchAssessmentData(assessmentId) {
    try {
        const response = await fetch(`/assessment/${assessmentId}`);
        const data = await response.json();
        
        // Update dashboard elements
        updateDashboardData(data);
        createDonutChart(data);
        
        // Update page title
        document.getElementById('assetTitle').textContent = 
            `Dashboard - ${data.asset_name}`;
    } catch (error) {
        console.error('Error fetching assessment data:', error);
        alert('Error loading dashboard data. Please try again.');
    }
}

function calculateRiskLevel(likelihood, impact) {
    // Convert likelihood to numerical value
    const likelihoodValues = {
        'High': 1.0,
        'Medium': 0.5,
        'Low': 0.1
    };

    // Convert impact to numerical value
    const impactValues = {
        'High': 100,
        'Medium': 50,
        'Low': 10
    };

    const likelihoodValue = likelihoodValues[likelihood] || 0;
    const impactValue = impactValues[impact] || 0;
    
    // Calculate risk score
    const riskScore = impactValue * likelihoodValue;
    
    // Determine risk level based on score
    if (riskScore > 50) return 'High';
    if (riskScore > 10) return 'Medium';
    return 'Low';
}

function updateDashboardData(data) {
    // Calculate overall risk level based on likelihood and impact
    const calculatedRisk = calculateRiskLevel(data.threat_level, data.impact_level);
    
    // Update quick stats
    document.getElementById('riskLevel').textContent = calculatedRisk;
    document.getElementById('riskLevel').className = `risk-${calculatedRisk.toLowerCase()}`;
    
    // Count threats
    const hasThreat = data.details.threat_category ? '1 Active' : 'None';
    document.getElementById('threatCount').textContent = hasThreat;
    
    // Show controls
    document.getElementById('controlCount').textContent = 
        data.details.existing_controls || 'None';

    // Update system details
    document.getElementById('assetName').textContent = data.asset_name || 'N/A';
    document.getElementById('assetType').textContent = data.asset_type || 'N/A';
    document.getElementById('systemOwner').textContent = data.system_owner || 'N/A';

    // Update threat assessment
    document.getElementById('threatSource').textContent = 
        data.details.threat_source || 'N/A';
    document.getElementById('vulnerabilityLevel').textContent = 
        data.details.vulnerability_category || 'N/A';
    document.getElementById('impactLevel').textContent = data.impact_level || 'N/A';
}

function getRiskValue(level) {
    // Simplified risk values based on the matrix
    const values = {
        'Low': 10,
        'Medium': 50,
        'High': 100
    };
    return values[level] || 0;
}

function createDonutChart(data) {
    const ctx = document.getElementById('donutChart').getContext('2d');
    
    // Clear any existing chart
    if (window.riskChart) {
        window.riskChart.destroy();
    }

    // Calculate the risk level
    const calculatedRisk = calculateRiskLevel(data.threat_level, data.impact_level);

    window.riskChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Impact', 'Likelihood'],
            datasets: [{
                data: [
                    getRiskValue(data.impact_level),
                    getRiskValue(data.threat_level),
                ],
                backgroundColor: [
                    '#4a90e2',  // Impact - Blue
                    '#2ecc71',  // Likelihood - Green
                ]
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