// dashboard.js
document.addEventListener('DOMContentLoaded', function() {
    // Donut Chart
    const donutCtx = document.createElement('canvas');
    document.getElementById('donutChart').appendChild(donutCtx);

    new Chart(donutCtx, {
        type: 'doughnut',
        data: {
            labels: ['High Risk', 'Medium Risk', 'Low Risk'],
            datasets: [{
                data: [30, 50, 20],
                backgroundColor: [
                    '#1e40af',
                    '#60a5fa',
                    '#93c5fd',
                ],
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        color: 'white'
                    }
                }
            },
            cutout: '70%'
        }
    });

    // Line Chart
    const lineCtx = document.createElement('canvas');
    document.getElementById('lineChart').appendChild(lineCtx);

    new Chart(lineCtx, {
        type: 'line',
        data: {
            labels: ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun'],
            datasets: [{
                label: 'Threats Detected',
                data: [12, 19, 15, 25, 22, 30],
                borderColor: '#60a5fa',
                tension: 0.4
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    labels: {
                        color: 'white'
                    }
                }
            },
            scales: {
                y: {
                    ticks: { color: 'white' }
                },
                x: {
                    ticks: { color: 'white' }
                }
            }
        }
    });

    // Bar Chart
    const barCtx = document.createElement('canvas');
    document.getElementById('barChart').appendChild(barCtx);

    new Chart(barCtx, {
        type: 'bar',
        data: {
            labels: ['Access Control', 'Encryption', 'Firewall', 'Backup'],
            datasets: [{
                label: 'Security Measures',
                data: [85, 90, 75, 95],
                backgroundColor: '#60a5fa'
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    labels: {
                        color: 'white'
                    }
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: { color: 'white' }
                },
                x: {
                    ticks: { color: 'white' }
                }
            }
        }
    });
});

// Add this to your JavaScript file
document.addEventListener('DOMContentLoaded', function() {
    const sidebar = document.getElementById('sidebar');
    const toggleBtn = document.getElementById('toggleSidebar');
    const mainContent = document.querySelector('.main-content');

    toggleBtn.addEventListener('click', function() {
        sidebar.classList.toggle('expanded');
        mainContent.classList.toggle('shifted');
    });
});