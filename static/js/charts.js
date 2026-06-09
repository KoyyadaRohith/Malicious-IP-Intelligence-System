// Chart.js visualizations for Threat Intelligence dashboard overview

function initDashboardCharts() {
    // 1. Threat Distribution Chart (Doughnut)
    const distributionCtx = document.getElementById('threatDistributionChart');
    if (distributionCtx && window.threatDistributionData) {
        new Chart(distributionCtx, {
            type: 'doughnut',
            data: {
                labels: ['Safe', 'Suspicious', 'Malicious'],
                datasets: [{
                    data: [
                        window.threatDistributionData.safe || 0,
                        window.threatDistributionData.suspicious || 0,
                        window.threatDistributionData.malicious || 0
                    ],
                    backgroundColor: [
                        '#10b981', // safe
                        '#f59e0b', // suspicious
                        '#ff0055'  // malicious
                    ],
                    borderColor: '#060913',
                    borderWidth: 2,
                    hoverOffset: 4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            color: '#94a3b8',
                            font: {
                                family: 'Outfit',
                                size: 12
                            },
                            padding: 15
                        }
                    }
                },
                cutout: '70%'
            }
        });
    }

    // 2. Investigation Trends Chart (Line)
    const trendsCtx = document.getElementById('investigationTrendsChart');
    if (trendsCtx && window.trendData) {
        new Chart(trendsCtx, {
            type: 'line',
            data: {
                labels: window.trendData.labels || [],
                datasets: [{
                    label: 'Queries',
                    data: window.trendData.counts || [],
                    borderColor: '#00f0ff',
                    backgroundColor: 'rgba(0, 240, 255, 0.05)',
                    borderWidth: 2,
                    fill: true,
                    tension: 0.4,
                    pointBackgroundColor: '#00f0ff',
                    pointBorderColor: '#060913',
                    pointBorderWidth: 2,
                    pointRadius: 4,
                    pointHoverRadius: 6
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        display: false
                    }
                },
                scales: {
                    x: {
                        grid: {
                            color: 'rgba(0, 240, 255, 0.03)',
                            drawBorder: false
                        },
                        ticks: {
                            color: '#94a3b8',
                            font: {
                                family: 'Outfit',
                                size: 10
                            }
                        }
                    },
                    y: {
                        grid: {
                            color: 'rgba(0, 240, 255, 0.03)',
                            drawBorder: false
                        },
                        ticks: {
                            color: '#94a3b8',
                            font: {
                                family: 'Outfit',
                                size: 10
                            },
                            stepSize: 1
                        },
                        beginAtZero: true
                    }
                }
            }
        });
    }
}

document.addEventListener('DOMContentLoaded', initDashboardCharts);
