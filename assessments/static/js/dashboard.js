document.addEventListener('DOMContentLoaded', function () {
    // Helper function to prepare chart data for compliance (pie charts)
    function prepareChartData(data, key, labelsMap) {
        const counts = {};
        data.forEach(item => {
            const label = labelsMap[item[key]] || item[key];
            counts[label] = (counts[label] || 0) + item.count;
        });
        return {
            labels: Object.keys(counts),
            values: Object.values(counts)
        };
    }

    // Mobile/Web Compliance Chart
    const mobileWebCtx = document.getElementById('mobileWebChart').getContext('2d');
    const mobileWebChartData = prepareChartData(mobileWebData, 'compliance_status', {
        'Compliant': 'Compliant',
        'Non-Compliant': 'Non-Compliant',
        'Partial': 'Partial'
    });
    new Chart(mobileWebCtx, {
        type: 'pie',
        data: {
            labels: mobileWebChartData.labels,
            datasets: [{
                data: mobileWebChartData.values,
                backgroundColor: ['#34D399', '#F87171', '#FBBF24'],
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: { position: 'top' }
            }
        }
    });

    // API Compliance Chart
    const apiCtx = document.getElementById('apiChart').getContext('2d');
    const apiChartData = prepareChartData(apiData, 'compliance_status', {
        'Compliant': 'Compliant',
        'Non-Compliant': 'Non-Compliant',
        'Partial': 'Partial'
    });
    new Chart(apiCtx, {
        type: 'pie',
        data: {
            labels: apiChartData.labels,
            datasets: [{
                data: apiChartData.values,
                backgroundColor: ['#34D399', '#F87171', '#FBBF24'],
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: { position: 'top' }
            }
        }
    });

    // Firewall Compliance Chart
    const firewallCtx = document.getElementById('firewallChart').getContext('2d');
    const firewallChartData = prepareChartData(firewallData, 'compliance_status', {
        'Compliant': 'Compliant',
        'Non-Compliant': 'Non-Compliant',
        'Partial': 'Partial'
    });
    new Chart(firewallCtx, {
        type: 'pie',
        data: {
            labels: firewallChartData.labels,
            datasets: [{
                data: firewallChartData.values,
                backgroundColor: ['#34D399', '#F87171', '#FBBF24'],
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: { position: 'top' }
            }
        }
    });

    // NIST Compliance Chart
    const nistCtx = document.getElementById('nistChart').getContext('2d');
    const nistChartData = prepareChartData(nistData, 'compliance_status', {
        'Compliant': 'Compliant',
        'Non-Compliant': 'Non-Compliant',
        'Partial': 'Partial'
    });
    new Chart(nistCtx, {
        type: 'pie',
        data: {
            labels: nistChartData.labels,
            datasets: [{
                data: nistChartData.values,
                backgroundColor: ['#34D399', '#F87171', '#FBBF24'],
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: { position: 'top' }
            }
        }
    });

    // Asset Inventory Bar Chart
    const assetInventoryCtx = document.getElementById('assetInventoryChart').getContext('2d');
    new Chart(assetInventoryCtx, {
        type: 'bar',
        data: {
            labels: ['Laptops', 'Mobile Devices', 'Workstations', 'Physical Servers', 'Virtual Servers', 'Cloud Services', 'Core Systems'],
            datasets: [{
                label: 'Asset Count',
                data: [
                    assetInventoryData.laptops,
                    assetInventoryData.mobile_devices,
                    assetInventoryData.workstations,
                    assetInventoryData.physical_servers,
                    assetInventoryData.virtual_servers,
                    assetInventoryData.cloud_services,
                    assetInventoryData.core_systems
                ],
                backgroundColor: '#60A5FA',
                borderColor: '#2563EB',
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            scales: {
                y: {
                    beginAtZero: true,
                    title: { display: true, text: 'Count' }
                },
                x: {
                    title: { display: true, text: 'Asset Type' }
                }
            },
            plugins: {
                legend: { display: false }
            }
        }
    });

    // Access Control Chart
    const accessControlCtx = document.getElementById('accessControlChart').getContext('2d');
    const accessControlChartData = prepareChartData(accessControlData, 'compliance_status', {
        'Compliant': 'Compliant',
        'Non-Compliant': 'Non-Compliant',
        'Partial': 'Partial'
    });
    new Chart(accessControlCtx, {
        type: 'pie',
        data: {
            labels: accessControlChartData.labels,
            datasets: [{
                data: accessControlChartData.values,
                backgroundColor: ['#34D399', '#F87171', '#FBBF24'],
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: { position: 'top' }
            }
        }
    });

    // Network Security Chart
    const networkSecurityCtx = document.getElementById('networkSecurityChart').getContext('2d');
    const networkSecurityChartData = prepareChartData(networkSecurityData, 'compliance_status', {
        'Compliant': 'Compliant',
        'Non-Compliant': 'Non-Compliant',
        'Partial': 'Partial'
    });
    new Chart(networkSecurityCtx, {
        type: 'pie',
        data: {
            labels: networkSecurityChartData.labels,
            datasets: [{
                data: networkSecurityChartData.values,
                backgroundColor: ['#34D399', '#F87171', '#FBBF24'],
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: { position: 'top' }
            }
        }
    });

    // Incident Response Chart
    const incidentResponseCtx = document.getElementById('incidentResponseChart').getContext('2d');
    const incidentResponseChartData = prepareChartData(incidentResponseData, 'compliance_status', {
        'Compliant': 'Compliant',
        'Non-Compliant': 'Non-Compliant',
        'Partial': 'Partial'
    });
    new Chart(incidentResponseCtx, {
        type: 'pie',
        data: {
            labels: incidentResponseChartData.labels,
            datasets: [{
                data: incidentResponseChartData.values,
                backgroundColor: ['#34D399', '#F87171', '#FBBF24'],
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: { position: 'top' }
            }
        }
    });

    // Maturity Levels Chart
    const maturityCtx = document.getElementById('maturityChart').getContext('2d');
    const maturityChartData = prepareChartData(maturityData, 'maturity_level', {});
    new Chart(maturityCtx, {
        type: 'pie',
        data: {
            labels: maturityChartData.labels,
            datasets: [{
                data: maturityChartData.values,
                backgroundColor: ['#A78BFA', '#F472B6', '#FBBF24', '#34D399', '#60A5FA', '#6EE7B7'],
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: { position: 'top' }
            }
        }
    });

    // Phishing Awareness Chart
    const phishingCtx = document.getElementById('phishingChart').getContext('2d');
    const phishingChartData = prepareChartData(phishingData, 'awareness_level', {});
    new Chart(phishingCtx, {
        type: 'pie',
        data: {
            labels: phishingChartData.labels,
            datasets: [{
                data: phishingChartData.values,
                backgroundColor: ['#34D399', '#FBBF24', '#F87171'],
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: { position: 'top' }
            }
        }
    });

    // Compliance Trend Chart
    const trendCtx = document.getElementById('complianceTrendChart').getContext('2d');
    new Chart(trendCtx, {
        type: 'line',
        data: {
            labels: complianceTrendData.map(item => item.month),
            datasets: [
                {
                    label: 'Mobile/Web Compliance (%)',
                    data: complianceTrendData.map(item => item.mobile_web),
                    borderColor: '#34D399',
                    fill: false,
                    tension: 0.1
                },
                {
                    label: 'API Compliance (%)',
                    data: complianceTrendData.map(item => item.api),
                    borderColor: '#60A5FA',
                    fill: false,
                    tension: 0.1
                }
            ]
        },
        options: {
            responsive: true,
            scales: {
                y: {
                    beginAtZero: true,
                    max: 100,
                    title: { display: true, text: 'Compliance Percentage (%)' }
                },
                x: {
                    title: { display: true, text: 'Month' }
                }
            },
            plugins: {
                legend: { position: 'top' }
            }
        }
    });
});