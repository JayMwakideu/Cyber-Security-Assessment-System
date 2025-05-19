document.addEventListener('DOMContentLoaded', function () {
    // Mobile/Web Compliance Pie Chart
    const mobileWebCtx = document.getElementById('mobileWebChart').getContext('2d');
    new Chart(mobileWebCtx, {
        type: 'pie',
        data: {
            labels: mobileWebData.map(item => item.compliance_status),
            datasets: [{
                data: mobileWebData.map(item => item.count),
                backgroundColor: ['#3B82F6', '#1E3A8A', '#93C5FD'],
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: { position: 'top' },
            }
        }
    });

    // API Compliance Pie Chart
    const apiCtx = document.getElementById('apiChart').getContext('2d');
    new Chart(apiCtx, {
        type: 'pie',
        data: {
            labels: apiData.map(item => item.compliance_status),
            datasets: [{
                data: apiData.map(item => item.count),
                backgroundColor: ['#3B82F6', '#1E3A8A', '#93C5FD'],
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: { position: 'top' },
            }
        }
    });

    // Maturity Levels Pie Chart
    const maturityCtx = document.getElementById('maturityChart').getContext('2d');
    new Chart(maturityCtx, {
        type: 'pie',
        data: {
            labels: maturityData.map(item => item.maturity_level),
            datasets: [{
                data: maturityData.map(item => item.count),
                backgroundColor: ['#3B82F6', '#1E3A8A', '#93C5FD', '#BFDBFE', '#DBEAFE'],
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: { position: 'top' },
            }
        }
    });

    // Phishing Awareness Pie Chart
    const phishingCtx = document.getElementById('phishingChart').getContext('2d');
    new Chart(phishingCtx, {
        type: 'pie',
        data: {
            labels: phishingData.map(item => item.awareness_level),
            datasets: [{
                data: phishingData.map(item => item.count),
                backgroundColor: ['#3B82F6', '#1E3A8A', '#93C5FD'],
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: { position: 'top' },
            }
        }
    });
});