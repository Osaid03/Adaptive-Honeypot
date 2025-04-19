<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Anomaly Review Interface - Adaptive Honeypot</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.3/font/bootstrap-icons.css">
    <style>
        :root {
            --primary-bg: #111927;
            --secondary-bg: #1a2332;
            --card-bg: #1e293b;
            --accent-color: #3b82f6;
            --text-primary: #e2e8f0;
            --text-secondary: #94a3b8;
            --border-color: #2d3748;
            --success-color: #10b981;
            --warning-color: #f59e0b;
            --danger-color: #ef4444;
            --info-color: #3b82f6;
        }

        body {
            background-color: var(--primary-bg);
            color: var(--text-primary);
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 0;
            overflow-x: hidden;
        }

        .container {
            max-width: 1200px;
            padding: 2rem;
        }

        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 2rem;
        }

        .header h1 {
            display: flex;
            align-items: center;
            gap: 1rem;
            color: var(--accent-color);
            font-size: 2rem;
        }

        .card {
            background-color: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 0.5rem;
            margin-bottom: 1.5rem;
        }

        .card-header {
            background-color: var(--secondary-bg);
            border-bottom: 1px solid var(--border-color);
            padding: 1rem;
            font-weight: bold;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .card-body {
            padding: 1.5rem;
        }

        .btn-primary {
            background-color: var(--accent-color);
            border-color: var(--accent-color);
        }

        .btn-success {
            background-color: var(--success-color);
            border-color: var(--success-color);
        }

        .btn-warning {
            background-color: var(--warning-color);
            border-color: var(--warning-color);
        }

        .btn-danger {
            background-color: var(--danger-color);
            border-color: var(--danger-color);
        }

        .btn-outline-primary {
            color: var(--accent-color);
            border-color: var(--accent-color);
        }

        .btn-outline-primary:hover {
            background-color: var(--accent-color);
            color: white;
        }

        .table {
            color: var(--text-primary);
        }

        .table thead th {
            border-color: var(--border-color);
            background-color: var(--secondary-bg);
        }

        .table tbody td {
            border-color: var(--border-color);
        }

        .form-select {
            background-color: var(--secondary-bg);
            color: var(--text-primary);
            border-color: var(--border-color);
        }

        .form-select:focus {
            border-color: var(--accent-color);
            box-shadow: 0 0 0 0.25rem rgba(59, 130, 246, 0.25);
        }

        .form-check-input {
            background-color: var(--secondary-bg);
            border-color: var(--border-color);
        }

        .form-check-input:checked {
            background-color: var(--accent-color);
            border-color: var(--accent-color);
        }

        .toast-container {
            position: fixed;
            top: 1rem;
            right: 1rem;
            z-index: 1050;
        }

        .toast {
            background-color: var(--card-bg);
            color: var(--text-primary);
            border: 1px solid var(--border-color);
        }

        .toast-header {
            background-color: var(--secondary-bg);
            color: var(--text-primary);
            border-bottom: 1px solid var(--border-color);
        }

        .back-btn {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            color: var(--text-primary);
            text-decoration: none;
            padding: 0.5rem 1rem;
            border-radius: 0.25rem;
            background-color: var(--secondary-bg);
            transition: background-color 0.3s;
        }

        .back-btn:hover {
            background-color: var(--card-bg);
            color: var(--text-primary);
        }

        .spinner-border {
            width: 1rem;
            height: 1rem;
            margin-right: 0.5rem;
        }

        .btn-loading {
            pointer-events: none;
            opacity: 0.8;
        }

        .empty-state {
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            padding: 3rem;
            text-align: center;
            color: var(--text-secondary);
        }

        .empty-state i {
            font-size: 3rem;
            margin-bottom: 1rem;
        }

        .empty-state p {
            font-size: 1.1rem;
            margin-bottom: 0.5rem;
        }

        .empty-state small {
            max-width: 400px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>
                <i class="bi bi-search"></i>
                Anomaly Review Interface
            </h1>
            <a href="/" class="back-btn">
                <i class="bi bi-arrow-left"></i>
                Back to Dashboard
            </a>
        </div>

        <div class="card">
            <div class="card-header">
                <i class="bi bi-bar-chart-line"></i> Statistics
            </div>
            <div class="card-body">
                <p>Total anomalies to review: <span id="anomaly-count">{{ anomalies|length }}</span></p>
            </div>
        </div>

        <div class="card">
            <div class="card-header">
                <i class="bi bi-tags"></i> Batch Actions
            </div>
            <div class="card-body">
                <div class="d-flex gap-2">
                    <button id="set-all-benign" class="btn btn-outline-success">Set All as BENIGN</button>
                    <button id="set-all-suspicious" class="btn btn-outline-warning">Set All as SUSPICIOUS</button>
                    <button id="set-all-malicious" class="btn btn-outline-danger">Set All as MALICIOUS</button>
                </div>
            </div>
        </div>

        <div id="anomalies-container">
            {% if anomalies|length > 0 %}
            <div class="table-responsive">
                <table class="table">
                    <thead>
                        <tr>
                            <th>Command</th>
                            <th>Label</th>
                        </tr>
                    </thead>
                    <tbody id="anomalies-table">
                        {% for command in anomalies %}
                        <tr data-command="{{ command }}">
                            <td>{{ command }}</td>
                            <td>
                                <select class="form-select label-select">
                                    <option value="" selected>Select label</option>
                                    <option value="BENIGN">BENIGN</option>
                                    <option value="SUSPICIOUS">SUSPICIOUS</option>
                                    <option value="MALICIOUS">MALICIOUS</option>
                                </select>
                            </td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
            <div class="d-flex justify-content-between mt-4">
                <button id="save-labels-btn" class="btn btn-success">
                    <i class="bi bi-save"></i> Save Labels
                </button>
                <div class="d-flex gap-2">
                    <button id="integrate-data-btn" class="btn btn-primary">
                        <i class="bi bi-database-add"></i> Integrate Labeled Data
                    </button>
                    <button id="retrain-model-btn" class="btn btn-warning">
                        <i class="bi bi-arrow-repeat"></i> Retrain Model
                    </button>
                </div>
            </div>
            {% else %}
            <div class="empty-state">
                <i class="bi bi-info-circle"></i>
                <p>No anomalies to review at this time.</p>
                <small>When the honeypot detects commands it doesn't recognize, they will appear here for you to review and label.</small>
            </div>
            {% endif %}
        </div>
    </div>

    <!-- Toast Container -->
    <div class="toast-container"></div>

    <!-- Scripts -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // DOM Elements
        const saveLabelsBtn = document.getElementById('save-labels-btn');
        const integrateDataBtn = document.getElementById('integrate-data-btn');
        const retrainModelBtn = document.getElementById('retrain-model-btn');
        const setAllBenignBtn = document.getElementById('set-all-benign');
        const setAllSuspiciousBtn = document.getElementById('set-all-suspicious');
        const setAllMaliciousBtn = document.getElementById('set-all-malicious');
        const anomaliesTable = document.getElementById('anomalies-table');
        const anomalyCount = document.getElementById('anomaly-count');

        // Store original button HTML for restoration after operations
        const saveLabelsOriginalHtml = saveLabelsBtn ? saveLabelsBtn.innerHTML : '';
        const integrateDataOriginalHtml = integrateDataBtn ? integrateDataBtn.innerHTML : '';
        const retrainModelOriginalHtml = retrainModelBtn ? retrainModelBtn.innerHTML : '';

        // Create Toast
        function createToast(title, message, type = 'info') {
            const toastContainer = document.querySelector('.toast-container');
            const toastId = 'toast-' + Date.now();
            const iconClass = type === 'success' ? 'bi-check-circle' :
                            type === 'warning' ? 'bi-exclamation-triangle' :
                            type === 'danger' ? 'bi-x-circle' : 'bi-info-circle';

            const toastHtml = `
                <div id="${toastId}" class="toast" role="alert" aria-live="assertive" aria-atomic="true">
                    <div class="toast-header">
                        <i class="bi ${iconClass} me-2"></i>
                        <strong class="me-auto">${title}</strong>
                        <small>Just now</small>
                        <button type="button" class="btn-close" data-bs-dismiss="toast" aria-label="Close"></button>
                    </div>
                    <div class="toast-body">
                        ${message}
                    </div>
                </div>
            `;

            toastContainer.insertAdjacentHTML('beforeend', toastHtml);
            const toastElement = document.getElementById(toastId);
            const toast = new bootstrap.Toast(toastElement, { autohide: true, delay: 5000 });
            toast.show();

            // Remove toast from DOM after it's hidden
            toastElement.addEventListener('hidden.bs.toast', () => {
                toastElement.remove();
            });
        }

        // Set Button Loading State
        function setButtonLoading(button, isLoading, originalHtml) {
            if (!button) return;

            if (isLoading) {
                button.innerHTML = `<span class="spinner-border" role="status" aria-hidden="true"></span> Loading...`;
                button.classList.add('btn-loading');
                button.disabled = true;
            } else {
                button.innerHTML = originalHtml;
                button.classList.remove('btn-loading');
                button.disabled = false;
            }
        }

        // Enable All Buttons
        function enableAllButtons() {
            if (saveLabelsBtn) {
                setButtonLoading(saveLabelsBtn, false, saveLabelsOriginalHtml);
            }
            if (integrateDataBtn) {
                setButtonLoading(integrateDataBtn, false, integrateDataOriginalHtml);
            }
            if (retrainModelBtn) {
                setButtonLoading(retrainModelBtn, false, retrainModelOriginalHtml);
            }
        }

        // Get Labels
        function getLabels() {
            const rows = anomaliesTable ? anomaliesTable.querySelectorAll('tr[data-command]') : [];
            const commands = [];
            const labels = [];

            rows.forEach(row => {
                const command = row.getAttribute('data-command');
                const labelSelect = row.querySelector('.label-select');
                const label = labelSelect.value;

                if (label) {
                    commands.push(command);
                    labels.push(label);
                }
            });

            return { commands, labels };
        }

        // Save Labels
        async function saveLabels() {
            if (!saveLabelsBtn) return;

            const { commands, labels } = getLabels();

            if (commands.length === 0) {
                createToast('Warning', 'Please select at least one label', 'warning');
                return;
            }

            try {
                setButtonLoading(saveLabelsBtn, true, saveLabelsOriginalHtml);

                const response = await fetch('/api/label', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ commands, labels })
                });

                const data = await response.json();

                if (data.success) {
                    createToast('Success', `Successfully labeled ${commands.length} commands`, 'success');
                } else {
                    createToast('Error', data.message, 'danger');
                }
            } catch (error) {
                createToast('Error', 'Failed to save labels: ' + error.message, 'danger');
            } finally {
                enableAllButtons();
            }
        }

        // Integrate Data
        async function integrateData() {
            if (!integrateDataBtn) return;

            try {
                setButtonLoading(integrateDataBtn, true, integrateDataOriginalHtml);

                const response = await fetch('/api/integrate', {
                    method: 'POST'
                });

                const data = await response.json();

                if (data.success) {
                    createToast('Success', data.message, 'success');
                } else {
                    createToast('Error', data.message, 'danger');
                }
            } catch (error) {
                createToast('Error', 'Failed to integrate data: ' + error.message, 'danger');
            } finally {
                enableAllButtons();
            }
        }

        // Retrain Model
        async function retrainModel() {
            if (!retrainModelBtn) return;

            try {
                setButtonLoading(retrainModelBtn, true, retrainModelOriginalHtml);

                const response = await fetch('/api/retrain', {
                    method: 'POST'
                });

                const data = await response.json();

                if (data.success) {
                    createToast('Success', data.message, 'success');
                } else {
                    createToast('Error', data.message, 'danger');
                }
            } catch (error) {
                createToast('Error', 'Failed to retrain model: ' + error.message, 'danger');
            } finally {
                enableAllButtons();
            }
        }

        // Set All Labels
        function setAllLabels(label) {
            const labelSelects = document.querySelectorAll('.label-select');
            labelSelects.forEach(select => {
                select.value = label;
            });
        }

        // Refresh Anomalies
        async function refreshAnomalies() {
            try {
                const response = await fetch('/api/anomalies');
                const data = await response.json();

                if (data.anomalies.length === 0) {
                    document.getElementById('anomalies-container').innerHTML = `
                        <div class="empty-state">
                            <i class="bi bi-info-circle"></i>
                            <p>No anomalies to review at this time.</p>
                            <small>When the honeypot detects commands it doesn't recognize, they will appear here for you to review and label.</small>
                        </div>
                    `;
                    anomalyCount.textContent = '0';
                    return;
                }

                // If we previously had no anomalies, rebuild the table structure
                if (!document.getElementById('anomalies-table')) {
                    document.getElementById('anomalies-container').innerHTML = `
                        <div class="table-responsive">
                            <table class="table">
                                <thead>
                                    <tr>
                                        <th>Command</th>
                                        <th>Label</th>
                                    </tr>
                                </thead>
                                <tbody id="anomalies-table"></tbody>
                            </table>
                        </div>
                        <div class="d-flex justify-content-between mt-4">
                            <button id="save-labels-btn" class="btn btn-success">
                                <i class="bi bi-save"></i> Save Labels
                            </button>
                            <div class="d-flex gap-2">
                                <button id="integrate-data-btn" class="btn btn-primary">
                                    <i class="bi bi-database-add"></i> Integrate Labeled Data
                                </button>
                                <button id="retrain-model-btn" class="btn btn-warning">
                                    <i class="bi bi-arrow-repeat"></i> Retrain Model
                                </button>
                            </div>
                        </div>
                    `;

                    // Re-get the elements
                    const saveLabelsBtn = document.getElementById('save-labels-btn');
                    const integrateDataBtn = document.getElementById('integrate-data-btn');
                    const retrainModelBtn = document.getElementById('retrain-model-btn');

                    // Add event listeners
                    if (saveLabelsBtn) saveLabelsBtn.addEventListener('click', saveLabels);
                    if (integrateDataBtn) integrateDataBtn.addEventListener('click', integrateData);
                    if (retrainModelBtn) retrainModelBtn.addEventListener('click', retrainModel);
                }

                const anomaliesTable = document.getElementById('anomalies-table');

                // Update the table with new anomalies
                let tableHtml = '';
                data.anomalies.forEach(command => {
                    tableHtml += `
                        <tr data-command="${command}">
                            <td>${command}</td>
                            <td>
                                <select class="form-select label-select">
                                    <option value="" selected>Select label</option>
                                    <option value="BENIGN">BENIGN</option>
                                    <option value="SUSPICIOUS">SUSPICIOUS</option>
                                    <option value="MALICIOUS">MALICIOUS</option>
                                </select>
                            </td>
                        </tr>
                    `;
                });

                anomaliesTable.innerHTML = tableHtml;
                anomalyCount.textContent = data.anomalies.length;

                if (data.anomalies.length > 0 && !document.querySelector('.toast')) {
                    createToast('New Anomalies', `${data.anomalies.length} anomalies available for review`, 'info');
                }
            } catch (error) {
                console.error('Error refreshing anomalies:', error);
            }
        }

        // Auto-refresh
        let refreshInterval;

        function startAutoRefresh() {
            stopAutoRefresh();
            refreshInterval = setInterval(refreshAnomalies, 30000); // Check every 30 seconds
        }

        function stopAutoRefresh() {
            if (refreshInterval) {
                clearInterval(refreshInterval);
            }
        }

        // Event Listeners
        document.addEventListener('DOMContentLoaded', function() {
            if (saveLabelsBtn) saveLabelsBtn.addEventListener('click', saveLabels);
            if (integrateDataBtn) integrateDataBtn.addEventListener('click', integrateData);
            if (retrainModelBtn) retrainModelBtn.addEventListener('click', retrainModel);

            if (setAllBenignBtn) setAllBenignBtn.addEventListener('click', () => setAllLabels('BENIGN'));
            if (setAllSuspiciousBtn) setAllSuspiciousBtn.addEventListener('click', () => setAllLabels('SUSPICIOUS'));
            if (setAllMaliciousBtn) setAllMaliciousBtn.addEventListener('click', () => setAllLabels('MALICIOUS'));

            if (refreshBtn) refreshBtn.addEventListener('click', refreshAnomalies);

            if (autoRefreshCheckbox) {
                autoRefreshCheckbox.addEventListener('change', function() {
                    if (this.checked) {
                        startAutoRefresh();
                    } else {
                        stopAutoRefresh();
                    }
                });

                // Start auto-refresh if checked by default
                if (autoRefreshCheckbox.checked) {
                    startAutoRefresh();
                }
            }
        });
    </script>
</body>
</html>