
import os
import json
import datetime
from rich.console import Console

from utils.logger import get_logger

logger = get_logger()

class ReportGenerator:
    """
    Generator for vulnerability scan reports in various formats.
    """
    
    def __init__(self, output_dir):

        self.output_dir = output_dir
        self.console = Console()
        
        # Create output directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)
        
        logger.info(f"Initialized report generator with output directory: {output_dir}")
    
    def generate_json_report(self, scan_result):

        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        report_filename = f"zerohuntai_report_{timestamp}.json"
        report_path = os.path.join(self.output_dir, report_filename)
        
        # Format the report
        report_data = {
            'scan_info': {
                'timestamp': scan_result['timestamp'],
                'target': scan_result['target'],
                'stats': scan_result['stats']
            },
            'vulnerabilities': scan_result['vulnerabilities'],
            'secrets': scan_result.get('secrets', [])
        }
        
        # Write the report to file
        with open(report_path, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        logger.info(f"Generated JSON report: {report_path}")
        return report_path
    
    def generate_html_report(self, scan_result):

        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        report_filename = f"zerohuntai_report_{timestamp}.html"
        report_path = os.path.join(self.output_dir, report_filename)
        
        # Get the current script directory
        current_dir = os.path.dirname(os.path.abspath(__file__))
        template_dir = os.path.join(os.path.dirname(current_dir), 'templates')
        template_path = os.path.join(template_dir, 'report_template.html')
        
        # Ensure the template directory exists
        os.makedirs(template_dir, exist_ok=True)
        
        # Create template if it doesn't exist
        if not os.path.exists(template_path):
            self._create_report_template(template_path)
        
        # Read the template
        with open(template_path, 'r') as f:
            template = f.read()
        
        # Sort vulnerabilities by severity
        vulnerabilities = sorted(
            scan_result['vulnerabilities'], 
            key=lambda x: {'High': 0, 'Medium': 1, 'Low': 2}.get(x['severity'], 3)
        )
        
        # Format the vulnerabilities for HTML with JSON data for modal
        vuln_html = ""
        for i, vuln in enumerate(vulnerabilities):
            severity_class = {
                'High': 'table-danger',
                'Medium': 'table-warning',
                'Low': 'table-info'
            }.get(vuln['severity'], 'table-secondary')
            
            # Prepare the vulnerability data for the modal
            modal_data = {
                'severity': vuln['severity'],
                'type': vuln['type'],
                'file': vuln['file'],
                'line': vuln['line'],
                'code': self._escape_html(vuln['code']),
                'description': vuln['description'],
                'ai_explanation': vuln.get('ai_explanation', 'No AI assessment available'),
                'remediation': vuln.get('remediation', 'Review the code and apply secure coding practices to address this vulnerability.')
            }
            
            # Encode the data for the onclick attribute
            encoded_data = json.dumps(modal_data).replace('"', '&quot;')
            
            vuln_html += f"""
            <tr class="vulnerability-row {severity_class}" onclick="showVulnerabilityDetail(decodeURIComponent('{encoded_data}'))">
                <td>{i+1}</td>
                <td><span class="badge rounded-pill bg-{severity_class.replace('table-', '')}">{vuln['severity']}</span></td>
                <td>{vuln['type']}</td>
                <td>{vuln['file']}</td>
                <td>{vuln['line']}</td>
                <td>{vuln['description'][:50]}{'...' if len(vuln['description']) > 50 else ''}</td>
                <td><button class="btn btn-sm btn-outline-primary">View Details</button></td>
            </tr>
            """
        
        # Format the secrets for HTML with improved styling
        secrets_html = ""
        for i, secret in enumerate(scan_result.get('secrets', [])):
            # Prepare the secret data for potential modal in the future
            secret_data = {
                'file': secret['file'],
                'line': secret['line'],
                'key': secret['key'],
                'value_preview': secret['value_preview'],
                'confidence': secret['confidence'],
                'context': secret.get('context', 'No context available')
            }
            
            # Encode the data for the onclick attribute
            encoded_data = json.dumps(secret_data).replace('"', '&quot;')
            
            confidence_badge = ""
            if secret.get('confidence') == 'High':
                confidence_badge = '<span class="badge rounded-pill bg-danger">High</span>'
            elif secret.get('confidence') == 'Medium':
                confidence_badge = '<span class="badge rounded-pill bg-warning text-dark">Medium</span>'
            else:
                confidence_badge = '<span class="badge rounded-pill bg-info text-dark">Low</span>'
            
            secrets_html += f"""
            <tr class="table-danger">
                <td>{i+1}</td>
                <td><i class="bi bi-file-earmark-text me-1"></i>{secret['file']}</td>
                <td>{secret['line']}</td>
                <td><code>{secret['key']}</code></td>
                <td><code>{secret['value_preview']}</code></td>
                <td>{confidence_badge}</td>
            </tr>
            """
        
        # Calculate statistics for the summary
        total_vulns = len(vulnerabilities)
        high_sev = sum(1 for vuln in vulnerabilities if vuln['severity'] == 'High')
        medium_sev = sum(1 for vuln in vulnerabilities if vuln['severity'] == 'Medium')
        low_sev = sum(1 for vuln in vulnerabilities if vuln['severity'] == 'Low')
        total_secrets = len(scan_result.get('secrets', []))
        
        # Replace placeholders in the template
        html_content = template.replace('{{TIMESTAMP}}', scan_result['timestamp'])
        html_content = html_content.replace('{{TARGET}}', scan_result['target'])
        html_content = html_content.replace('{{VULNERABILITIES}}', vuln_html)
        html_content = html_content.replace('{{SECRETS}}', secrets_html)
        html_content = html_content.replace('{{TOTAL_VULNERABILITIES}}', str(total_vulns))
        html_content = html_content.replace('{{HIGH_SEVERITY}}', str(high_sev))
        html_content = html_content.replace('{{MEDIUM_SEVERITY}}', str(medium_sev))
        html_content = html_content.replace('{{LOW_SEVERITY}}', str(low_sev))
        html_content = html_content.replace('{{TOTAL_SECRETS}}', str(total_secrets))
        html_content = html_content.replace('{{TOTAL_FILES}}', str(scan_result['stats']['total_files']))
        
        # Write the report to file
        with open(report_path, 'w') as f:
            f.write(html_content)
        
        logger.info(f"Generated HTML report: {report_path}")
        return report_path
    
    def _escape_html(self, text):

        if not text:
            return ""
        
        return (text
            .replace('&', '&amp;')
            .replace('<', '&lt;')
            .replace('>', '&gt;')
            .replace('"', '&quot;')
            .replace("'", '&#39;')
        )
    
    def _create_report_template(self, template_path):

        template = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ZeroHuntAI Vulnerability Scan Report</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.8.1/font/bootstrap-icons.css">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/chart.js@3.7.1/dist/chart.min.css">
    <style>
        :root {
            --primary-color: #0d6efd;
            --secondary-color: #6c757d;
            --success-color: #198754;
            --danger-color: #dc3545;
            --warning-color: #fd7e14;
            --info-color: #0dcaf0;
            --dark-color: #212529;
            --light-color: #f8f9fa;
        }
        
        body {
            padding-top: 0;
            padding-bottom: 3rem;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: #f5f5f7;
            color: #333;
        }
        
        .severity-high {
            color: var(--danger-color);
            font-weight: bold;
        }
        
        .severity-medium {
            color: var(--warning-color);
            font-weight: bold;
        }
        
        .severity-low {
            color: var(--info-color);
            font-weight: bold;
        }
        
        .banner {
            background: linear-gradient(135deg, #2a2a72 0%, #0d6efd 100%);
            color: white;
            padding: 2rem 0;
            margin-bottom: 2rem;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
        }
        
        .logo {
            font-size: 2.5rem;
            font-weight: 700;
            margin-bottom: 0.5rem;
        }
        
        .stat-card {
            text-align: center;
            padding: 1.5rem;
            border-radius: 10px;
            margin-bottom: 1.5rem;
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.05);
            transition: transform 0.3s ease;
            background-color: white;
        }
        
        .stat-card:hover {
            transform: translateY(-5px);
        }
        
        .stat-icon {
            font-size: 2rem;
            margin-bottom: 1rem;
        }
        
        .stat-number {
            font-size: 2.5rem;
            font-weight: 700;
            margin-bottom: 0.5rem;
        }
        
        .high-card .stat-icon {
            color: var(--danger-color);
        }
        
        .medium-card .stat-icon {
            color: var(--warning-color);
        }
        
        .low-card .stat-icon {
            color: var(--info-color);
        }
        
        .files-card .stat-icon {
            color: var(--primary-color);
        }
        
        .vulnerability-card {
            background-color: white;
            border-radius: 10px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.05);
            position: relative;
            overflow: hidden;
        }
        
        .vulnerability-card.high {
            border-left: 5px solid var(--danger-color);
        }
        
        .vulnerability-card.medium {
            border-left: 5px solid var(--warning-color);
        }
        
        .vulnerability-card.low {
            border-left: 5px solid var(--info-color);
        }
        
        .code-block {
            background-color: #f8f9fa;
            padding: 1rem;
            border-radius: 5px;
            font-family: 'Courier New', Courier, monospace;
            white-space: pre-wrap;
            word-break: break-all;
            margin: 1rem 0;
            border: 1px solid #e9ecef;
            position: relative;
        }
        
        .code-line-highlight {
            background-color: rgba(255, 220, 100, 0.3);
            display: block;
        }
        
        .card-header-tabs {
            margin-bottom: -1rem;
        }
        
        .nav-tabs .nav-link {
            border: none;
            color: var(--secondary-color);
            font-weight: 500;
        }
        
        .nav-tabs .nav-link.active {
            color: var(--primary-color);
            background-color: transparent;
            border-bottom: 3px solid var(--primary-color);
        }
        
        .filter-section {
            background-color: white;
            border-radius: 10px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.05);
        }
        
        .chart-container {
            position: relative;
            height: 250px;
            margin-bottom: 1.5rem;
        }
        
        .table-container {
            overflow-x: auto;
            background-color: white;
            border-radius: 10px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.05);
        }
        
        .vulnerability-details {
            display: none;
            background-color: #f8f9fa;
            padding: 1.5rem;
            border-radius: 5px;
            margin-top: 1rem;
        }
        
        .vulnerability-row {
            cursor: pointer;
        }
        
        .vulnerability-row:hover {
            background-color: rgba(13, 110, 253, 0.05);
        }
        
        .section-title {
            position: relative;
            padding-bottom: 0.5rem;
            margin-bottom: 1.5rem;
        }
        
        .section-title::after {
            content: '';
            position: absolute;
            bottom: 0;
            left: 0;
            width: 50px;
            height: 3px;
            background-color: var(--primary-color);
        }
        
        .ai-suggestion {
            background-color: rgba(13, 110, 253, 0.05);
            border-left: 3px solid var(--primary-color);
            padding: 1rem;
            margin-top: 1rem;
            border-radius: 5px;
        }
        
        .copy-btn {
            position: absolute;
            top: 0.5rem;
            right: 0.5rem;
            background-color: var(--light-color);
            border: none;
            border-radius: 3px;
            padding: 0.25rem 0.5rem;
            font-size: 0.8rem;
            cursor: pointer;
            transition: background-color 0.2s ease;
        }
        
        .copy-btn:hover {
            background-color: #e9ecef;
        }
        
        .badge-severity {
            font-size: 0.9rem;
            padding: 0.35rem 0.65rem;
        }
        
        .back-to-top {
            position: fixed;
            bottom: 1.5rem;
            right: 1.5rem;
            background-color: var(--primary-color);
            color: white;
            width: 45px;
            height: 45px;
            border-radius: 50%;
            display: flex;
            justify-content: center;
            align-items: center;
            cursor: pointer;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.2);
            transition: background-color 0.3s ease;
            z-index: 1000;
        }
        
        .back-to-top:hover {
            background-color: #0b5ed7;
        }
        
        @media (max-width: 768px) {
            .stat-card {
                margin-bottom: 1rem;
            }
        }
    </style>
</head>
<body>
    <div class="banner">
        <div class="container">
            <div class="row align-items-center">
                <div class="col-md-8">
                    <div class="logo">
                        <i class="bi bi-shield-check me-2"></i>
                        <span class="text-danger">Zero</span><span class="text-light">Hunt</span><span class="text-info">AI</span>
                    </div>
                    <h3>Vulnerability Scan Report</h3>
                    <p class="mb-0">AI-powered Zero-Day Vulnerability Detection</p>
                </div>
                <div class="col-md-4 text-end d-flex flex-column justify-content-center">
                    <div class="report-meta">
                        <p class="mb-1"><i class="bi bi-calendar3 me-2"></i><strong>Scan Date:</strong> {{TIMESTAMP}}</p>
                        <p class="mb-0"><i class="bi bi-folder me-2"></i><strong>Target:</strong> {{TARGET}}</p>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <div class="container">
        <!-- Summary Section -->
        <div class="row mb-4">
            <div class="col-12">
                <h2 class="section-title">Executive Summary</h2>
            </div>
        </div>
        
        <div class="row">
            <div class="col-md-8">
                <div class="chart-container">
                    <canvas id="severityChart"></canvas>
                </div>
            </div>
            <div class="col-md-4">
                <div class="chart-container">
                    <canvas id="filesChart"></canvas>
                </div>
            </div>
        </div>
        
        <div class="row">
            <div class="col-md-3">
                <div class="stat-card files-card">
                    <div class="stat-icon">
                        <i class="bi bi-file-earmark-code"></i>
                    </div>
                    <div class="stat-number">{{TOTAL_FILES}}</div>
                    <p>Files Scanned</p>
                </div>
            </div>
            <div class="col-md-3">
                <div class="stat-card high-card">
                    <div class="stat-icon">
                        <i class="bi bi-exclamation-triangle"></i>
                    </div>
                    <div class="stat-number severity-high">{{HIGH_SEVERITY}}</div>
                    <p>High Severity</p>
                </div>
            </div>
            <div class="col-md-3">
                <div class="stat-card medium-card">
                    <div class="stat-icon">
                        <i class="bi bi-exclamation-circle"></i>
                    </div>
                    <div class="stat-number severity-medium">{{MEDIUM_SEVERITY}}</div>
                    <p>Medium Severity</p>
                </div>
            </div>
            <div class="col-md-3">
                <div class="stat-card low-card">
                    <div class="stat-icon">
                        <i class="bi bi-info-circle"></i>
                    </div>
                    <div class="stat-number severity-low">{{LOW_SEVERITY}}</div>
                    <p>Low Severity</p>
                </div>
            </div>
        </div>
        
        <!-- Vulnerabilities Section -->
        <div class="row mt-5">
            <div class="col-12">
                <h2 class="section-title">Vulnerabilities ({{TOTAL_VULNERABILITIES}})</h2>
            </div>
        </div>
        
        <div class="row mb-4">
            <div class="col-12">
                <div class="filter-section">
                    <div class="row align-items-center">
                        <div class="col-md-8">
                            <div class="input-group">
                                <span class="input-group-text"><i class="bi bi-search"></i></span>
                                <input type="text" class="form-control" id="vulnerabilitySearch" placeholder="Search vulnerabilities...">
                            </div>
                        </div>
                        <div class="col-md-4">
                            <select class="form-select" id="severityFilter">
                                <option value="all">All Severities</option>
                                <option value="High">High</option>
                                <option value="Medium">Medium</option>
                                <option value="Low">Low</option>
                            </select>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="table-container">
            <table class="table table-hover" id="vulnerabilitiesTable">
                <thead>
                    <tr>
                        <th>#</th>
                        <th>Severity</th>
                        <th>Type</th>
                        <th>File</th>
                        <th>Line</th>
                        <th>Description</th>
                        <th>Details</th>
                    </tr>
                </thead>
                <tbody>
                    {{VULNERABILITIES}}
                </tbody>
            </table>
        </div>
        
        <!-- Modal for Vulnerability Details -->
        <div class="modal fade" id="vulnerabilityModal" tabindex="-1" aria-labelledby="vulnerabilityModalLabel" aria-hidden="true">
            <div class="modal-dialog modal-lg">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title" id="vulnerabilityModalLabel">Vulnerability Details</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <div class="modal-body" id="vulnerabilityModalBody">
                        <!-- Content will be dynamically inserted here -->
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Secrets Section -->
        <div class="row mt-5">
            <div class="col-12">
                <h2 class="section-title">Secrets Detected ({{TOTAL_SECRETS}})</h2>
            </div>
        </div>
        
        <div class="table-container">
            <table class="table table-hover" id="secretsTable">
                <thead>
                    <tr>
                        <th>#</th>
                        <th>File</th>
                        <th>Line</th>
                        <th>Key</th>
                        <th>Value Preview</th>
                        <th>Confidence</th>
                    </tr>
                </thead>
                <tbody>
                    {{SECRETS}}
                </tbody>
            </table>
        </div>
        
        <!-- Recommendations Section -->
        <div class="row mt-5">
            <div class="col-12">
                <h2 class="section-title">Recommendations</h2>
            </div>
        </div>
        
        <div class="row">
            <div class="col-md-6 mb-4">
                <div class="card h-100">
                    <div class="card-header bg-primary text-white">
                        <h5 class="mb-0"><i class="bi bi-shield-check me-2"></i>Security Best Practices</h5>
                    </div>
                    <div class="card-body">
                        <ul class="list-group list-group-flush">
                            <li class="list-group-item"><i class="bi bi-check-circle text-success me-2"></i>Implement input validation for all user inputs</li>
                            <li class="list-group-item"><i class="bi bi-check-circle text-success me-2"></i>Apply proper output encoding for different contexts</li>
                            <li class="list-group-item"><i class="bi bi-check-circle text-success me-2"></i>Use parameterized queries for database interactions</li>
                            <li class="list-group-item"><i class="bi bi-check-circle text-success me-2"></i>Apply the principle of least privilege</li>
                            <li class="list-group-item"><i class="bi bi-check-circle text-success me-2"></i>Keep dependencies updated and regularly audit them</li>
                        </ul>
                    </div>
                </div>
            </div>
            
            <div class="col-md-6 mb-4">
                <div class="card h-100">
                    <div class="card-header bg-info text-white">
                        <h5 class="mb-0"><i class="bi bi-lightning-charge me-2"></i>Next Steps</h5>
                    </div>
                    <div class="card-body">
                        <ol class="list-group list-group-numbered">
                            <li class="list-group-item">Address high severity vulnerabilities immediately</li>
                            <li class="list-group-item">Schedule remediation for medium and low severity issues</li>
                            <li class="list-group-item">Implement secure coding guidelines for your team</li>
                            <li class="list-group-item">Integrate ZeroHuntAI into your CI/CD pipeline</li>
                            <li class="list-group-item">Conduct regular security training for developers</li>
                        </ol>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Footer -->
        <div class="row mt-5">
            <div class="col-12 text-center">
                <p class="text-muted">
                    <i class="bi bi-shield"></i> Report generated by <strong>ZeroHuntAI</strong> - AI-powered Vulnerability Scanner
                </p>
                <p class="text-muted"><small>© 2025 ZeroHuntAI</small></p>
            </div>
        </div>
    </div>
    
    <!-- Back to Top Button -->
    <div class="back-to-top" id="backToTop">
        <i class="bi bi-arrow-up"></i>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@3.7.1/dist/chart.min.js"></script>
    <script>
        // Severity Chart
        const severityChart = new Chart(
            document.getElementById('severityChart'),
            {
                type: 'pie',
                data: {
                    labels: ['High', 'Medium', 'Low'],
                    datasets: [{
                        label: 'Vulnerabilities by Severity',
                        data: [{{HIGH_SEVERITY}}, {{MEDIUM_SEVERITY}}, {{LOW_SEVERITY}}],
                        backgroundColor: [
                            'rgba(220, 53, 69, 0.8)',
                            'rgba(253, 126, 20, 0.8)',
                            'rgba(13, 202, 240, 0.8)'
                        ],
                        borderColor: [
                            'rgba(220, 53, 69, 1)',
                            'rgba(253, 126, 20, 1)',
                            'rgba(13, 202, 240, 1)'
                        ],
                        borderWidth: 1
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'right',
                        },
                        title: {
                            display: true,
                            text: 'Vulnerabilities by Severity'
                        }
                    }
                }
            }
        );
        
        // Files Chart
        const filesChart = new Chart(
            document.getElementById('filesChart'),
            {
                type: 'doughnut',
                data: {
                    labels: ['Vulnerable Files', 'Clean Files'],
                    datasets: [{
                        label: 'Files Status',
                        data: [
                            {{TOTAL_VULNERABILITIES}} > 0 ? Math.min({{TOTAL_FILES}}, {{TOTAL_VULNERABILITIES}}) : 0,
                            Math.max(0, {{TOTAL_FILES}} - ({{TOTAL_VULNERABILITIES}} > 0 ? Math.min({{TOTAL_FILES}}, {{TOTAL_VULNERABILITIES}}) : 0))
                        ],
                        backgroundColor: [
                            'rgba(220, 53, 69, 0.8)',
                            'rgba(25, 135, 84, 0.8)'
                        ],
                        borderColor: [
                            'rgba(220, 53, 69, 1)',
                            'rgba(25, 135, 84, 1)'
                        ],
                        borderWidth: 1
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'bottom',
                        },
                        title: {
                            display: true,
                            text: 'Files Status'
                        }
                    }
                }
            }
        );
        
        // Vulnerability Search and Filter
        document.getElementById('vulnerabilitySearch').addEventListener('keyup', filterVulnerabilities);
        document.getElementById('severityFilter').addEventListener('change', filterVulnerabilities);
        
        function filterVulnerabilities() {
            const searchText = document.getElementById('vulnerabilitySearch').value.toLowerCase();
            const severityFilter = document.getElementById('severityFilter').value;
            const rows = document.querySelectorAll('#vulnerabilitiesTable tbody tr');
            
            rows.forEach(row => {
                const rowText = row.textContent.toLowerCase();
                const rowSeverity = row.querySelector('td:nth-child(2)').textContent;
                
                const textMatch = rowText.includes(searchText);
                const severityMatch = severityFilter === 'all' || rowSeverity === severityFilter;
                
                row.style.display = textMatch && severityMatch ? '' : 'none';
            });
        }
        
        // Back to Top Button
        const backToTopButton = document.getElementById('backToTop');
        
        window.addEventListener('scroll', () => {
            if (window.pageYOffset > 300) {
                backToTopButton.style.display = 'flex';
            } else {
                backToTopButton.style.display = 'none';
            }
        });
        
        backToTopButton.addEventListener('click', () => {
            window.scrollTo({
                top: 0,
                behavior: 'smooth'
            });
        });
        
        // Initialize tooltips and popovers
        const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
        const tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
            return new bootstrap.Tooltip(tooltipTriggerEl);
        });
        
        const popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
        const popoverList = popoverTriggerList.map(function (popoverTriggerEl) {
            return new bootstrap.Popover(popoverTriggerEl);
        });
        
        // Copy Code Function
        function copyCode(btn) {
            const codeBlock = btn.parentElement.querySelector('code');
            const textArea = document.createElement('textarea');
            textArea.value = codeBlock.textContent;
            document.body.appendChild(textArea);
            textArea.select();
            document.execCommand('copy');
            document.body.removeChild(textArea);
            
            btn.textContent = 'Copied!';
            setTimeout(() => {
                btn.textContent = 'Copy';
            }, 2000);
        }
        
        // Vulnerability Detail Modal
        function showVulnerabilityDetail(vulnerabilityData) {
            const modalBody = document.getElementById('vulnerabilityModalBody');
            const modal = new bootstrap.Modal(document.getElementById('vulnerabilityModal'));
            
            // Parse the vulnerabilityData string into an object
            const vulnerability = JSON.parse(decodeURIComponent(vulnerabilityData));
            
            // Create severity badge
            const severityClass = {
                'High': 'danger',
                'Medium': 'warning',
                'Low': 'info'
            }[vulnerability.severity] || 'secondary';
            
            // Build the modal content
            modalBody.innerHTML = `
                <div class="d-flex justify-content-between align-items-center mb-3">
                    <h4>${vulnerability.type}</h4>
                    <span class="badge bg-${severityClass} badge-severity">${vulnerability.severity}</span>
                </div>
                
                <div class="mb-3">
                    <h5><i class="bi bi-file-earmark-code me-2"></i>Location</h5>
                    <p><strong>File:</strong> ${vulnerability.file}</p>
                    <p><strong>Line:</strong> ${vulnerability.line}</p>
                </div>
                
                <div class="mb-3">
                    <h5><i class="bi bi-exclamation-triangle me-2"></i>Description</h5>
                    <p>${vulnerability.description}</p>
                </div>
                
                <div class="mb-3">
                    <h5><i class="bi bi-code-slash me-2"></i>Vulnerable Code</h5>
                    <div class="code-block">
                        <button class="copy-btn" onclick="copyCode(this)">Copy</button>
                        <code>${vulnerability.code}</code>
                    </div>
                </div>
                
                <div class="mb-3">
                    <h5><i class="bi bi-robot me-2"></i>AI Assessment</h5>
                    <div class="ai-suggestion">
                        ${vulnerability.ai_explanation || "No AI assessment available for this vulnerability."}
                    </div>
                </div>
                
                <div>
                    <h5><i class="bi bi-shield-check me-2"></i>Remediation</h5>
                    <p>${vulnerability.remediation || "Review the code and apply secure coding practices to address this vulnerability."}</p>
                </div>
            `;
            
            modal.show();
        }
    </script>
</body>
</html>
"""
        # Create the template file
        with open(template_path, 'w') as f:
            f.write(template)
        
        logger.info(f"Created HTML report template at: {template_path}")
