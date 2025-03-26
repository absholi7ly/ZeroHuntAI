
import os
import time
import json
import logging
from pathlib import Path
from typing import Dict, List, Any, Tuple, Optional, Set, Union

from scanner.ast_analyzer import ASTAnalyzer
from scanner.dataflow_analyzer import DataFlowAnalyzer
from scanner.controlflow_analyzer import ControlFlowAnalyzer
from scanner.symbolic_executor import SymbolicExecutor
from scanner.dependency_analyzer import DependencyAnalyzer
from scanner.query_engine import QueryEngine
from utils.logger import get_logger
from utils.file_utils import is_supported_file, parse_file_content

logger = get_logger()

class AdvancedScanner:
    """
    Advanced scanner integrating multiple analysis techniques for comprehensive
    security assessment of codebases.
    """
    
    def __init__(self, target_path, output_dir="output", language_extensions=None,
                verbose=False, scan_secrets=True, enable_call_graph=False,
                scan_mode="local", scan_deps=True, enable_symbolic=True,
                max_files=10000, config=None):

        self.target_path = os.path.abspath(target_path)
        self.output_dir = output_dir
        self.language_extensions = language_extensions
        self.verbose = verbose
        self.scan_secrets = scan_secrets
        self.enable_call_graph = enable_call_graph
        self.scan_mode = scan_mode
        self.scan_deps = scan_deps
        self.enable_symbolic = enable_symbolic
        self.max_files = max_files
        self.config = config or {}
        
        # Results storage
        self.files_scanned = 0
        self.vulnerabilities = []
        self.secrets = []
        self.scan_result = None
        
        # Initialize analyzers
        self.ast_analyzer = ASTAnalyzer(verbose=verbose)
        self.dataflow_analyzer = DataFlowAnalyzer(verbose=verbose)
        self.controlflow_analyzer = ControlFlowAnalyzer(verbose=verbose)
        self.symbolic_executor = SymbolicExecutor(verbose=verbose)
        self.dependency_analyzer = DependencyAnalyzer(verbose=verbose)
        self.query_engine = QueryEngine(verbose=verbose)
        
        # Check if target exists
        if not os.path.exists(self.target_path):
            raise ValueError(f"Target not found: {self.target_path}")
        
        # Create output directory if it doesn't exist
        os.makedirs(self.output_dir, exist_ok=True)
        
        logger.info(f"Initialized advanced scanner for {self.scan_mode} target: {self.target_path}")
    
    def scan(self):

        logger.info(f"Starting advanced scan of {self.scan_mode} target: {self.target_path}")
        start_time = time.time()
        
        # Find files to scan
        files_to_scan = self._get_files_to_scan()
        total_files = len(files_to_scan)
        logger.info(f"Found {total_files} files to scan")
        
        # Track results from different analyzers
        ast_results = {}
        dataflow_results = {}
        controlflow_results = {}
        symbolic_results = {}
        dependency_results = {}
        query_results = {}
        
        # Scan files with AST analyzer first
        logger.info("Phase 1: Performing AST analysis")
        for file_path in files_to_scan:
            if self.files_scanned >= self.max_files:
                logger.warning(f"Reached maximum file limit ({self.max_files}). Stopping scan.")
                break
            
            try:
                file_ext = os.path.splitext(file_path)[1].lower()
                file_content = parse_file_content(file_path)
                
                if file_content:
                    # Perform AST analysis
                    ast_result = self.ast_analyzer.analyze_file(file_path, file_content)
                    if ast_result.get("success", False):
                        ast_results[file_path] = ast_result
                        
                        # Add vulnerabilities to the list
                        self.vulnerabilities.extend(ast_result.get("vulnerabilities", []))
                    
                    self.files_scanned += 1
            
            except Exception as e:
                logger.error(f"Error processing file {file_path} in AST analysis: {str(e)}")
                if self.verbose:
                    logger.exception("Exception details:")
        
        logger.info(f"AST analysis completed. Found {len(self.vulnerabilities)} potential vulnerabilities.")
        
        # Perform data flow analysis
        logger.info("Phase 2: Performing data flow analysis")
        for file_path, ast_result in ast_results.items():
            try:
                dataflow_result = self.dataflow_analyzer.analyze_file(file_path, ast_result)
                if dataflow_result.get("success", False):
                    dataflow_results[file_path] = dataflow_result
                    
                    # Add vulnerabilities to the list
                    self.vulnerabilities.extend(dataflow_result.get("vulnerabilities", []))
            
            except Exception as e:
                logger.error(f"Error processing file {file_path} in data flow analysis: {str(e)}")
                if self.verbose:
                    logger.exception("Exception details:")
        
        logger.info(f"Data flow analysis completed. Total vulnerabilities: {len(self.vulnerabilities)}")
        
        # Perform control flow analysis
        logger.info("Phase 3: Performing control flow analysis")
        for file_path, ast_result in ast_results.items():
            try:
                controlflow_result = self.controlflow_analyzer.analyze_file(file_path, ast_result)
                if controlflow_result.get("success", False):
                    controlflow_results[file_path] = controlflow_result
                    
                    # Add vulnerabilities to the list
                    self.vulnerabilities.extend(controlflow_result.get("vulnerabilities", []))
            
            except Exception as e:
                logger.error(f"Error processing file {file_path} in control flow analysis: {str(e)}")
                if self.verbose:
                    logger.exception("Exception details:")
        
        logger.info(f"Control flow analysis completed. Total vulnerabilities: {len(self.vulnerabilities)}")
        
        # Perform symbolic execution to validate vulnerabilities
        if self.enable_symbolic:
            logger.info("Phase 4: Performing symbolic execution to validate vulnerabilities")
            for file_path in ast_results:
                try:
                    # Get vulnerabilities for this file
                    file_vulns = [v for v in self.vulnerabilities if v.get("file") == file_path]
                    
                    if file_vulns:
                        # Get AST and CFG results for this file
                        ast_result = ast_results.get(file_path, {})
                        cfg_result = controlflow_results.get(file_path, {})
                        
                        # Perform symbolic execution
                        symbolic_result = self.symbolic_executor.execute(
                            file_path, file_vulns, ast_result, cfg_result)
                        
                        if symbolic_result.get("success", False):
                            symbolic_results[file_path] = symbolic_result
                            
                            # Update vulnerabilities with validation information
                            validated_vulns = symbolic_result.get("validated_vulnerabilities", [])
                            
                            # Create a map of line numbers to validated vulnerabilities
                            validated_map = {v.get("line"): v for v in validated_vulns}
                            
                            # Update existing vulnerabilities with validation info
                            for i, vuln in enumerate(self.vulnerabilities):
                                if vuln.get("file") == file_path and vuln.get("line") in validated_map:
                                    validated_vuln = validated_map[vuln.get("line")]
                                    self.vulnerabilities[i]["is_exploitable"] = validated_vuln.get("is_exploitable", False)
                                    self.vulnerabilities[i]["exploitation_difficulty"] = validated_vuln.get("exploitation_difficulty", "Unknown")
                
                except Exception as e:
                    logger.error(f"Error processing file {file_path} in symbolic execution: {str(e)}")
                    if self.verbose:
                        logger.exception("Exception details:")
            
            logger.info("Symbolic execution completed.")
        
        # Scan dependencies if enabled
        if self.scan_deps:
            logger.info("Phase 5: Scanning dependencies for vulnerabilities")
            try:
                dependency_result = self.dependency_analyzer.scan_dependencies(self.target_path)
                if dependency_result.get("success", False):
                    dependency_results = dependency_result
                    
                    # Add dependency vulnerabilities to the list with a special marker
                    for dep_vuln in dependency_result.get("vulnerabilities", []):
                        vuln = {
                            "file": "DEPENDENCY",
                            "line": 0,
                            "column": 0,
                            "vulnerability_type": "Vulnerable Dependency",
                            "severity": dep_vuln.get("severity", "Medium"),
                            "description": f"{dep_vuln.get('package')} {dep_vuln.get('version')} has vulnerability: {dep_vuln.get('title')}",
                            "dependency": dep_vuln.get("package"),
                            "version": dep_vuln.get("version"),
                            "vulnerability_id": dep_vuln.get("vulnerability_id"),
                            "is_dependency": True,
                            "mitigation": f"Update {dep_vuln.get('package')} to a version >= {dep_vuln.get('patched_versions', ['?'])[0]}"
                        }
                        self.vulnerabilities.append(vuln)
            
            except Exception as e:
                logger.error(f"Error scanning dependencies: {str(e)}")
                if self.verbose:
                    logger.exception("Exception details:")
            
            logger.info(f"Dependency scanning completed. Total vulnerabilities: {len(self.vulnerabilities)}")
        
        # Run custom queries
        logger.info("Phase 6: Running custom security queries")
        try:
            # Load queries from the queries directory
            query_dir = os.path.join(self.output_dir, "queries")
            query_load_result = self.query_engine.load_queries(query_dir)
            
            if query_load_result.get("success", False):
                logger.info(f"Loaded {query_load_result.get('loaded', 0)} custom queries")
                
                # Execute each query
                for query_id in query_load_result.get("queries", []):
                    try:
                        query_result = self.query_engine.execute_query(query_id, self.target_path, ast_results)
                        
                        if query_result.get("success", False):
                            query_results[query_id] = query_result
                            
                            # Add query results to vulnerabilities list
                            for result in query_result.get("results", []):
                                vuln = {
                                    "file": result.get("file", ""),
                                    "line": result.get("line_start", 0),
                                    "column": 0,
                                    "vulnerability_type": f"Custom Query: {query_result.get('query_name')}",
                                    "severity": result.get("severity", "Medium"),
                                    "description": f"Custom query '{query_result.get('query_name')}' matched: {result.get('match', '')}",
                                    "code_snippet": result.get("match", ""),
                                    "context": result.get("context", []),
                                    "from_query": True,
                                    "query_id": query_id
                                }
                                self.vulnerabilities.append(vuln)
                    
                    except Exception as e:
                        logger.error(f"Error executing query {query_id}: {str(e)}")
                        if self.verbose:
                            logger.exception("Exception details:")
        
        except Exception as e:
            logger.error(f"Error running custom queries: {str(e)}")
            if self.verbose:
                logger.exception("Exception details:")
        
        logger.info(f"Custom queries completed. Total vulnerabilities: {len(self.vulnerabilities)}")
        
        # Calculate statistics
        scan_duration = time.time() - start_time
        vulnerability_stats = self._calculate_vulnerability_stats()
        
        # Prepare scan result
        self.scan_result = {
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'target': self.target_path,
            'scan_mode': self.scan_mode,
            'vulnerabilities': self.vulnerabilities,
            'secrets': self.secrets,
            'stats': {
                'total_files': self.files_scanned,
                'scan_duration': scan_duration,
                'high_severity': vulnerability_stats['high'],
                'medium_severity': vulnerability_stats['medium'],
                'low_severity': vulnerability_stats['low'],
                'critical_severity': vulnerability_stats['critical'],
                'total_vulnerabilities': len(self.vulnerabilities),
                'total_secrets': len(self.secrets),
                'languages': self._get_language_stats(),
                'vulnerability_types': self._get_vulnerability_type_stats()
            },
            'analysis_coverage': {
                'ast_analysis': len(ast_results),
                'dataflow_analysis': len(dataflow_results),
                'controlflow_analysis': len(controlflow_results),
                'symbolic_execution': len(symbolic_results) if self.enable_symbolic else 0,
                'dependency_analysis': 1 if dependency_results else 0,
                'custom_queries': len(query_results)
            }
        }
        
        logger.info(f"Advanced scan completed in {scan_duration:.2f} seconds. "
                  f"Found {len(self.vulnerabilities)} vulnerabilities "
                  f"({vulnerability_stats['critical']} critical, {vulnerability_stats['high']} high, "
                  f"{vulnerability_stats['medium']} medium, {vulnerability_stats['low']} low).")
        
        return self.scan_result
    
    def _get_files_to_scan(self):

        files_to_scan = []
        
        for root, _, files in os.walk(self.target_path):
            for file in files:
                file_path = os.path.join(root, file)
                
                # Skip output directory
                if self.output_dir in file_path:
                    continue
                
                # Check if the file should be scanned
                if is_supported_file(file_path, self.language_extensions):
                    files_to_scan.append(file_path)
                
                # Check for env files if secret scanning is enabled
                if self.scan_secrets and file.endswith('.env'):
                    files_to_scan.append(file_path)
        
        return files_to_scan
    
    def _calculate_vulnerability_stats(self):

        stats = {
            'high': 0,
            'medium': 0,
            'low': 0,
            'critical': 0
        }
        
        for vuln in self.vulnerabilities:
            severity = vuln.get('severity', 'Medium')
            if severity == 'High':
                stats['high'] += 1
            elif severity == 'Medium':
                stats['medium'] += 1
            elif severity == 'Low':
                stats['low'] += 1
            elif severity == 'Critical':
                stats['critical'] += 1
        
        return stats
    
    def _get_language_stats(self):

        language_stats = {}
        
        for vuln in self.vulnerabilities:
            file_path = vuln.get('file', '')
            
            if file_path == 'DEPENDENCY':
                continue
                
            _, ext = os.path.splitext(file_path)
            ext = ext.lower()
            
            if ext:
                if ext not in language_stats:
                    language_stats[ext] = 0
                language_stats[ext] += 1
        
        return language_stats
    
    def _get_vulnerability_type_stats(self):

        type_stats = {}
        
        for vuln in self.vulnerabilities:
            vuln_type = vuln.get('vulnerability_type', 'Unknown')
            
            if vuln_type not in type_stats:
                type_stats[vuln_type] = 0
            type_stats[vuln_type] += 1
        
        return type_stats
    
    def generate_report(self, format='json'):

        if not self.scan_result:
            raise ValueError("No scan results available. Run scan() first.")
        
        # Create reports directory if it doesn't exist
        reports_dir = os.path.join(self.output_dir, "reports")
        os.makedirs(reports_dir, exist_ok=True)
        
        # Generate timestamp for the report filename
        timestamp = time.strftime('%Y%m%d_%H%M%S')
        
        if format.lower() == 'json':
            # Generate JSON report
            report_path = os.path.join(reports_dir, f"zerohuntai_report_{timestamp}.json")
            
            try:
                with open(report_path, 'w') as f:
                    json.dump(self.scan_result, f, indent=2)
                
                logger.info(f"Generated JSON report: {report_path}")
                return report_path
            
            except Exception as e:
                logger.error(f"Error generating JSON report: {str(e)}")
                if self.verbose:
                    logger.exception("Exception details:")
                return None
        
        elif format.lower() == 'html':
            # Generate HTML report
            report_path = os.path.join(reports_dir, f"zerohuntai_report_{timestamp}.html")
            
            try:
                # Create an HTML report template
                html_content = self._generate_html_report()
                
                with open(report_path, 'w') as f:
                    f.write(html_content)
                
                logger.info(f"Generated HTML report: {report_path}")
                return report_path
            
            except Exception as e:
                logger.error(f"Error generating HTML report: {str(e)}")
                if self.verbose:
                    logger.exception("Exception details:")
                return None
        
        elif format.lower() == 'pdf':
            # Generate PDF report
            report_path = os.path.join(reports_dir, f"zerohuntai_report_{timestamp}.pdf")
            
            try:
                # First generate an HTML report
                html_content = self._generate_html_report()
                
                # Convert HTML to PDF (would require a PDF library in a real implementation)
                # For now, just save the HTML content with a .pdf extension
                with open(report_path, 'w') as f:
                    f.write(html_content)
                
                logger.info(f"Generated PDF report: {report_path}")
                return report_path
            
            except Exception as e:
                logger.error(f"Error generating PDF report: {str(e)}")
                if self.verbose:
                    logger.exception("Exception details:")
                return None
        
        else:
            raise ValueError(f"Unsupported report format: {format}")
    
    def _generate_html_report(self):

        # Use a template for the HTML report
        html_template = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ZeroHuntAI Vulnerability Scan Report</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f8f9fa;
        }
        .header {
            text-align: center;
            margin-bottom: 30px;
            padding: 20px;
            background-color: #343a40;
            color: white;
            border-radius: 5px;
        }
        .header h1 {
            margin: 0;
            font-size: 28px;
        }
        .header p {
            margin: 5px 0 0;
            opacity: 0.8;
        }
        .summary {
            background-color: white;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }
        .summary h2 {
            margin-top: 0;
            border-bottom: 1px solid #eee;
            padding-bottom: 10px;
        }
        .stats {
            display: flex;
            flex-wrap: wrap;
            gap: 15px;
            margin-top: 20px;
        }
        .stat-box {
            flex: 1;
            min-width: 150px;
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            text-align: center;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
        .stat-box.critical {
            background-color: #dc3545;
            color: white;
        }
        .stat-box.high {
            background-color: #fd7e14;
            color: white;
        }
        .stat-box.medium {
            background-color: #ffc107;
            color: #343a40;
        }
        .stat-box.low {
            background-color: #20c997;
            color: white;
        }
        .stat-box h3 {
            margin: 0;
            font-size: 14px;
            font-weight: normal;
            text-transform: uppercase;
        }
        .stat-box p {
            margin: 5px 0 0;
            font-size: 24px;
            font-weight: bold;
        }
        .vulnerabilities {
            background-color: white;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }
        .vulnerabilities h2 {
            margin-top: 0;
            border-bottom: 1px solid #eee;
            padding-bottom: 10px;
        }
        .filter-options {
            margin-bottom: 15px;
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }
        .filter-btn {
            padding: 8px 12px;
            border: none;
            border-radius: 4px;
            background-color: #e9ecef;
            cursor: pointer;
            font-size: 14px;
        }
        .filter-btn:hover {
            background-color: #dee2e6;
        }
        .filter-btn.active {
            background-color: #007bff;
            color: white;
        }
        .filter-btn.critical {
            background-color: #dc3545;
            color: white;
        }
        .filter-btn.high {
            background-color: #fd7e14;
            color: white;
        }
        .filter-btn.medium {
            background-color: #ffc107;
            color: #343a40;
        }
        .filter-btn.low {
            background-color: #20c997;
            color: white;
        }
        .vuln-list {
            border-collapse: collapse;
            width: 100%;
        }
        .vuln-list th, .vuln-list td {
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid #e9ecef;
        }
        .vuln-list tr:hover {
            background-color: #f8f9fa;
        }
        .vuln-list th {
            background-color: #e9ecef;
            font-weight: bold;
        }
        .severity-badge {
            display: inline-block;
            padding: 5px 10px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: bold;
            text-transform: uppercase;
        }
        .severity-badge.critical {
            background-color: #dc3545;
            color: white;
        }
        .severity-badge.high {
            background-color: #fd7e14;
            color: white;
        }
        .severity-badge.medium {
            background-color: #ffc107;
            color: #343a40;
        }
        .severity-badge.low {
            background-color: #20c997;
            color: white;
        }
        .vuln-details {
            padding: 15px;
            background-color: #f8f9fa;
            border-radius: 5px;
            margin-top: 15px;
            display: none;
        }
        .vuln-details pre {
            background-color: #343a40;
            color: #f8f9fa;
            padding: 10px;
            border-radius: 5px;
            overflow-x: auto;
            font-family: 'Courier New', monospace;
        }
        .toggle-details {
            background-color: #6c757d;
            color: white;
            border: none;
            padding: 5px 10px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 12px;
        }
        .toggle-details:hover {
            background-color: #5a6268;
        }
        .coverage {
            background-color: white;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }
        .coverage h2 {
            margin-top: 0;
            border-bottom: 1px solid #eee;
            padding-bottom: 10px;
        }
        .progress-bar {
            height: 20px;
            background-color: #e9ecef;
            border-radius: 10px;
            margin-bottom: 15px;
            overflow: hidden;
        }
        .progress-bar-fill {
            height: 100%;
            background-color: #007bff;
            border-radius: 10px;
            width: 0%;
            transition: width 0.5s ease;
        }
        .footer {
            text-align: center;
            margin-top: 30px;
            padding-top: 15px;
            border-top: 1px solid #dee2e6;
            font-size: 12px;
            color: #6c757d;
        }
        @media (max-width: 768px) {
            .stats {
                flex-direction: column;
            }
            .stat-box {
                min-width: auto;
            }
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>ZeroHuntAI Vulnerability Scan Report</h1>
        <p>Generated on {{timestamp}}</p>
    </div>

    <div class="summary">
        <h2>Scan Summary</h2>
        <p><strong>Target:</strong> {{target}}</p>
        <p><strong>Scan Mode:</strong> {{scan_mode}}</p>
        <p><strong>Files Scanned:</strong> {{files_scanned}}</p>
        <p><strong>Scan Duration:</strong> {{scan_duration}} seconds</p>
        
        <div class="stats">
            <div class="stat-box critical">
                <h3>Critical</h3>
                <p>{{critical_severity}}</p>
            </div>
            <div class="stat-box high">
                <h3>High</h3>
                <p>{{high_severity}}</p>
            </div>
            <div class="stat-box medium">
                <h3>Medium</h3>
                <p>{{medium_severity}}</p>
            </div>
            <div class="stat-box low">
                <h3>Low</h3>
                <p>{{low_severity}}</p>
            </div>
            <div class="stat-box">
                <h3>Total Vulnerabilities</h3>
                <p>{{total_vulnerabilities}}</p>
            </div>
        </div>
    </div>

    <div class="coverage">
        <h2>Analysis Coverage</h2>
        <div>
            <p><strong>AST Analysis:</strong> {{ast_coverage}} files</p>
            <div class="progress-bar">
                <div class="progress-bar-fill" id="ast-progress"></div>
            </div>
            
            <p><strong>Data Flow Analysis:</strong> {{dataflow_coverage}} files</p>
            <div class="progress-bar">
                <div class="progress-bar-fill" id="dataflow-progress"></div>
            </div>
            
            <p><strong>Control Flow Analysis:</strong> {{controlflow_coverage}} files</p>
            <div class="progress-bar">
                <div class="progress-bar-fill" id="controlflow-progress"></div>
            </div>
            
            <p><strong>Symbolic Execution:</strong> {{symbolic_coverage}} files</p>
            <div class="progress-bar">
                <div class="progress-bar-fill" id="symbolic-progress"></div>
            </div>
            
            <p><strong>Dependency Analysis:</strong> {{dep_coverage}}</p>
            <div class="progress-bar">
                <div class="progress-bar-fill" id="dep-progress"></div>
            </div>
            
            <p><strong>Custom Queries Executed:</strong> {{query_coverage}}</p>
            <div class="progress-bar">
                <div class="progress-bar-fill" id="query-progress"></div>
            </div>
        </div>
    </div>

    <div class="vulnerabilities">
        <h2>Detected Vulnerabilities</h2>
        
        <div class="filter-options">
            <button class="filter-btn active" data-filter="all">All</button>
            <button class="filter-btn critical" data-filter="Critical">Critical</button>
            <button class="filter-btn high" data-filter="High">High</button>
            <button class="filter-btn medium" data-filter="Medium">Medium</button>
            <button class="filter-btn low" data-filter="Low">Low</button>
            <button class="filter-btn" data-filter="dependency">Dependencies</button>
        </div>
        
        <table class="vuln-list">
            <thead>
                <tr>
                    <th>Severity</th>
                    <th>Type</th>
                    <th>File</th>
                    <th>Line</th>
                    <th>Details</th>
                </tr>
            </thead>
            <tbody>
                {{vulnerability_rows}}
            </tbody>
        </table>
    </div>

    <div class="footer">
        <p>Report generated by ZeroHuntAI Advanced Vulnerability Scanner</p>
    </div>

    <script>
        // Initialize progress bars
        document.addEventListener('DOMContentLoaded', function() {
            const totalFiles = {{files_scanned}};
            if (totalFiles > 0) {
                document.getElementById('ast-progress').style.width = 
                    Math.min(100, ({{ast_coverage}} / totalFiles * 100)) + '%';
                document.getElementById('dataflow-progress').style.width = 
                    Math.min(100, ({{dataflow_coverage}} / totalFiles * 100)) + '%';
                document.getElementById('controlflow-progress').style.width = 
                    Math.min(100, ({{controlflow_coverage}} / totalFiles * 100)) + '%';
                document.getElementById('symbolic-progress').style.width = 
                    Math.min(100, ({{symbolic_coverage}} / totalFiles * 100)) + '%';
                document.getElementById('dep-progress').style.width = 
                    {{dep_coverage}} > 0 ? '100%' : '0%';
                document.getElementById('query-progress').style.width = 
                    {{query_coverage}} > 0 ? (Math.min(100, {{query_coverage}} * 10)) + '%' : '0%';
            }
        });

        // Vulnerability details toggles
        document.querySelectorAll('.toggle-details').forEach(button => {
            button.addEventListener('click', function() {
                const detailsId = this.getAttribute('data-target');
                const detailsElement = document.getElementById(detailsId);
                
                if (detailsElement.style.display === 'none' || detailsElement.style.display === '') {
                    detailsElement.style.display = 'block';
                    this.textContent = 'Hide Details';
                } else {
                    detailsElement.style.display = 'none';
                    this.textContent = 'Show Details';
                }
            });
        });

        // Filtering functionality
        document.querySelectorAll('.filter-btn').forEach(button => {
            button.addEventListener('click', function() {
                // Update active button
                document.querySelectorAll('.filter-btn').forEach(btn => {
                    btn.classList.remove('active');
                });
                this.classList.add('active');
                
                // Apply filter
                const filter = this.getAttribute('data-filter');
                const rows = document.querySelectorAll('.vuln-list tbody tr');
                
                rows.forEach(row => {
                    if (filter === 'all') {
                        row.style.display = '';
                    } else if (filter === 'dependency') {
                        row.style.display = row.classList.contains('dependency') ? '' : 'none';
                    } else {
                        const severityCell = row.querySelector('td:first-child');
                        row.style.display = 
                            severityCell && severityCell.textContent.trim() === filter ? '' : 'none';
                    }
                });
            });
        });
    </script>
</body>
</html>
"""
        
        # Generate vulnerability rows
        vulnerability_rows = ""
        for idx, vuln in enumerate(self.scan_result['vulnerabilities']):
            severity = vuln.get('severity', 'Medium')
            vuln_type = vuln.get('vulnerability_type', 'Unknown')
            file_path = vuln.get('file', '')
            line = vuln.get('line', 0)
            
            # Create a row class for dependency vulnerabilities
            row_class = 'dependency' if vuln.get('is_dependency', False) else ''
            
            # Format file path to be more readable
            if file_path == 'DEPENDENCY':
                file_path = vuln.get('dependency', 'Unknown Package')
            else:
                # Get the relative path (last 2-3 components)
                path_parts = file_path.split('/')
                if len(path_parts) > 2:
                    file_path = '/'.join(path_parts[-2:])
            
            # Create vulnerability details
            details_id = f"vuln-details-{idx}"
            details_content = f"""
                <div id="{details_id}" class="vuln-details">
                    <p><strong>Description:</strong> {vuln.get('description', 'No description available')}</p>
                    <p><strong>Mitigation:</strong> {vuln.get('mitigation', 'No mitigation advice available')}</p>
                    
                    {f'<p><strong>Package:</strong> {vuln.get("dependency", "")} {vuln.get("version", "")}</p>' if vuln.get('is_dependency', False) else ''}
                    {f'<p><strong>Vulnerability ID:</strong> {vuln.get("vulnerability_id", "")}</p>' if vuln.get('vulnerability_id', '') else ''}
                    
                    {f'<p><strong>Exploitability:</strong> {vuln.get("is_exploitable", "Unknown")}</p>' if 'is_exploitable' in vuln else ''}
                    {f'<p><strong>Exploitation Difficulty:</strong> {vuln.get("exploitation_difficulty", "Unknown")}</p>' if 'exploitation_difficulty' in vuln else ''}
                    
                    {f'<p><strong>Code Snippet:</strong></p><pre>{vuln.get("code_snippet", "")}</pre>' if vuln.get('code_snippet', '') else ''}
                </div>
            """
            
            # Add the row to the table
            vulnerability_rows += f"""
                <tr class="{row_class}">
                    <td><span class="severity-badge {severity.lower()}">{severity}</span></td>
                    <td>{vuln_type}</td>
                    <td>{file_path}</td>
                    <td>{line}</td>
                    <td>
                        <button class="toggle-details" data-target="{details_id}">Show Details</button>
                        {details_content}
                    </td>
                </tr>
            """
        
        # Replace placeholders in the template
        html_content = html_template.replace("{{timestamp}}", self.scan_result['timestamp'])
        html_content = html_content.replace("{{target}}", self.scan_result['target'])
        html_content = html_content.replace("{{scan_mode}}", self.scan_result['scan_mode'])
        html_content = html_content.replace("{{files_scanned}}", str(self.scan_result['stats']['total_files']))
        html_content = html_content.replace("{{scan_duration}}", f"{self.scan_result['stats']['scan_duration']:.2f}")
        
        html_content = html_content.replace("{{critical_severity}}", str(self.scan_result['stats']['critical_severity']))
        html_content = html_content.replace("{{high_severity}}", str(self.scan_result['stats']['high_severity']))
        html_content = html_content.replace("{{medium_severity}}", str(self.scan_result['stats']['medium_severity']))
        html_content = html_content.replace("{{low_severity}}", str(self.scan_result['stats']['low_severity']))
        html_content = html_content.replace("{{total_vulnerabilities}}", str(self.scan_result['stats']['total_vulnerabilities']))
        
        # Analysis coverage
        html_content = html_content.replace("{{ast_coverage}}", str(self.scan_result['analysis_coverage']['ast_analysis']))
        html_content = html_content.replace("{{dataflow_coverage}}", str(self.scan_result['analysis_coverage']['dataflow_analysis']))
        html_content = html_content.replace("{{controlflow_coverage}}", str(self.scan_result['analysis_coverage']['controlflow_analysis']))
        html_content = html_content.replace("{{symbolic_coverage}}", str(self.scan_result['analysis_coverage']['symbolic_execution']))
        html_content = html_content.replace("{{dep_coverage}}", str(self.scan_result['analysis_coverage']['dependency_analysis']))
        html_content = html_content.replace("{{query_coverage}}", str(self.scan_result['analysis_coverage']['custom_queries']))
        
        # Add vulnerability rows
        html_content = html_content.replace("{{vulnerability_rows}}", vulnerability_rows)
        
        return html_content
    
    def generate_trace_graph(self):

        if not self.scan_result:
            raise ValueError("No scan results available. Run scan() first.")
        
        # This would generate a visual graph of vulnerability traces
        # Here we'll just create a placeholder JSON file
        
        # Create visualizations directory if it doesn't exist
        viz_dir = os.path.join(self.output_dir, "visualizations")
        os.makedirs(viz_dir, exist_ok=True)
        
        # Generate a trace graph file
        timestamp = time.strftime('%Y%m%d_%H%M%S')
        graph_path = os.path.join(viz_dir, f"trace_graph_{timestamp}.json")
        
        try:
            # Create a simple graph structure
            graph_data = {
                "nodes": [],
                "edges": []
            }
            
            # Add nodes for files with vulnerabilities
            file_nodes = {}
            vuln_nodes = {}
            
            for idx, vuln in enumerate(self.scan_result['vulnerabilities']):
                file_path = vuln.get('file', '')
                
                if file_path == 'DEPENDENCY':
                    continue
                
                # Add file node if it doesn't exist
                if file_path not in file_nodes:
                    file_id = f"file_{len(file_nodes)}"
                    file_nodes[file_path] = file_id
                    
                    graph_data["nodes"].append({
                        "id": file_id,
                        "label": os.path.basename(file_path),
                        "type": "file",
                        "path": file_path
                    })
                
                # Add vulnerability node
                vuln_id = f"vuln_{idx}"
                vuln_nodes[idx] = vuln_id
                
                graph_data["nodes"].append({
                    "id": vuln_id,
                    "label": vuln.get('vulnerability_type', 'Unknown'),
                    "type": "vulnerability",
                    "severity": vuln.get('severity', 'Medium')
                })
                
                # Connect vulnerability to file
                graph_data["edges"].append({
                    "source": file_nodes[file_path],
                    "target": vuln_id,
                    "type": "contains"
                })
            
            # Add trace edges if available
            for vuln_idx, vuln in enumerate(self.scan_result['vulnerabilities']):
                if 'taint_trace' in vuln:
                    trace = vuln.get('taint_trace', [])
                    
                    for trace_step in trace:
                        source_file = trace_step.get('file', '')
                        target_file = vuln.get('file', '')
                        
                        if source_file in file_nodes and target_file in file_nodes:
                            graph_data["edges"].append({
                                "source": file_nodes[source_file],
                                "target": file_nodes[target_file],
                                "type": "trace",
                                "label": trace_step.get('type', 'flow')
                            })
            
            # Save the graph data
            with open(graph_path, 'w') as f:
                json.dump(graph_data, f, indent=2)
            
            logger.info(f"Generated trace graph: {graph_path}")
            return graph_path
        
        except Exception as e:
            logger.error(f"Error generating trace graph: {str(e)}")
            if self.verbose:
                logger.exception("Exception details:")
            return None
    
    def simulate_exploits(self):

        if not self.scan_result:
            raise ValueError("No scan results available. Run scan() first.")
        
        simulation_results = []
        
        # Only simulate exploits for vulnerabilities that have been validated
        for vuln in self.vulnerabilities:
            if vuln.get('is_exploitable', False):
                try:
                    # Get the execution path for this vulnerability
                    file_path = vuln.get('file', '')
                    vuln_line = vuln.get('line', 0)
                    
                    # Find the symbolic execution result for this file
                    path = []
                    for symbolic_file, symbolic_result in self.symbolic_executor.executed_paths.items():
                        if symbolic_file == file_path:
                            # Find the path to this vulnerability
                            for exec_path in symbolic_result.get('paths', []):
                                for node in exec_path:
                                    if node.get('line', 0) == vuln_line:
                                        path = exec_path
                                        break
                                if path:
                                    break
                    
                    # Simulate the exploit
                    simulation = self.symbolic_executor.simulate_exploit(vuln, path)
                    simulation_results.append({
                        'vulnerability': vuln,
                        'simulation': simulation
                    })
                
                except Exception as e:
                    logger.error(f"Error simulating exploit for vulnerability in {vuln.get('file', '')}:{vuln.get('line', 0)}: {str(e)}")
                    if self.verbose:
                        logger.exception("Exception details:")
        
        return {
            'success': True,
            'simulations': simulation_results,
            'simulation_count': len(simulation_results)
        }