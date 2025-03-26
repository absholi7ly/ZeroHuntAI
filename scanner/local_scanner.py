import os
import time
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn

from scanner.analyzer import CodeAnalyzer
from scanner.report_generator import ReportGenerator
from scanner.visualization import CallGraphVisualizer
from utils.file_utils import is_supported_file, parse_file_content, extract_secrets_from_env, scan_sensitive_data
from utils.logger import get_logger

logger = get_logger()

class LocalScanner:
    """
    Scanner for local directory analysis.
    """
    def __init__(self, directory_path, output_dir="output", language_extensions=None, 
                 verbose=False, scan_secrets=True, enable_call_graph=False,
                 search_pattern=None, exclude_pattern=None, search_functions=None):

        self.directory_path = os.path.abspath(directory_path)
        self.output_dir = output_dir
        self.language_extensions = language_extensions
        self.verbose = verbose
        self.scan_secrets = scan_secrets
        self.enable_call_graph = enable_call_graph
        self.search_pattern = search_pattern
        self.exclude_pattern = exclude_pattern
        
        # Convert comma-separated function names to list if provided
        if search_functions and isinstance(search_functions, str):
            self.search_functions = [f.strip() for f in search_functions.split(',')]
        else:
            self.search_functions = search_functions
        
        # Results storage
        self.files_scanned = 0
        self.vulnerabilities = []
        self.secrets = []
        self.scan_result = None
        self.pattern_matches = []  # Store any specific pattern matches
        
        # Initialize analyzer
        self.analyzer = CodeAnalyzer(verbose=verbose)
        
        # Check if directory exists
        if not os.path.isdir(self.directory_path):
            raise ValueError(f"Directory not found: {self.directory_path}")
            
        logger.info(f"Initialized local scanner for directory: {self.directory_path}")
        if self.search_pattern:
            logger.info(f"Will search for specific pattern: {self.search_pattern}")
        if self.exclude_pattern:
            logger.info(f"Will exclude files matching pattern: {self.exclude_pattern}")
        if self.search_functions:
            logger.info(f"Will search for specific functions: {', '.join(self.search_functions)}")
        
    def scan(self):

        logger.info(f"Starting local scan of directory: {self.directory_path}")
        
        files_to_scan = self._get_files_to_scan()
        total_files = len(files_to_scan)
        logger.info(f"Found {total_files} files to scan")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
        ) as progress:
            scan_task = progress.add_task(f"[cyan]Scanning {total_files} files...", total=total_files)
            
            # Scan each file
            for file_path in files_to_scan:
                progress.update(scan_task, advance=1, description=f"[cyan]Scanning: {os.path.basename(file_path)}")
                
                try:
                    # Process the file
                    self._process_file(file_path)
                except Exception as e:
                    logger.error(f"Error processing file {file_path}: {str(e)}")
                    if self.verbose:
                        logger.exception("Exception details:")
            
            # Process results
            progress.update(scan_task, description="[green]Scan completed!")
            
            # If sensitive data scanning is enabled, perform an enhanced scan
            if self.scan_secrets:
                progress.update(scan_task, description="[cyan]Running enhanced sensitive data scan...")
                self._perform_sensitive_data_scan(files_to_scan)
            
        # Calculate statistics
        high_sev = sum(1 for vuln in self.vulnerabilities if vuln['severity'] == 'High')
        medium_sev = sum(1 for vuln in self.vulnerabilities if vuln['severity'] == 'Medium')
        low_sev = sum(1 for vuln in self.vulnerabilities if vuln['severity'] == 'Low')
        
        self.scan_result = {
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'target': self.directory_path,
            'vulnerabilities': self.vulnerabilities,
            'secrets': self.secrets,
            'stats': {
                'total_files': self.files_scanned,
                'high_severity': high_sev,
                'medium_severity': medium_sev,
                'low_severity': low_sev,
                'total_vulnerabilities': len(self.vulnerabilities),
                'total_secrets': len(self.secrets)
            }
        }
        
        logger.info(f"Scan completed. Found {len(self.vulnerabilities)} vulnerabilities.")
        return self.scan_result
    
    def _get_files_to_scan(self):
        import re
        
        files_to_scan = []
        excluded_count = 0
        
        # Compile patterns if they exist
        exclude_pattern_re = None
        if self.exclude_pattern:
            try:
                exclude_pattern_re = re.compile(self.exclude_pattern)
            except re.error as e:
                logger.error(f"Invalid exclude pattern: {str(e)}")
        
        for root, _, files in os.walk(self.directory_path):
            for file in files:
                file_path = os.path.join(root, file)
                relative_path = os.path.relpath(file_path, self.directory_path)
                
                # Skip if matching exclude pattern
                if exclude_pattern_re and exclude_pattern_re.search(relative_path):
                    if self.verbose:
                        logger.info(f"Excluding file due to pattern match: {relative_path}")
                    excluded_count += 1
                    continue
                
                # Check if the file should be scanned
                if is_supported_file(file_path, self.language_extensions):
                    files_to_scan.append(file_path)
                
                # Check for env files if secret scanning is enabled
                elif self.scan_secrets and file.endswith('.env'):
                    files_to_scan.append(file_path)
        
        if excluded_count > 0:
            logger.info(f"Excluded {excluded_count} files based on pattern: {self.exclude_pattern}")
            
        return files_to_scan
    
    def _process_file(self, file_path):

        import re
        
        try:
            # Parse file content
            relative_path = os.path.relpath(file_path, self.directory_path)
            file_ext = os.path.splitext(file_path)[1].lower()
            
            # If it's an .env file and we're scanning for secrets
            if self.scan_secrets and file_path.endswith('.env'):
                secrets = extract_secrets_from_env(file_path)
                if secrets:
                    for secret in secrets:
                        self.secrets.append({
                            'file': relative_path,
                            'line': secret['line'],
                            'key': secret['key'],
                            'value_preview': secret['value_preview'],
                            'confidence': secret['confidence']
                        })
                    logger.info(f"Found {len(secrets)} potential secrets in {relative_path}")
                self.files_scanned += 1
                return
            
            # Parse and analyze the file content
            code_content = parse_file_content(file_path)
            if not code_content:
                return
                
            # Check for specific pattern match if requested
            if self.search_pattern:
                try:
                    pattern = re.compile(self.search_pattern, re.MULTILINE)
                    matches = list(pattern.finditer(code_content))
                    
                    if matches:
                        for match in matches:
                            # Get line number of the match
                            line_no = code_content.count('\n', 0, match.start()) + 1
                            
                            # Get context around the match
                            lines = code_content.splitlines()
                            start_line = max(0, line_no - 3)
                            end_line = min(len(lines), line_no + 2)
                            context = '\n'.join(lines[start_line:end_line])
                            
                            # Add to pattern matches
                            self.pattern_matches.append({
                                'file': relative_path,
                                'line': line_no,
                                'match': match.group(0),
                                'context': context,
                                'type': 'pattern_match'
                            })
                        
                        logger.info(f"Found {len(matches)} pattern matches in {relative_path}")
                except re.error as e:
                    logger.error(f"Invalid search pattern: {str(e)}")
                    
            # Check for specific function matches if requested
            if self.search_functions:
                for func_name in self.search_functions:
                    # Basic function pattern for most languages
                    func_patterns = [
                        rf"function\s+{re.escape(func_name)}\s*\(",  # JavaScript/PHP
                        rf"def\s+{re.escape(func_name)}\s*\(",      # Python
                        rf"public.*function\s+{re.escape(func_name)}\s*\(",  # PHP class method
                        rf"private.*function\s+{re.escape(func_name)}\s*\(",  # PHP class method
                        rf"protected.*function\s+{re.escape(func_name)}\s*\(",  # PHP class method
                        rf"public.*static.*{re.escape(func_name)}\s*\(",  # Java/C# static method
                        rf"private.*static.*{re.escape(func_name)}\s*\(",  # Java/C# static method
                        rf"protected.*static.*{re.escape(func_name)}\s*\(",  # Java/C# static method
                        rf"public.*{re.escape(func_name)}\s*\(",  # Java/C# method
                        rf"private.*{re.escape(func_name)}\s*\(",  # Java/C# method
                        rf"protected.*{re.escape(func_name)}\s*\(",  # Java/C# method
                    ]
                    
                    # Also match function/method calls
                    func_patterns.append(rf"{re.escape(func_name)}\s*\([^)]*\)")
                    
                    for pattern in func_patterns:
                        try:
                            pattern_re = re.compile(pattern, re.MULTILINE)
                            matches = list(pattern_re.finditer(code_content))
                            
                            if matches:
                                for match in matches:
                                    # Get line number of the match
                                    line_no = code_content.count('\n', 0, match.start()) + 1
                                    
                                    # Get context around the match
                                    lines = code_content.splitlines()
                                    start_line = max(0, line_no - 3)
                                    end_line = min(len(lines), line_no + 2)
                                    context = '\n'.join(lines[start_line:end_line])
                                    
                                    # Add to pattern matches
                                    self.pattern_matches.append({
                                        'file': relative_path,
                                        'line': line_no,
                                        'match': match.group(0),
                                        'context': context,
                                        'type': 'function_match',
                                        'function': func_name
                                    })
                                
                                if matches:
                                    logger.info(f"Found function '{func_name}' ({len(matches)} matches) in {relative_path}")
                                    break  # Found at least one match for this pattern, no need to try others
                        except re.error as e:
                            logger.error(f"Invalid function pattern: {str(e)}")
            
            # Analyze for vulnerabilities
            analysis_result = self.analyzer.analyze_code(code_content, file_ext, relative_path)
            
            # Add vulnerabilities to the list
            if analysis_result['vulnerabilities']:
                self.vulnerabilities.extend(analysis_result['vulnerabilities'])
                logger.info(f"Found {len(analysis_result['vulnerabilities'])} vulnerabilities in {relative_path}")
            
            self.files_scanned += 1
            return
                
        except Exception as e:
            logger.error(f"Error processing file {file_path}: {str(e)}")
            if self.verbose:
                logger.exception("Exception details:")
    
    def generate_report(self, format='json'):

        if not self.scan_result:
            raise ValueError("No scan results available. Run scan() first.")
        
        # Create the report generator
        report_generator = ReportGenerator(self.output_dir)
        
        # Generate the report
        if format.lower() == 'json':
            return report_generator.generate_json_report(self.scan_result)
        elif format.lower() == 'html':
            return report_generator.generate_html_report(self.scan_result)
        else:
            raise ValueError(f"Unsupported report format: {format}")
    
    def generate_call_graph(self):

        if not self.enable_call_graph or not self.scan_result:
            return None
        
        try:
            visualizer = CallGraphVisualizer(self.directory_path, self.output_dir)
            return visualizer.generate_graph(self.scan_result)
        except Exception as e:
            logger.error(f"Error generating call graph: {str(e)}")
            if self.verbose:
                logger.exception("Exception details:")
            return None
            
    def _perform_sensitive_data_scan(self, files_to_scan):

        try:
            logger.info("Starting enhanced sensitive data scan...")
            
            # Use the new sensitive data detector
            sensitive_data_results = scan_sensitive_data(files_to_scan, self.verbose)
            
            # Process and add results to secrets list
            for file_path, findings in sensitive_data_results.items():
                relative_path = os.path.relpath(file_path, self.directory_path)
                
                # Process each finding
                for finding in findings:
                    # Skip error findings
                    if finding.get('type') == 'error':
                        continue
                        
                    # Convert to standard format for our secrets list
                    secret_info = {
                        'file': relative_path,
                        'line': finding.get('line', 0),
                        'key': finding.get('category', 'unknown'),
                        'match': finding.get('match', ''),
                        'context': finding.get('context', ''),
                        'value_preview': '*****',  # Mask the actual value
                        'confidence': 'High' if finding.get('severity') == 'High' else 
                                     ('Medium' if finding.get('severity') == 'Medium' else 'Low'),
                        'is_sensitive_file': finding.get('is_sensitive_file', False)
                    }
                    
                    # Only add if it's not a false positive
                    if not finding.get('probable_false_positive', False):
                        self.secrets.append(secret_info)
            
            # Log summary
            total_findings = sum(len(findings) for findings in sensitive_data_results.values())
            logger.info(f"Enhanced sensitive data scan completed. Found {total_findings} potential issues.")
            
        except Exception as e:
            logger.error(f"Error in sensitive data scan: {str(e)}")
            if self.verbose:
                logger.exception("Exception details:")
