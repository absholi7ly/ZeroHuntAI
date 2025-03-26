import re
import os

class SensitiveDataDetector:
    """
    Detector for sensitive data patterns in code.
    """
    
    def __init__(self, high_entropy_threshold=4.5):

        self.high_entropy_threshold = high_entropy_threshold
        
        # Sensitive data patterns
        self.patterns = {
            'api_key': [
                r'(?i)([a-z0-9_-]+)?api[_-]?key[a-z0-9_-]*[\s]*[=:][^;,)]+',
                r'(?i)([a-z0-9_-]+)?secret[_-]?key[a-z0-9_-]*[\s]*[=:][^;,)]+',
                r'(?i)([a-z0-9_-]+)?auth[_-]?token[a-z0-9_-]*[\s]*[=:][^;,)]+',
                r'(?i)([a-z0-9_-]+)?access[_-]?token[a-z0-9_-]*[\s]*[=:][^;,)]+'
            ],
            'credentials': [
                r'(?i)([a-z0-9_-]+)?password[a-z0-9_-]*[\s]*[=:][^;,)]+',
                r'(?i)([a-z0-9_-]+)?passwd[a-z0-9_-]*[\s]*[=:][^;,)]+',
                r'(?i)([a-z0-9_-]+)?credential[a-z0-9_-]*[\s]*[=:][^;,)]+',
                r'(?i)([a-z0-9_-]+)?secret[a-z0-9_-]*[\s]*[=:][^;,)]+'
            ],
            'pii': [
                r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # Email
                r'\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b',  # US Phone number
                r'\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b',  # SSN
                r'\b(?:\d[ -]*?){13,16}\b'  # Credit card (simplified)
            ],
            'certificates': [
                r'-----BEGIN [A-Z ]+ PRIVATE KEY-----',
                r'-----BEGIN CERTIFICATE-----'
            ],
            'oauth': [
                r'(?i)oauth[_-]?token[a-z0-9_-]*[\s]*[=:][^;,)]+',
                r'(?i)oauth[_-]?secret[a-z0-9_-]*[\s]*[=:][^;,)]+'
            ],
            'aws': [
                r'(?i)aws[_-]?access[_-]?key[_-]?id[a-z0-9_-]*[\s]*[=:][^;,)]+',
                r'(?i)aws[_-]?secret[_-]?access[_-]?key[a-z0-9_-]*[\s]*[=:][^;,)]+',
                r'(?i)aws[_-]?account[_-]?id[a-z0-9_-]*[\s]*[=:][^;,)]+'
            ],
            'database': [
                r'(?i)(?:mongodb|postgres|mysql|oracle|db2)[_-]?uri[a-z0-9_-]*[\s]*[=:][^;,)]+',
                r'(?i)(?:mongo|postgres|mysql|oracle|db2)[_-]?url[a-z0-9_-]*[\s]*[=:][^;,)]+',
                r'(?i)(?:mongo|postgres|mysql|oracle|db2)[_-]?connection[_-]?string[a-z0-9_-]*[\s]*[=:][^;,)]+'
            ],
            'jwt': [
                r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+'  # JWT pattern
            ],
            'high_entropy_strings': []
        }
        
        # File patterns that typically contain sensitive data
        self.sensitive_files = [
            r'\.env$', 
            r'config\.(?:json|yml|yaml|xml|properties|ini|cfg|conf)$',
            r'secrets\.(?:json|yml|yaml|xml|properties|ini|cfg|conf)$',
            r'credentials\.(?:json|yml|yaml|xml|properties|ini|cfg|conf)$',
            r'\.pem$', 
            r'\.key$', 
            r'\.cert$', 
            r'\.pfx$', 
            r'\.p12$'
        ]
        
    def scan_file(self, file_path, file_content=None):

        # Check if the file name itself indicates sensitive content
        is_sensitive_file = any(re.search(pattern, file_path, re.IGNORECASE) 
                               for pattern in self.sensitive_files)
        
        # Get file content if not provided
        if file_content is None:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    file_content = f.read()
            except Exception as e:
                return [{'type': 'error', 'message': f"Could not read file: {str(e)}"}]
        
        findings = []
        
        # Check each pattern category
        for category, patterns in self.patterns.items():
            if category == 'high_entropy_strings':
                # Skip entropy analysis in this simplified version
                continue
                
            for pattern in patterns:
                matches = re.finditer(pattern, file_content)
                for match in matches:
                    finding = {
                        'type': 'sensitive_data',
                        'category': category,
                        'pattern': pattern,
                        'match': match.group(0),
                        'file': file_path,
                        'line': self._get_line_number(file_content, match.start()),
                        'is_sensitive_file': is_sensitive_file
                    }
                    
                    # Add context for better understanding
                    finding['context'] = self._get_context(file_content, match.start())
                    
                    # Check if this is likely a false positive (e.g., in comments or tests)
                    if self._is_false_positive(file_content, match.start()):
                        finding['probable_false_positive'] = True
                    
                    findings.append(finding)
        
        return findings
    
    def _get_line_number(self, content, position):
        """Get the line number for a position in the content."""
        return content[:position].count('\n') + 1
    
    def _get_context(self, content, position, context_lines=2):
        """Get context around the position in the content."""
        lines = content.split('\n')
        line_no = content[:position].count('\n')
        
        start_line = max(0, line_no - context_lines)
        end_line = min(len(lines), line_no + context_lines + 1)
        
        return '\n'.join(lines[start_line:end_line])
    
    def _is_false_positive(self, content, position):

        # Get the line containing this position
        line_start = content.rfind('\n', 0, position) + 1
        line_end = content.find('\n', position)
        if line_end == -1:
            line_end = len(content)
        line = content[line_start:line_end]
        
        # Check for common false positive indicators
        false_positive_indicators = [
            r'^\s*#', r'^\s*//', r'^\s*/\*', r'\*/',  # Comments
            r'TEST', r'test', r'Test', r'Mock', r'mock', r'Mock',  # Test code
            r'example', r'Example', r'EXAMPLE',  # Examples
            r'sample', r'Sample', r'SAMPLE',  # Samples
            r'dummy', r'Dummy', r'DUMMY',  # Dummy data
            r'(?:None|null|undefined|false)'  # Empty/default values
        ]
        
        for indicator in false_positive_indicators:
            if re.search(indicator, line):
                return True
        
        return False


def detect_sensitive_data(file_paths, verbose=False):

    detector = SensitiveDataDetector()
    all_findings = []
    
    for file_path in file_paths:
        if not os.path.isfile(file_path):
            continue
            
        # Skip binary files
        if _is_binary(file_path):
            if verbose:
                print(f"Skipping binary file: {file_path}")
            continue
        
        try:
            if verbose:
                print(f"Scanning {file_path} for sensitive data...")
                
            findings = detector.scan_file(file_path)
            
            # Add severity to findings
            for finding in findings:
                if finding.get('type') != 'error':
                    finding['severity'] = _determine_severity(finding)
            
            # Filter out probable false positives if not in verbose mode
            if not verbose:
                findings = [f for f in findings if not f.get('probable_false_positive', False)]
                
            all_findings.extend(findings)
            
        except Exception as e:
            if verbose:
                print(f"Error scanning {file_path}: {str(e)}")
    
    return all_findings


def _is_binary(file_path):

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            f.read(1024)
        return False
    except UnicodeDecodeError:
        return True


def _determine_severity(finding):

    category = finding.get('category', '')
    is_sensitive_file = finding.get('is_sensitive_file', False)
    
    # High severity categories
    if category in ['certificates', 'api_key', 'credentials', 'aws']:
        return 'High'
    
    # Medium severity
    if category in ['pii', 'oauth', 'database', 'jwt']:
        return 'Medium'
    
    # Increase severity if in a sensitive file
    if is_sensitive_file:
        return 'High'
    
    # Default to low severity
    return 'Low'