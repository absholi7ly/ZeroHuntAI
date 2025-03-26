import os
import re
from pathlib import Path

from utils.logger import get_logger
from utils.sensitive_data_detector import detect_sensitive_data

logger = get_logger()

# Define supported file extensions
SUPPORTED_EXTENSIONS = {
    '.py': 'Python',
    '.php': 'PHP',
    '.js': 'JavaScript',
    '.java': 'Java',
    '.c': 'C',
    '.cpp': 'C++',
    '.go': 'Go',
    '.rb': 'Ruby',
    '.cs': 'C#',
    '.ts': 'TypeScript',
    '.swift': 'Swift',
    '.kt': 'Kotlin',
    '.jsx': 'React',
    '.tsx': 'React TypeScript',
    '.html': 'HTML',
    '.xml': 'XML',
    '.sql': 'SQL'
}

def is_supported_file(file_path, language_extensions=None):

    # Skip hidden files and directories
    if os.path.basename(file_path).startswith('.'):
        return False
    
    # Get file extension
    file_ext = os.path.splitext(file_path)[1].lower()
    
    # Check if we're filtering by specific extensions
    if language_extensions:
        return file_ext in language_extensions
    
    # Otherwise check if it's a supported extension
    return file_ext in SUPPORTED_EXTENSIONS

def parse_file_content(file_path):

    try:
        # Get file size
        file_size = os.path.getsize(file_path)
        
        # Skip files larger than 1MB
        if file_size > 1024 * 1024:
            logger.warning(f"Skipping large file (size: {file_size} bytes): {file_path}")
            return None
        
        # Read the file content
        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()
            
        return content
    
    except UnicodeDecodeError:
        logger.warning(f"Unicode decode error for file: {file_path}")
        return None
    except Exception as e:
        logger.error(f"Error reading file {file_path}: {str(e)}")
        return None

def extract_secrets_from_env(file_path):
    secrets = []
    
    try:
        # Read the file content
        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            lines = f.readlines()
        
        # Define patterns for secrets
        secret_patterns = [
            r'password',
            r'secret',
            r'token',
            r'key',
            r'auth',
            r'credentials?',
            r'api[-_]?key',
            r'access[-_]?token',
            r'jwt',
            r'hash',
            r'encrypt'
        ]
        
        # Compile regex for faster matching
        combined_pattern = re.compile('|'.join(secret_patterns), re.IGNORECASE)
        
        # Check each line
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            
            # Skip empty lines and comments
            if not line or line.startswith('#'):
                continue
            
            # Try to parse key=value format
            if '=' in line:
                key, value = line.split('=', 1)
                key = key.strip()
                value = value.strip()
                
                # Skip empty values
                if not value:
                    continue
                
                # Check if key contains a secret pattern
                if combined_pattern.search(key):
                    # Determine confidence level
                    confidence = 'Low'
                    
                    # Higher confidence for certain key patterns
                    high_confidence_patterns = ['password', 'secret', 'token', 'api_key', 'apikey']
                    for pattern in high_confidence_patterns:
                        if pattern in key.lower():
                            confidence = 'High'
                            break
                    
                    # Medium confidence for things that might be secrets
                    medium_confidence_patterns = ['key', 'auth', 'credential', 'access']
                    if confidence != 'High':
                        for pattern in medium_confidence_patterns:
                            if pattern in key.lower():
                                confidence = 'Medium'
                                break
                    
                    # Mask the value for reporting
                    value_preview = ''
                    if len(value) <= 4:
                        value_preview = '*' * len(value)
                    else:
                        value_preview = value[:2] + '*' * (len(value) - 4) + value[-2:]
                    
                    secrets.append({
                        'line': line_num,
                        'key': key,
                        'value_preview': value_preview,
                        'confidence': confidence
                    })
        
        return secrets
    
    except Exception as e:
        logger.error(f"Error extracting secrets from {file_path}: {str(e)}")
        return []


def scan_sensitive_data(files, verbose=False):

    logger.info(f"Scanning {len(files)} files for sensitive data...")
    
    # Filter out files that don't exist or are too large
    valid_files = []
    for file_path in files:
        if not os.path.isfile(file_path):
            continue
            
        try:
            file_size = os.path.getsize(file_path)
            if file_size > 1024 * 1024:  # Skip files larger than 1MB
                logger.info(f"Skipping large file for sensitive data scan: {file_path}")
                continue
                
            valid_files.append(file_path)
        except Exception as e:
            logger.warning(f"Error checking file {file_path}: {str(e)}")
    
    # Use the advanced sensitive data detector
    findings = detect_sensitive_data(valid_files, verbose)
    
    # Organize findings by file
    result = {}
    for finding in findings:
        file_path = finding.get('file', '')
        if file_path not in result:
            result[file_path] = []
            
        result[file_path].append(finding)
    
    # Log summary
    total_findings = sum(len(f) for f in result.values())
    severity_counts = {
        'High': sum(1 for f in findings if f.get('severity') == 'High'),
        'Medium': sum(1 for f in findings if f.get('severity') == 'Medium'),
        'Low': sum(1 for f in findings if f.get('severity') == 'Low')
    }
    
    logger.info(f"Sensitive data scan completed. Found {total_findings} potential issues.")
    logger.info(f"Severity breakdown: High: {severity_counts['High']}, Medium: {severity_counts['Medium']}, Low: {severity_counts['Low']}")
    
    return result
