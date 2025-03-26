
import ast
import re
import os
from pathlib import Path
from collections import defaultdict

from scanner.ai_model import AIRiskScorer
from utils.vulnerability_patterns import get_vulnerability_patterns
from utils.logger import get_logger

logger = get_logger()

class CodeAnalyzer:

    #Analyzer for static code analysis.
    def __init__(self, verbose=False):

        self.verbose = verbose
        self.vulnerability_patterns = get_vulnerability_patterns()
        self.ai_scorer = AIRiskScorer()
        
        logger.info("Initialized code analyzer")
    
    def analyze_code(self, code_content, file_extension, file_path):

        vulnerabilities = []
        
        # Select analysis method based on file type
        if file_extension == '.py':
            # Python-specific analysis using AST
            vulnerabilities.extend(self._analyze_python_code(code_content, file_path))
        
        # Generic pattern-based analysis for all file types
        vulnerabilities.extend(self._analyze_patterns(code_content, file_extension, file_path))
        
        # Use AI model to score the findings
        if vulnerabilities:
            self._enrich_with_ai_scoring(vulnerabilities, code_content)
        
        return {
            'file': file_path,
            'extension': file_extension,
            'vulnerabilities': vulnerabilities
        }
    
    def _analyze_python_code(self, code_content, file_path):

        vulnerabilities = []
        
        try:
            # Parse the Python code into an AST
            tree = ast.parse(code_content)
            
            # Visitor to find dangerous function calls
            dangerous_funcs = {
                'exec': 'Command Execution',
                'eval': 'Command Execution', 
                'os.system': 'Command Execution',
                'os.popen': 'Command Execution',
                'subprocess.call': 'Command Execution',
                'subprocess.Popen': 'Command Execution',
                'pickle.loads': 'Deserialization',
                'yaml.load': 'Deserialization',
                'sqlite3.connect': 'SQL Injection (SQLite)',
                'mysql.connector.connect': 'SQL Injection (MySQL)',
                'psycopg2.connect': 'SQL Injection (PostgreSQL)',
                'pymongo.MongoClient': 'NoSQL Injection'
            }
            
            # Walk through the AST nodes
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    # Check function calls
                    func_name = None
                    
                    # Get function name for various call types
                    if isinstance(node.func, ast.Name):
                        func_name = node.func.id
                    elif isinstance(node.func, ast.Attribute):
                        # Handle module.function() style calls
                        if isinstance(node.func.value, ast.Name):
                            func_name = f"{node.func.value.id}.{node.func.attr}"
                    
                    # Check if function is in our dangerous list
                    if func_name in dangerous_funcs:
                        vuln_type = dangerous_funcs[func_name]
                        
                        # Get additional context (line number and code)
                        line_no = getattr(node, 'lineno', 0)
                        code_lines = code_content.splitlines()
                        context = code_lines[line_no - 1] if line_no > 0 and line_no <= len(code_lines) else ""
                        
                        vulnerabilities.append({
                            'type': vuln_type,
                            'file': file_path,
                            'line': line_no,
                            'code': context.strip(),
                            'description': f"Potentially dangerous function call: {func_name}",
                            'severity': 'Medium',  # Will be adjusted by AI scorer
                            'confidence': 'Medium'
                        })
                
                # Check for insecure use of input() in Python
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'input':
                    line_no = getattr(node, 'lineno', 0)
                    code_lines = code_content.splitlines()
                    context = code_lines[line_no - 1] if line_no > 0 and line_no <= len(code_lines) else ""
                    
                    vulnerabilities.append({
                        'type': 'User Input',
                        'file': file_path,
                        'line': line_no, 
                        'code': context.strip(),
                        'description': "Unvalidated user input from input() function",
                        'severity': 'Low',
                        'confidence': 'Low'
                    })
        
        except SyntaxError:
            # Handle syntax errors in the Python code
            logger.warning(f"Syntax error in Python file: {file_path}")
            vulnerabilities.append({
                'type': 'Syntax Error',
                'file': file_path,
                'line': 0,
                'code': '',
                'description': "Syntax error in Python file",
                'severity': 'Low',
                'confidence': 'High'
            })
        except Exception as e:
            # Handle other exceptions
            logger.error(f"Error analyzing Python code in {file_path}: {str(e)}")
            if self.verbose:
                logger.exception("Exception details:")
        
        return vulnerabilities
    
    def _analyze_patterns(self, code_content, file_extension, file_path):

        vulnerabilities = []
        
        try:
            # Check if we have patterns for this file type
            patterns = self.vulnerability_patterns.get(file_extension.replace('.', ''), [])
            if not patterns:
                # Use generic patterns if no language-specific ones
                patterns = self.vulnerability_patterns.get('generic', [])
                
            # Lines of code for context
            code_lines = code_content.splitlines()
            
            # Check each pattern
            for pattern_info in patterns:
                pattern = pattern_info['pattern']
                matches = re.finditer(pattern, code_content)
                
                for match in matches:
                    # Calculate line number
                    line_no = code_content.count('\n', 0, match.start()) + 1
                    
                    # Get context (the line of code)
                    context = code_lines[line_no - 1] if line_no > 0 and line_no <= len(code_lines) else ""
                    
                    # Create vulnerability entry
                    vulnerabilities.append({
                        'type': pattern_info['type'],
                        'file': file_path,
                        'line': line_no,
                        'code': context.strip(),
                        'description': pattern_info['description'],
                        'severity': pattern_info['default_severity'],
                        'confidence': pattern_info['confidence']
                    })
        
        except Exception as e:
            logger.error(f"Error in pattern analysis for {file_path}: {str(e)}")
            if self.verbose:
                logger.exception("Exception details:")
        
        return vulnerabilities
    
    def _enrich_with_ai_scoring(self, vulnerabilities, code_content):
        """
        Use AI model to enrich and score the vulnerabilities.
            vulnerabilities (list): List of detected vulnerabilities
            code_content (str): Full code content for context
            
        Returns:
            None (modifies vulnerabilities in place)
        """
        for vuln in vulnerabilities:
            # Get AI assessment for this vulnerability
            ai_assessment = self.ai_scorer.assess_vulnerability(
                vuln['type'], 
                vuln['code'],
                vuln['description'],
                code_content
            )
            
            # Update the vulnerability with AI assessment
            vuln['severity'] = ai_assessment['severity']
            vuln['ai_explanation'] = ai_assessment['explanation']
            
            # AI may adjust confidence level
            if 'confidence' in ai_assessment:
                vuln['confidence'] = ai_assessment['confidence']
