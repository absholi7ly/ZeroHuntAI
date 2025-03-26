"""
Advanced AST Analyzer Module

This module provides advanced Abstract Syntax Tree (AST) analysis capabilities
for detecting vulnerabilities and security flaws in source code.
"""

import os
import ast
import logging
import json
import yaml
from typing import Dict, List, Any, Tuple, Optional, Set, Union

from utils.logger import get_logger

logger = get_logger()

class PythonASTVisitor(ast.NodeVisitor):
    """
    AST visitor for Python code to extract information needed for vulnerability analysis.
    """
    def __init__(self, file_path):
        self.file_path = file_path
        self.functions = {}
        self.classes = {}
        self.calls = []
        self.imports = []
        self.assignments = []
        self.strings = []
        self.file_content = None
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                self.file_content = f.read()
                self.file_lines = self.file_content.split('\n')
        except Exception as e:
            logger.error(f"Error reading file {file_path}: {str(e)}")

    def visit_FunctionDef(self, node):
        """Visit function definition nodes."""
        function_info = {
            'name': node.name,
            'line': node.lineno,
            'col': node.col_offset,
            'args': [arg.arg for arg in node.args.args],
            'returns': None,
            'docstring': ast.get_docstring(node),
            'calls': [],
            'code': self.get_line_context(node.lineno)['context']
        }
        
        if node.returns:
            function_info['returns'] = getattr(node.returns, 'id', None)
        
        self.functions[node.name] = function_info
        self.generic_visit(node)

    def visit_ClassDef(self, node):
        """Visit class definition nodes."""
        class_info = {
            'name': node.name,
            'line': node.lineno,
            'col': node.col_offset,
            'bases': [getattr(base, 'id', None) for base in node.bases],
            'methods': [],
            'docstring': ast.get_docstring(node)
        }
        
        self.classes[node.name] = class_info
        self.generic_visit(node)

    def visit_Call(self, node):
        """Visit function call nodes."""
        func_name = None
        
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = self._get_attribute_chain(node.func)
        
        if func_name:
            call_info = {
                'name': func_name,
                'line': node.lineno,
                'col': node.col_offset,
                'args': [],
                'keywords': []
            }
            
            # Process positional arguments
            for arg in node.args:
                if isinstance(arg, ast.Name):
                    call_info['args'].append(arg.id)
                elif isinstance(arg, ast.Constant):
                    call_info['args'].append(arg.value)
                else:
                    call_info['args'].append(type(arg).__name__)
            
            # Process keyword arguments
            for kw in node.keywords:
                if kw.arg is not None:
                    if isinstance(kw.value, ast.Name):
                        call_info['keywords'].append({kw.arg: kw.value.id})
                    elif isinstance(kw.value, ast.Constant):
                        call_info['keywords'].append({kw.arg: kw.value.value})
                    else:
                        call_info['keywords'].append({kw.arg: type(kw.value).__name__})
            
            self.calls.append(call_info)
            
            # Add this call to the containing function if applicable
            for func_name, func_info in self.functions.items():
                if func_info['line'] < node.lineno and 'end_line' in func_info and func_info['end_line'] > node.lineno:
                    func_info['calls'].append(call_info)
        
        self.generic_visit(node)

    def visit_Assign(self, node):
        """Visit assignment nodes."""
        for target in node.targets:
            if isinstance(target, ast.Name):
                assignment_info = {
                    'target': target.id,
                    'line': node.lineno,
                    'col': node.col_offset,
                    'value_type': type(node.value).__name__
                }
                
                if isinstance(node.value, ast.Constant):
                    assignment_info['value'] = node.value.value
                
                self.assignments.append(assignment_info)
        
        self.generic_visit(node)

    def visit_Import(self, node):
        """Visit import nodes."""
        for name in node.names:
            import_info = {
                'name': name.name,
                'asname': name.asname,
                'line': node.lineno,
                'col': node.col_offset
            }
            self.imports.append(import_info)
        
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        """Visit import from nodes."""
        for name in node.names:
            import_info = {
                'module': node.module,
                'name': name.name,
                'asname': name.asname,
                'line': node.lineno,
                'col': node.col_offset
            }
            self.imports.append(import_info)
        
        self.generic_visit(node)

    def visit_Str(self, node):
        """Visit string literal nodes."""
        string_info = {
            'value': node.s,
            'line': node.lineno,
            'col': node.col_offset
        }
        self.strings.append(string_info)
        
        self.generic_visit(node)

    def _get_attribute_chain(self, node):

        if isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name):
                return f"{node.value.id}.{node.attr}"
            elif isinstance(node.value, ast.Attribute):
                return f"{self._get_attribute_chain(node.value)}.{node.attr}"
            else:
                return node.attr
        return None

    def get_line_context(self, line_num, context_lines=2):

        if not self.file_content:
            return {'line': '', 'context': ''}
        
        start_line = max(0, line_num - context_lines - 1)
        end_line = min(len(self.file_lines), line_num + context_lines)
        
        context = '\n'.join(self.file_lines[start_line:end_line])
        line = self.file_lines[line_num - 1] if line_num <= len(self.file_lines) else ''
        
        return {
            'line': line,
            'context': context,
            'start_line': start_line + 1,
            'end_line': end_line
        }

class ASTAnalyzer:
    """
    Advanced AST analyzer for vulnerability detection using abstract syntax tree analysis.
    Supports custom rule definitions and multiple programming languages.
    """
    
    def __init__(self, rules_dir="rules", verbose=False):

        self.rules_dir = rules_dir
        self.verbose = verbose
        self.rules = {}
        
        # Initialize rules
        self._load_rules()
        
        logger.info("Initialized AST analyzer")
    
    def _load_rules(self):
        """Load custom vulnerability detection rules from YAML/JSON files."""
        if not os.path.exists(self.rules_dir):
            os.makedirs(self.rules_dir)
            self._create_default_rules()
            
        # Load rule files
        for root, _, files in os.walk(self.rules_dir):
            for file in files:
                if file.endswith(('.yaml', '.yml')):
                    try:
                        rule_file = os.path.join(root, file)
                        with open(rule_file, 'r') as f:
                            rule_data = yaml.safe_load(f)
                            
                        language = rule_data.get('language', 'common')
                        if language not in self.rules:
                            self.rules[language] = []
                            
                        if 'rules' in rule_data:
                            self.rules[language].extend(rule_data['rules'])
                            
                    except Exception as e:
                        logger.error(f"Error loading rule file {file}: {str(e)}")
                        if self.verbose:
                            logger.exception("Exception details:")
                
                elif file.endswith('.json'):
                    try:
                        rule_file = os.path.join(root, file)
                        with open(rule_file, 'r') as f:
                            rule_data = json.load(f)
                            
                        language = rule_data.get('language', 'common')
                        if language not in self.rules:
                            self.rules[language] = []
                            
                        if 'rules' in rule_data:
                            self.rules[language].extend(rule_data['rules'])
                            
                    except Exception as e:
                        logger.error(f"Error loading rule file {file}: {str(e)}")
                        if self.verbose:
                            logger.exception("Exception details:")
        
        if self.verbose:
            for language, rules in self.rules.items():
                logger.debug(f"Loaded {len(rules)} rules for {language}")
    
    def _create_default_rules(self):
        """Create default rule files."""
        default_rule = {
            "language": "python",
            "rules": [
                {
                    "id": "PY-EVAL-EXEC-001",
                    "name": "Use of eval() or exec()",
                    "description": "Identifies potentially dangerous use of eval() or exec()",
                    "severity": "High",
                    "patterns": [
                        {
                            "type": "function_call",
                            "name": "eval"
                        },
                        {
                            "type": "function_call",
                            "name": "exec"
                        }
                    ],
                    "mitigation": "Avoid using eval() or exec() with user input. Use safer alternatives."
                },
                {
                    "id": "PY-SQL-INJECTION-001",
                    "name": "Potential SQL Injection",
                    "description": "String formatting used in SQL queries",
                    "severity": "High",
                    "patterns": [
                        {
                            "type": "function_call",
                            "name": "execute",
                            "with_string_formatting": True
                        }
                    ],
                    "mitigation": "Use parameterized queries or ORM instead of string formatting."
                }
            ]
        }
        
        # Write default rule file
        default_rule_path = os.path.join(self.rules_dir, "default_python_rules.yaml")
        try:
            with open(default_rule_path, 'w') as f:
                yaml.dump(default_rule, f, default_flow_style=False)
            
            logger.info(f"Created default rule file: {default_rule_path}")
        except Exception as e:
            logger.error(f"Error creating default rule file: {str(e)}")
            if self.verbose:
                logger.exception("Exception details:")
    
    def analyze_file(self, file_path: str, file_content: Optional[str] = None) -> Dict[str, Any]:

        _, file_ext = os.path.splitext(file_path)
        file_ext = file_ext.lower()
        
        analysis_result = {
            "success": False,
            "file": file_path,
            "vulnerabilities": []
        }
        
        # Read file content if not provided
        if file_content is None:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    file_content = f.read()
            except Exception as e:
                logger.error(f"Error reading file {file_path}: {str(e)}")
                analysis_result["error"] = f"Error reading file: {str(e)}"
                return analysis_result
        
        # Perform language-specific AST analysis
        if file_ext == '.py':
            ast_result = self._parse_python_ast(file_content, file_path)
            
            if ast_result.get("success", False):
                analysis_result["success"] = True
                analysis_result["ast"] = ast_result
                
                # Analyze AST for vulnerabilities
                vulnerabilities = self._analyze_ast_for_vulnerabilities(file_path, file_ext, ast_result)
                analysis_result["vulnerabilities"] = vulnerabilities
            else:
                analysis_result["error"] = ast_result.get("error", "Unknown error parsing AST")
        else:
            # For now, we only support Python AST analysis
            analysis_result["error"] = f"AST analysis not supported for {file_ext} files"
        
        return analysis_result
    
    def _parse_python_ast(self, content: str, file_path: str) -> Dict[str, Any]:

        result = {
            "success": False,
            "file": file_path
        }
        
        try:
            tree = ast.parse(content)
            
            # Create AST visitor to extract information
            visitor = PythonASTVisitor(file_path)
            visitor.visit(tree)
            
            result["success"] = True
            result["ast_tree"] = tree
            result["visitor"] = visitor
            result["functions"] = visitor.functions
            result["classes"] = visitor.classes
            result["calls"] = visitor.calls
            result["imports"] = visitor.imports
            result["assignments"] = visitor.assignments
            result["strings"] = visitor.strings
            
        except SyntaxError as e:
            logger.error(f"Syntax error in {file_path} at line {e.lineno}: {e.msg}")
            result["error"] = f"Syntax error at line {e.lineno}: {e.msg}"
        except Exception as e:
            logger.error(f"Error parsing AST for {file_path}: {str(e)}")
            result["error"] = f"Error parsing AST: {str(e)}"
        
        return result
    
    def _analyze_ast_for_vulnerabilities(self, file_path: str, file_ext: str, ast_result: Dict[str, Any]) -> List[Dict[str, Any]]:

        vulnerabilities = []
        
        # Get applicable rules for this file type
        applicable_rules = []
        language_key = file_ext[1:] if file_ext.startswith('.') else file_ext
        
        if language_key in self.rules:
            applicable_rules.extend(self.rules[language_key])
        
        if 'common' in self.rules:
            applicable_rules.extend(self.rules['common'])
        
        # Apply rules based on language
        if file_ext == '.py':
            visitor = ast_result.get("visitor")
            if visitor:
                python_vulns = self._apply_python_rules(file_path, visitor, applicable_rules)
                vulnerabilities.extend(python_vulns)
        
        return vulnerabilities
    
    def _apply_python_rules(self, file_path: str, visitor: 'PythonASTVisitor', rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:

        vulnerabilities = []
        
        for rule in rules:
            rule_id = rule.get('id', 'UNKNOWN')
            rule_name = rule.get('name', 'Unknown Rule')
            severity = rule.get('severity', 'Medium')
            patterns = rule.get('patterns', [])
            
            # Process each pattern in the rule
            for pattern in patterns:
                pattern_type = pattern.get('type', '')
                
                if pattern_type == 'function_call':
                    # Check for function calls matching the pattern
                    func_name = pattern.get('name', '')
                    
                    for call in visitor.calls:
                        call_name = call.get('name', '')
                        
                        # Check if the call matches the pattern
                        if call_name == func_name or (call_name.endswith(f".{func_name}") and pattern.get('include_methods', True)):
                            # Check additional pattern conditions
                            match = True
                            
                            # Check for string formatting in arguments if specified
                            if pattern.get('with_string_formatting', False):
                                # This is a simplified check - in a real implementation, 
                                # we would do more sophisticated analysis
                                args_str = str(call.get('args', []))
                                if '%s' in args_str or '{' in args_str or '+' in args_str:
                                    pass
                                else:
                                    match = False
                            
                            if match:
                                # Create vulnerability entry
                                context = visitor.get_line_context(call['line'])
                                vuln = {
                                    'rule_id': rule_id,
                                    'rule_name': rule_name,
                                    'vulnerability_type': rule_name,
                                    'file': file_path,
                                    'line': call['line'],
                                    'column': call['col'],
                                    'severity': severity,
                                    'description': rule.get('description', ''),
                                    'code_snippet': context['line'],
                                    'context': context['context'],
                                    'mitigation': rule.get('mitigation', '')
                                }
                                vulnerabilities.append(vuln)
                
                elif pattern_type == 'import':
                    # Check for imports matching the pattern
                    import_name = pattern.get('name', '')
                    
                    for imp in visitor.imports:
                        if imp.get('name') == import_name or imp.get('module') == import_name:
                            # Create vulnerability entry
                            context = visitor.get_line_context(imp['line'])
                            vuln = {
                                'rule_id': rule_id,
                                'rule_name': rule_name,
                                'vulnerability_type': rule_name,
                                'file': file_path,
                                'line': imp['line'],
                                'column': imp['col'],
                                'severity': severity,
                                'description': rule.get('description', ''),
                                'code_snippet': context['line'],
                                'context': context['context'],
                                'mitigation': rule.get('mitigation', '')
                            }
                            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _extract_function_relationships(self) -> Dict[str, Any]:

        return {}