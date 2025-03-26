import os
import time
import logging
from typing import Dict, List, Any, Tuple, Optional, Set, Union

from utils.logger import get_logger
from scanner.ast_analyzer import PythonASTVisitor

logger = get_logger()

class SymbolicExecutor:
    """
    Symbolic execution engine for finding complex vulnerabilities and
    validating the exploitability of discovered issues.
    """
    
    def __init__(self, max_depth=10, max_paths=100, timeout=30, verbose=False):

        self.max_depth = max_depth
        self.max_paths = max_paths
        self.timeout = timeout
        self.verbose = verbose
        self.paths_explored = 0
        
        logger.info(f"Initialized symbolic executor (max_depth={max_depth}, max_paths={max_paths}, timeout={timeout}s)")
    
    def execute(self, file_path: str, vulnerabilities: List[Dict[str, Any]], 
               ast_result: Dict[str, Any], cfg_result: Dict[str, Any]) -> Dict[str, Any]:

        file_ext = os.path.splitext(file_path)[1].lower()
        
        result = {
            "success": False,
            "file": file_path,
            "validated_vulnerabilities": [],
            "paths_explored": 0,
            "execution_time": 0
        }
        
        # Check if we have AST and CFG results to analyze
        if not ast_result.get('success', False):
            result['error'] = "No valid AST results available for symbolic execution"
            return result
            
        if not cfg_result.get('success', False):
            result['error'] = "No valid CFG results available for symbolic execution"
            return result
        
        # Perform language-specific symbolic execution
        start_time = time.time()
        
        if file_ext == '.py':
            sym_result = self._execute_python_symbolically(file_path, vulnerabilities, ast_result, cfg_result)
            
            if sym_result.get('success', False):
                result.update(sym_result)
                result['success'] = True
            else:
                result['error'] = sym_result.get('error', "Unknown symbolic execution error")
        else:
            # For now, we only support Python symbolic execution
            result['error'] = f"Symbolic execution not supported for {file_ext} files"
        
        # Record execution time
        result['execution_time'] = time.time() - start_time
        
        return result
    
    def _execute_python_symbolically(self, file_path: str, vulnerabilities: List[Dict[str, Any]],
                                   ast_result: Dict[str, Any], cfg_result: Dict[str, Any]) -> Dict[str, Any]:

        result = {
            "success": False,
            "file": file_path,
            "validated_vulnerabilities": [],
            "infeasible_vulnerabilities": [],
            "paths_explored": 0
        }
        
        try:
            # Reset paths counter
            self.paths_explored = 0
            
            # Get the visitor from the AST result
            visitor = ast_result.get('visitor')
            
            if not visitor:
                result['error'] = "AST visitor not available"
                return result
            
            # Get the control flow graph
            cfg = cfg_result.get('cfg', {})
            
            if not cfg:
                result['error'] = "Control flow graph not available"
                return result
            
            # Keep track of validated and infeasible vulnerabilities
            validated_vulnerabilities = []
            infeasible_vulnerabilities = []
            
            # Record start time for timeout checking
            start_time = time.time()
            
            # For each vulnerability, perform symbolic execution to check if it's exploitable
            for vuln in vulnerabilities:
                # Get the function containing the vulnerability
                vuln_line = vuln.get('line', 0)
                containing_func = None
                func_cfg = None
                
                # Find the function containing the vulnerability
                for func_name, func_info in cfg.get('functions', {}).items():
                    func_line = func_info.get('line', 0)
                    func_nodes = func_info.get('all_nodes', [])
                    
                    # Check if there's a node in this function with the vulnerability line
                    for node_id in func_nodes:
                        for node in cfg.get('nodes', []):
                            if node['id'] == node_id and node.get('line', 0) == vuln_line:
                                containing_func = func_name
                                func_cfg = func_info
                                break
                        
                        if containing_func:
                            break
                    
                    if containing_func:
                        break
                
                if containing_func and func_cfg:
                    # Check if the vulnerability is exploitable
                    is_exploitable, exploitation_path = self._symbolically_execute_function(
                        func_cfg, vuln, visitor, start_time)
                    
                    if is_exploitable:
                        # The vulnerability is exploitable
                        exploit_difficulty = self._assess_exploitation_difficulty(vuln, exploitation_path)
                        
                        # Generate exploitation simulation
                        exploit_simulation = self.simulate_exploit(vuln, exploitation_path)
                        
                        validated_vuln = vuln.copy()
                        validated_vuln.update({
                            'validated': True,
                            'exploitation_difficulty': exploit_difficulty,
                            'exploit_path': exploitation_path,
                            'exploit_simulation': exploit_simulation
                        })
                        
                        validated_vulnerabilities.append(validated_vuln)
                        
                        if self.verbose:
                            logger.debug(f"Validated vulnerability at line {vuln_line} in function {containing_func}")
                    else:
                        # The vulnerability is not exploitable
                        infeasible_vuln = vuln.copy()
                        infeasible_vuln.update({
                            'validated': False,
                            'reason': "No feasible execution path to vulnerability"
                        })
                        
                        infeasible_vulnerabilities.append(infeasible_vuln)
                        
                        if self.verbose:
                            logger.debug(f"Could not validate vulnerability at line {vuln_line}")
                else:
                    # Could not find the function containing the vulnerability
                    infeasible_vuln = vuln.copy()
                    infeasible_vuln.update({
                        'validated': False,
                        'reason': "Could not locate containing function"
                    })
                    
                    infeasible_vulnerabilities.append(infeasible_vuln)
                    
                    if self.verbose:
                        logger.debug(f"Could not locate function containing vulnerability at line {vuln_line}")
            
            result.update({
                "success": True,
                "validated_vulnerabilities": validated_vulnerabilities,
                "infeasible_vulnerabilities": infeasible_vulnerabilities,
                "paths_explored": self.paths_explored
            })
            
        except Exception as e:
            logger.error(f"Error in symbolic execution of {file_path}: {str(e)}")
            if self.verbose:
                logger.exception("Exception details:")
            result['error'] = f"Symbolic execution error: {str(e)}"
        
        return result
    
    def _symbolically_execute_function(self, func_cfg: Dict[str, Any], vulnerability: Dict[str, Any],
                                    visitor: 'PythonASTVisitor', start_time: float) -> Tuple[bool, List[Dict[str, Any]]]:

        # This is a simplified implementation of symbolic execution
        # A real implementation would use a solver like Z3 to solve path constraints
        
        # Get the target node (vulnerability location)
        target_line = vulnerability.get('line', 0)
        target_node = None
        
        for node_id in func_cfg.get('all_nodes', []):
            for node in func_cfg.get('nodes', []):
                if node['id'] == node_id and node.get('line', 0) == target_line:
                    target_node = node
                    break
            
            if target_node:
                break
        
        if not target_node:
            return False, []
        
        # Get the entry node
        start_node_id = func_cfg.get('start_node')
        if not start_node_id:
            return False, []
        
        # Find paths from entry to vulnerability
        self.paths_explored = 0
        path = []
        constraints = []
        
        # Define the DFS function for path finding
        def dfs(node_id, depth, path, constraints):
            # Check timeout and path limits
            if time.time() - start_time > self.timeout or self.paths_explored >= self.max_paths:
                return False, []
            
            if depth > self.max_depth:
                return False, []
            
            # Get the current node
            current_node = None
            for node in func_cfg.get('nodes', []):
                if node['id'] == node_id:
                    current_node = node
                    break
            
            if not current_node:
                return False, []
            
            # Add this node to the path
            path.append(current_node)
            
            # Check if we've reached the target node
            if current_node.get('line', 0) == target_line:
                # Check if the path is feasible with these constraints
                if self._check_path_feasibility(constraints):
                    return True, path
                else:
                    # Path is not feasible
                    path.pop()
                    return False, []
            
            # Find outgoing edges
            outgoing_edges = []
            for edge in func_cfg.get('edges', []):
                if edge.get('source') == node_id:
                    outgoing_edges.append(edge)
            
            # For each outgoing edge, continue DFS
            for edge in outgoing_edges:
                target_id = edge.get('target')
                
                # Add any constraints from this edge (simplified)
                edge_constraints = []  # In real symbolic execution, we'd extract conditions here
                all_constraints = constraints + edge_constraints
                
                # Explore this path
                found, result_path = dfs(target_id, depth + 1, path.copy(), all_constraints)
                self.paths_explored += 1
                
                if found:
                    return True, result_path
            
            # No path found from this node
            return False, []
        
        # Start DFS from the entry node
        found, result_path = dfs(start_node_id, 0, [], [])
        
        return found, result_path
    
    def _check_path_feasibility(self, constraints: List[Dict[str, Any]]) -> bool:

        # In a real implementation, this would use a solver like Z3
        # For this simplified version, we'll assume all paths are feasible
        return True
    
    def _assess_exploitation_difficulty(self, vulnerability: Dict[str, Any], 
                                      path: List[Dict[str, Any]]) -> str:

        # Count the number of conditions in the path
        condition_count = sum(1 for node in path if node.get('type') == 'IF')
        
        # Check the number of parameters that need to be controlled
        tainted_var = vulnerability.get('tainted_variable', '')
        parameter_control_needed = tainted_var in str(path)
        
        # Check if authentication is required
        auth_required = 'authentication' in str(path) or 'auth' in str(path)
        
        # Determine difficulty
        if condition_count > 5 or (auth_required and parameter_control_needed):
            return 'Hard'
        elif condition_count > 2 or auth_required or parameter_control_needed:
            return 'Medium'
        else:
            return 'Easy'
    
    def simulate_exploit(self, vulnerability: Dict[str, Any], path: List[Dict[str, Any]]) -> Dict[str, Any]:

        vuln_type = vulnerability.get('vulnerability_type', '').lower()
        
        if 'sql' in vuln_type or 'sqli' in vuln_type:
            return self._generate_sql_injection_poc(vulnerability, path)
        elif 'command' in vuln_type or 'cmd' in vuln_type or 'rce' in vuln_type:
            return self._generate_command_injection_poc(vulnerability, path)
        elif 'xss' in vuln_type:
            return self._generate_xss_poc(vulnerability, path)
        elif 'path' in vuln_type or 'file' in vuln_type or 'directory' in vuln_type:
            return self._generate_path_traversal_poc(vulnerability, path)
        elif 'ssrf' in vuln_type:
            return self._generate_ssrf_poc(vulnerability, path)
        else:
            return self._generate_generic_poc(vulnerability, path)
    
    def _generate_sql_injection_poc(self, vulnerability: Dict[str, Any], 
                                  path: List[Dict[str, Any]]) -> Dict[str, Any]:

        tainted_var = vulnerability.get('tainted_variable', 'param')
        
        return {
            'type': 'sql_injection',
            'description': 'SQL Injection Proof of Concept',
            'payload': f"' OR '1'='1",
            'usage': f"Inject the payload into the {tainted_var} parameter",
            'expected_result': 'The query will return all rows, bypassing authentication or filtering',
            'impact': 'Unauthorized access to data, potential authentication bypass',
            'remediation': 'Use parameterized queries or an ORM instead of string concatenation'
        }
    
    def _generate_command_injection_poc(self, vulnerability: Dict[str, Any], 
                                      path: List[Dict[str, Any]]) -> Dict[str, Any]:

        tainted_var = vulnerability.get('tainted_variable', 'param')
        
        return {
            'type': 'command_injection',
            'description': 'Command Injection Proof of Concept',
            'payload': f"; cat /etc/passwd",
            'usage': f"Inject the payload into the {tainted_var} parameter",
            'expected_result': 'The contents of /etc/passwd will be displayed',
            'impact': 'Arbitrary command execution on the server',
            'remediation': 'Use library functions instead of shell commands, sanitize inputs with shlex.quote()'
        }
    
    def _generate_xss_poc(self, vulnerability: Dict[str, Any], 
                        path: List[Dict[str, Any]]) -> Dict[str, Any]:

        tainted_var = vulnerability.get('tainted_variable', 'param')
        
        return {
            'type': 'xss',
            'description': 'Cross-Site Scripting Proof of Concept',
            'payload': f"<script>alert('XSS')</script>",
            'usage': f"Inject the payload into the {tainted_var} parameter",
            'expected_result': 'An alert dialog with the text "XSS" will appear',
            'impact': 'Theft of cookies, session hijacking, phishing attacks',
            'remediation': 'Use context-aware escaping, template systems with automatic escaping'
        }
    
    def _generate_path_traversal_poc(self, vulnerability: Dict[str, Any], 
                                   path: List[Dict[str, Any]]) -> Dict[str, Any]:

        tainted_var = vulnerability.get('tainted_variable', 'param')
        
        return {
            'type': 'path_traversal',
            'description': 'Path Traversal Proof of Concept',
            'payload': f"../../../etc/passwd",
            'usage': f"Inject the payload into the {tainted_var} parameter",
            'expected_result': 'The contents of /etc/passwd will be accessed',
            'impact': 'Unauthorized access to files outside the intended directory',
            'remediation': 'Use os.path.normpath() and validate paths against a whitelist'
        }
    
    def _generate_ssrf_poc(self, vulnerability: Dict[str, Any], 
                         path: List[Dict[str, Any]]) -> Dict[str, Any]:

        tainted_var = vulnerability.get('tainted_variable', 'param')
        
        return {
            'type': 'ssrf',
            'description': 'Server-Side Request Forgery Proof of Concept',
            'payload': f"http://localhost:8080/admin",
            'usage': f"Inject the payload into the {tainted_var} parameter",
            'expected_result': 'The server will make a request to its own admin interface',
            'impact': 'Access to internal services, potential firewall bypass',
            'remediation': 'Validate and sanitize URLs against an allowlist, do not allow requests to internal resources'
        }
    
    def _generate_generic_poc(self, vulnerability: Dict[str, Any], 
                            path: List[Dict[str, Any]]) -> Dict[str, Any]:

        tainted_var = vulnerability.get('tainted_variable', 'param')
        vuln_type = vulnerability.get('vulnerability_type', 'Unknown')
        
        return {
            'type': 'generic',
            'description': f'{vuln_type} Proof of Concept',
            'payload': f"PAYLOAD",
            'usage': f"Inject the payload into the {tainted_var} parameter",
            'expected_result': 'Vulnerability will be triggered',
            'impact': 'Depends on the vulnerability type',
            'remediation': vulnerability.get('mitigation', 'Review and sanitize untrusted inputs')
        }