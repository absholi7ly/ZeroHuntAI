
import os
import logging
from typing import Dict, List, Any, Tuple, Optional, Set, Union

from utils.logger import get_logger
from scanner.ast_analyzer import PythonASTVisitor

logger = get_logger()

class DataFlowAnalyzer:
    """
    Advanced data flow analyzer for tracing data through applications and detecting vulnerabilities.
    Supports taint analysis and tracking of user input across execution paths.
    """
    
    def __init__(self, verbose=False):

        self.verbose = verbose
        self.tainted_vars = {}
        self.taint_sources = {
            'request.form': 'user_input',
            'request.args': 'user_input',
            'request.cookies': 'user_input',
            'request.headers': 'user_input',
            'request.data': 'user_input',
            'request.json': 'user_input',
            'input(': 'user_input',
            'sys.argv': 'command_line',
            'os.environ': 'environment',
            'open(': 'file_io',
            'sqlite3.connect': 'database',
            'mysql.connector.connect': 'database',
            'psycopg2.connect': 'database',
            'urllib.request.urlopen': 'network',
            'requests.get': 'network',
            'requests.post': 'network'
        }
        
        self.dangerous_sinks = {
            'eval(': {'type': 'code_execution', 'severity': 'High'},
            'exec(': {'type': 'code_execution', 'severity': 'High'},
            'os.system': {'type': 'command_injection', 'severity': 'High'},
            'subprocess.call': {'type': 'command_injection', 'severity': 'High'},
            'subprocess.Popen': {'type': 'command_injection', 'severity': 'High'},
            'execute': {'type': 'sql_injection', 'severity': 'High'},
            'executemany': {'type': 'sql_injection', 'severity': 'High'},
            'cursor.execute': {'type': 'sql_injection', 'severity': 'High'},
            'render_template_string': {'type': 'template_injection', 'severity': 'High'},
            'render': {'type': 'xss', 'severity': 'Medium'},
            'response.write': {'type': 'xss', 'severity': 'Medium'},
            'open(': {'type': 'path_traversal', 'severity': 'Medium'},
            'pickle.loads': {'type': 'deserialization', 'severity': 'High'},
            'yaml.load': {'type': 'deserialization', 'severity': 'High'},
            'urllib.request.urlopen': {'type': 'ssrf', 'severity': 'Medium'},
            'requests.get': {'type': 'ssrf', 'severity': 'Medium'},
            'requests.post': {'type': 'ssrf', 'severity': 'Medium'}
        }
        
        self.sanitizers = [
            'escape', 'sanitize', 'html.escape', 'markupsafe.escape', 
            'quote', 'quote_plus', 'shlex.quote', 'parameterized', 
            'prepared', 'bindparam', 'safe_string', 'validator'
        ]
        
        logger.info("Initialized data flow analyzer")
    
    def analyze_file(self, file_path: str, ast_result: Dict[str, Any]) -> Dict[str, Any]:

        file_ext = os.path.splitext(file_path)[1].lower()
        
        analysis_result = {
            "success": False,
            "file": file_path,
            "vulnerabilities": []
        }
        
        # Check if we have AST results to analyze
        if not ast_result.get('success', False):
            analysis_result['error'] = "No valid AST results available for data flow analysis"
            return analysis_result
        
        # Perform language-specific analysis
        if file_ext == '.py':
            df_result = self._analyze_python_dataflow(file_path, ast_result)
            
            if df_result.get('success', False):
                analysis_result.update(df_result)
                analysis_result['success'] = True
            else:
                analysis_result['error'] = df_result.get('error', "Unknown data flow analysis error")
        else:
            # For now, we only support Python data flow analysis
            analysis_result['error'] = f"Data flow analysis not supported for {file_ext} files"
        
        return analysis_result
    
    def _analyze_python_dataflow(self, file_path: str, ast_result: Dict[str, Any]) -> Dict[str, Any]:

        result = {
            "success": False,
            "file": file_path,
            "vulnerabilities": []
        }
        
        try:
            # Get the visitor from the AST result
            visitor = ast_result.get('visitor')
            
            if not visitor:
                result['error'] = "AST visitor not available"
                return result
            
            # Reset tainted variables
            self.tainted_vars = {}
            
            # Identify taint sources
            self._identify_taint_sources(visitor)
            
            # Propagate taint through variable assignments
            self._propagate_taint(visitor)
            
            # Check if tainted data reaches dangerous sinks
            vulnerabilities = self._check_taint_in_sinks(file_path, visitor)
            
            # Generate data flow traces for vulnerabilities
            traces = self._generate_dataflow_traces(vulnerabilities)
            
            result.update({
                "success": True,
                "vulnerabilities": vulnerabilities,
                "tainted_vars": self.tainted_vars,
                "dataflow_traces": traces
            })
            
        except Exception as e:
            logger.error(f"Error in data flow analysis of {file_path}: {str(e)}")
            if self.verbose:
                logger.exception("Exception details:")
            result['error'] = f"Data flow analysis error: {str(e)}"
        
        return result
    
    def _identify_taint_sources(self, visitor: 'PythonASTVisitor') -> None:

        # Check function calls for taint sources
        for call in visitor.calls:
            call_name = call.get('name', '')
            
            # Check if this call is a taint source
            for source, taint_type in self.taint_sources.items():
                if call_name.startswith(source) or call_name.endswith(f".{source}"):
                    # This is a taint source
                    # Mark variables that receive this value as tainted
                    
                    # Look for assignments that use this call
                    for assign in visitor.assignments:
                        target = assign.get('target', '')
                        assign_line = assign.get('line', 0)
                        call_line = call.get('line', 0)
                        
                        # Simple heuristic: if assignment is on the same line as the call
                        # or the next line, it likely uses this call's return value
                        if abs(assign_line - call_line) <= 1:
                            self._mark_as_tainted(assign, visitor, taint_type, source)
                            break
    
    def _mark_as_tainted(self, node_info: Dict[str, Any], visitor: 'PythonASTVisitor', 
                       taint_type: str, source_name: str) -> None:

        target = node_info.get('target', '')
        if target:
            self.tainted_vars[target] = {
                'taint_type': taint_type,
                'source': source_name,
                'line': node_info.get('line', 0),
                'propagated_to': []
            }
            
            if self.verbose:
                logger.debug(f"Marked {target} as tainted from {source_name} ({taint_type})")
    
    def _propagate_taint(self, visitor: 'PythonASTVisitor') -> None:

        # Simple propagation approach - any variable assigned a tainted value becomes tainted
        change_made = True
        
        # Keep propagating until no more changes are made
        while change_made:
            change_made = False
            
            for assign in visitor.assignments:
                target = assign.get('target', '')
                
                # Check if this assignment involves a tainted variable
                for var_name, taint_info in self.tainted_vars.items():
                    # Very simple check - if the tainted var appears in any context in this line
                    # This is an approximation - real dataflow analysis would be more precise
                    context = visitor.get_line_context(assign.get('line', 0))
                    
                    if var_name in context.get('line', '') and target != var_name:
                        # The target variable is now tainted through propagation
                        if target not in self.tainted_vars:
                            self.tainted_vars[target] = {
                                'taint_type': taint_info['taint_type'],
                                'source': f"propagated from {var_name}",
                                'original_source': taint_info.get('original_source', taint_info['source']),
                                'line': assign.get('line', 0),
                                'propagated_to': []
                            }
                            
                            # Record this propagation
                            taint_info['propagated_to'].append(target)
                            
                            change_made = True
                            
                            if self.verbose:
                                logger.debug(f"Propagated taint from {var_name} to {target}")
    
    def _check_taint_in_sinks(self, file_path: str, visitor: 'PythonASTVisitor') -> List[Dict[str, Any]]:

        vulnerabilities = []
        
        for call in visitor.calls:
            call_name = call.get('name', '')
            
            # Check if this call is a dangerous sink
            for sink, sink_info in self.dangerous_sinks.items():
                if call_name.startswith(sink) or call_name.endswith(f".{sink}"):
                    # This is a dangerous sink - check if it's called with tainted data
                    context = visitor.get_line_context(call.get('line', 0))
                    line_content = context.get('line', '')
                    
                    # Simplistic check - if tainted var appears in the line with the sink, flag it
                    for var_name, taint_info in self.tainted_vars.items():
                        if var_name in line_content:
                            # Check if sanitization is present
                            sanitized = False
                            for sanitizer in self.sanitizers:
                                if sanitizer in line_content:
                                    sanitized = True
                                    break
                            
                            if not sanitized:
                                # Potential vulnerability found
                                source_info = self._get_taint_source(var_name)
                                
                                vuln = {
                                    'vulnerability_type': f"Potential {sink_info['type']}",
                                    'file': file_path,
                                    'line': call.get('line', 0),
                                    'column': call.get('col', 0),
                                    'severity': sink_info['severity'],
                                    'description': f"Tainted data from {source_info} reaches dangerous sink {sink}",
                                    'code_snippet': line_content,
                                    'context': context.get('context', ''),
                                    'tainted_variable': var_name,
                                    'sink': call_name,
                                    'taint_source': source_info,
                                    'mitigation': self._get_mitigation_advice(sink_info['type'])
                                }
                                
                                vulnerabilities.append(vuln)
                                
                                if self.verbose:
                                    logger.debug(f"Found potential {sink_info['type']} at line {call.get('line', 0)}")
        
        return vulnerabilities
    
    def _get_taint_source(self, var_name: str) -> str:

        taint_info = self.tainted_vars.get(var_name, {})
        
        if 'original_source' in taint_info:
            return taint_info['original_source']
        
        return taint_info.get('source', 'unknown source')
    
    def _generate_dataflow_traces(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:

        traces = {}
        
        for i, vuln in enumerate(vulnerabilities):
            var_name = vuln.get('tainted_variable', '')
            
            if var_name in self.tainted_vars:
                trace = []
                current_var = var_name
                
                # Follow the taint chain back to its source
                while current_var in self.tainted_vars:
                    taint_info = self.tainted_vars[current_var]
                    
                    trace.append({
                        'variable': current_var,
                        'line': taint_info.get('line', 0),
                        'source': taint_info.get('source', 'unknown')
                    })
                    
                    # If this was propagated from another variable, follow that chain
                    if taint_info.get('source', '').startswith('propagated from '):
                        current_var = taint_info.get('source', '').replace('propagated from ', '')
                    else:
                        # We've reached the original source
                        break
                
                # Reverse the trace to show source -> sink order
                trace.reverse()
                
                # Add the sink as the final step in the trace
                trace.append({
                    'variable': 'sink',
                    'line': vuln.get('line', 0),
                    'source': vuln.get('sink', 'unknown sink')
                })
                
                traces[f"vulnerability_{i}"] = {
                    'type': vuln.get('vulnerability_type', 'Unknown'),
                    'trace': trace
                }
        
        return traces
    
    def _get_mitigation_advice(self, vulnerability_type: str) -> str:

        mitigations = {
            'sql_injection': 'Use parameterized queries or an ORM instead of string concatenation.',
            'command_injection': 'Use library functions instead of shell commands. If shell commands are necessary, use shlex.quote() to sanitize inputs.',
            'code_execution': 'Avoid using eval() or exec() with untrusted input. Use safer alternatives like ast.literal_eval() for parsing.',
            'xss': 'Use context-aware escaping and a template system with automatic escaping.',
            'path_traversal': 'Use os.path.normpath() and validate paths against a whitelist of allowed directories.',
            'deserialization': 'Use safe deserializers like json or yaml.safe_load() instead of pickle or yaml.load().',
            'ssrf': 'Validate and sanitize URLs against an allowlist. Do not allow requests to internal resources.'
        }
        
        return mitigations.get(vulnerability_type, 'Review and sanitize untrusted inputs before use.')