
import os
import logging
from typing import Dict, List, Any, Tuple, Optional, Set, Union

from utils.logger import get_logger
from scanner.ast_analyzer import PythonASTVisitor

logger = get_logger()

class ControlFlowAnalyzer:
    """
    Advanced control flow analyzer for detecting logical flaws, race conditions,
    and complex vulnerabilities in source code.
    """
    
    def __init__(self, verbose=False):

        self.verbose = verbose
        
        logger.info("Initialized control flow analyzer")
    
    def analyze_file(self, file_path: str, ast_result: Dict[str, Any]) -> Dict[str, Any]:

        file_ext = os.path.splitext(file_path)[1].lower()
        
        analysis_result = {
            "success": False,
            "file": file_path,
            "vulnerabilities": []
        }
        
        # Check if we have AST results to analyze
        if not ast_result.get('success', False):
            analysis_result['error'] = "No valid AST results available for control flow analysis"
            return analysis_result
        
        # Perform language-specific analysis
        if file_ext == '.py':
            cf_result = self._analyze_python_controlflow(file_path, ast_result)
            
            if cf_result.get('success', False):
                analysis_result.update(cf_result)
                analysis_result['success'] = True
            else:
                analysis_result['error'] = cf_result.get('error', "Unknown control flow analysis error")
        else:
            # For now, we only support Python control flow analysis
            analysis_result['error'] = f"Control flow analysis not supported for {file_ext} files"
        
        return analysis_result
    
    def _analyze_python_controlflow(self, file_path: str, ast_result: Dict[str, Any]) -> Dict[str, Any]:

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
                
            # Build a simplified control flow graph
            cfg_builder = PythonCFGBuilder(visitor)
            cfg = cfg_builder.build_cfg()
            
            # Analyze exception handling patterns
            exception_issues = self._analyze_python_exception_handling(visitor, cfg)
            
            # Analyze resource handling patterns
            resource_issues = self._analyze_python_resource_handling(visitor, cfg)
            
            # Analyze logical flaws
            logical_issues = self._analyze_python_logical_flaws(visitor, cfg)
            
            # Analyze race conditions
            race_issues = self._analyze_python_race_conditions(visitor, cfg)
            
            # Analyze dead code
            dead_code_issues = self._analyze_python_dead_code(visitor, cfg)
            
            # Combine all issues
            all_issues = exception_issues + resource_issues + logical_issues + race_issues + dead_code_issues
            
            # Generate visualization data for the control flow graph
            visualization = self._generate_cfg_visualization(file_path, cfg)
            
            result.update({
                "success": True,
                "vulnerabilities": all_issues,
                "cfg": cfg,
                "visualization": visualization
            })
            
        except Exception as e:
            logger.error(f"Error in control flow analysis of {file_path}: {str(e)}")
            if self.verbose:
                logger.exception("Exception details:")
            result['error'] = f"Control flow analysis error: {str(e)}"
        
        return result
    
    def _analyze_python_exception_handling(self, visitor: 'PythonASTVisitor', 
                                          cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Analyze exception handling patterns in Python code.
        
        Args:
            visitor: AST visitor with extracted information
            cfg: Control flow graph
            
        Returns:
            list: Exception handling issues
        """
        # Placeholder - in a real implementation, this would analyze the code for:
        # - Bare except clauses
        # - Broad exception types
        # - Swallowed exceptions
        # - Missing error handling on critical operations
        
        # For now, we'll return a simplified placeholder implementation
        issues = []
        
        # This is a simplified check - we're just looking for bare except clauses
        # A real implementation would traverse the AST
        for func_name, func_info in visitor.functions.items():
            code = func_info.get('code', '')
            if 'except:' in code and not 'except Exception' in code:
                context = visitor.get_line_context(func_info['line'])
                issues.append({
                    'vulnerability_type': 'Bare except clause',
                    'file': visitor.file_path,
                    'line': func_info['line'],
                    'column': func_info['col'],
                    'severity': 'Medium',
                    'description': f"Bare except clause in function {func_name}. This will catch and suppress all exceptions, including SystemExit, KeyboardInterrupt, and MemoryError.",
                    'code_snippet': 'except:',
                    'context': context.get('context', ''),
                    'mitigation': "Specify the exception types to catch, e.g., 'except Exception:' or more specific types."
                })
        
        return issues
    
    def _analyze_python_resource_handling(self, visitor: 'PythonASTVisitor', 
                                        cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Analyze resource handling patterns in Python code.
        
        Args:
            visitor: AST visitor with extracted information
            cfg: Control flow graph
            
        Returns:
            list: Resource handling issues
        """
        # Placeholder - in a real implementation, this would analyze the code for:
        # - File handles not properly closed
        # - Database connections not properly closed
        # - Network connections not properly closed
        # - Locks not properly released
        
        issues = []
        
        # This is a simplified check - we're looking for file operations without 'with' context
        for call in visitor.calls:
            call_name = call.get('name', '')
            if call_name == 'open':
                context = visitor.get_line_context(call.get('line', 0))
                line_content = context.get('line', '')
                
                # Check if the open call is in a with statement
                if 'with ' not in line_content:
                    issues.append({
                        'vulnerability_type': 'Resource not properly managed',
                        'file': visitor.file_path,
                        'line': call.get('line', 0),
                        'column': call.get('col', 0),
                        'severity': 'Medium',
                        'description': f"File opened without using a 'with' statement, which may lead to resource leaks if the file is not explicitly closed.",
                        'code_snippet': line_content,
                        'context': context.get('context', ''),
                        'mitigation': "Use 'with open(...) as f:' to ensure the file is properly closed even if an exception occurs."
                    })
        
        return issues
    
    def _analyze_python_logical_flaws(self, visitor: 'PythonASTVisitor', 
                                    cfg: Dict[str, Any]) -> List[Dict[str, Any]]:

        issues = []
        
        return issues
    
    def _analyze_python_race_conditions(self, visitor: 'PythonASTVisitor', 
                                      cfg: Dict[str, Any]) -> List[Dict[str, Any]]:

        issues = []
        
        return issues
    
    def _analyze_python_dead_code(self, visitor: 'PythonASTVisitor', 
                                cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
        
        issues = []
        
        return issues
    
    def _generate_cfg_visualization(self, file_path: str, cfg: Dict[str, Any]) -> Dict[str, Any]:

        
        return {
            "nodes": cfg.get('nodes', []),
            "edges": cfg.get('edges', []),
            "functions": cfg.get('functions', {})
        }

class PythonCFGBuilder:
    """
    Builder for Python control flow graphs.
    """
    
    def __init__(self, visitor: 'PythonASTVisitor'):

        self.visitor = visitor
        self.cfg = {
            "nodes": [],
            "edges": [],
            "functions": {},
            "entry_points": [],
            "exit_points": []
        }
        self.node_counter = 0
    
    def build_cfg(self) -> Dict[str, Any]:

        # For each function, create a subgraph
        for func_name, func_info in self.visitor.functions.items():
            func_nodes = self._process_function_body(func_name, func_info)
            
            # Add function to the CFG
            self.cfg["functions"][func_name] = {
                "name": func_name,
                "start_node": func_nodes[0]["id"] if func_nodes else None,
                "end_nodes": [func_nodes[-1]["id"]] if func_nodes else [],
                "all_nodes": [node["id"] for node in func_nodes],
                "line": func_info.get("line", 0),
                "col": func_info.get("col", 0),
                "args": func_info.get("args", [])
            }
            
            # Add nodes to the main graph
            self.cfg["nodes"].extend(func_nodes)
            
            # Add entry point
            if func_nodes:
                self.cfg["entry_points"].append(func_nodes[0]["id"])
                self.cfg["exit_points"].append(func_nodes[-1]["id"])
        
        return self.cfg
    
    def _process_function_body(self, func_name: str, func_info: Dict[str, Any]) -> List[Dict[str, Any]]:

        # In a real implementation, this would parse the AST of the function body
        # and create nodes and edges for the control flow graph
        
        # For this placeholder implementation, we'll create a simple linear flow
        nodes = []
        
        # Create an entry node
        entry_node = self._create_node("ENTRY", func_info.get("line", 0), func_info.get("col", 0))
        entry_node["label"] = f"ENTRY: {func_name}"
        nodes.append(entry_node)
        
        # Create nodes for function calls in the function body
        call_nodes = []
        for call in func_info.get("calls", []):
            call_node = self._create_node("CALL", call.get("line", 0), call.get("col", 0))
            call_node["label"] = f"CALL: {call.get('name', 'unknown')}"
            call_node["call_info"] = call
            call_nodes.append(call_node)
        
        nodes.extend(call_nodes)
        
        # Create an exit node
        exit_node = self._create_node("EXIT", func_info.get("line", 0), func_info.get("col", 0))
        exit_node["label"] = f"EXIT: {func_name}"
        nodes.append(exit_node)
        
        # Create edges between nodes
        for i in range(len(nodes) - 1):
            self.cfg["edges"].append({
                "source": nodes[i]["id"],
                "target": nodes[i + 1]["id"],
                "type": "flow"
            })
        
        return nodes
    
    def _create_node(self, node_type: str, lineno: int, col_offset: int) -> Dict[str, Any]:

        node_id = f"node_{self.node_counter}"
        self.node_counter += 1
        
        return {
            "id": node_id,
            "type": node_type,
            "line": lineno,
            "col": col_offset,
            "label": node_type
        }
    
    def find_unreachable_nodes(self) -> List[str]:
        # In a real implementation, this would perform a reachability analysis
        # from the entry points of the CFG
        
        return []
    
    def get_path_count(self) -> int:
        # In a real implementation, this would calculate the number of distinct
        # paths through the CFG
        
        return len(self.cfg["functions"])