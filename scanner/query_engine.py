import os
import re
import ast
import logging
import json
from typing import Dict, List, Any, Tuple, Optional, Set, Union, Callable

from utils.logger import get_logger

logger = get_logger()

class QueryEngine:
    
    def __init__(self, verbose=False):
        """
        Initialize the query engine.
        
        Args:
            verbose (bool): Enable verbose logging
        """
        self.verbose = verbose
        self.query_cache = {}
        self.loaded_queries = {}
        self.code_database = {}
        self.query_results = {}
        
        # Language-specific query executors
        self.query_executors = {
            ".py": self._execute_python_query
        }
        
        # Initialize the default query library
        self._init_query_library()
        
        logger.info("Initialized query engine")
    
    def load_queries(self, query_dir: str) -> Dict[str, Any]:

        loaded = 0
        skipped = 0
        
        try:
            if not os.path.exists(query_dir):
                os.makedirs(query_dir)
                # Create some default queries
                self._create_default_queries(query_dir)
            
            # Load query files
            for root, _, files in os.walk(query_dir):
                for file in files:
                    if file.endswith('.json'):
                        query_file = os.path.join(root, file)
                        
                        try:
                            with open(query_file, 'r') as f:
                                query_data = json.load(f)
                            
                            query_id = query_data.get('id', file.replace('.json', ''))
                            
                            # Validate required fields
                            if not all(k in query_data for k in ['language', 'name', 'pattern']):
                                logger.warning(f"Skipping query {query_id}: Missing required fields")
                                skipped += 1
                                continue
                            
                            self.loaded_queries[query_id] = query_data
                            loaded += 1
                            
                            if self.verbose:
                                logger.debug(f"Loaded query {query_id}: {query_data['name']}")
                        
                        except Exception as e:
                            logger.error(f"Error loading query file {query_file}: {str(e)}")
                            skipped += 1
        
        except Exception as e:
            logger.error(f"Error loading queries from {query_dir}: {str(e)}")
            return {
                "success": False,
                "error": str(e)
            }
        
        return {
            "success": True,
            "loaded": loaded,
            "skipped": skipped,
            "queries": list(self.loaded_queries.keys())
        }
    
    def execute_query(self, query_id_or_text: str, project_dir: str,
                    ast_results: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:

        # Determine if this is a query ID or raw query text
        if query_id_or_text in self.loaded_queries:
            # This is a query ID
            query = self.loaded_queries[query_id_or_text]
            query_id = query_id_or_text
        else:
            # This is raw query text, parse it
            try:
                query = self._parse_query(query_id_or_text)
                query_id = "custom_query"
            except Exception as e:
                logger.error(f"Error parsing query: {str(e)}")
                return {
                    "success": False,
                    "error": f"Invalid query syntax: {str(e)}"
                }
        
        # Check if we have a compatible query executor
        language = query.get('language', 'common')
        file_extension = f".{language}" if language != 'common' else None
        
        if file_extension and file_extension not in self.query_executors:
            return {
                "success": False,
                "error": f"No query executor available for {language}"
            }
        
        # Initialize code database if needed
        if not self.code_database:
            self._build_code_database(project_dir, ast_results)
        
        # Execute the query
        if language == 'common':
            # Execute a common query across all supported languages
            results = []
            for ext, executor in self.query_executors.items():
                lang_results = executor(query, project_dir)
                results.extend(lang_results)
        else:
            # Execute query for a specific language
            executor = self.query_executors[file_extension]
            results = executor(query, project_dir)
        
        # Cache the results
        self.query_results[query_id] = results
        
        return {
            "success": True,
            "query_id": query_id,
            "query_name": query.get('name', 'Custom Query'),
            "language": language,
            "results": results,
            "result_count": len(results)
        }
    
    def _parse_query(self, query_text: str) -> Dict[str, Any]:

        # Simple parsing for demonstration
        # A real implementation would use a proper parser
        lines = query_text.strip().split('\n')
        query = {
            "name": "Custom Query",
            "description": "",
            "language": "common",
            "pattern": "",
            "severity": "Medium"
        }
        
        # Process query directives
        current_section = None
        pattern_lines = []
        
        for line in lines:
            line = line.strip()
            
            if not line or line.startswith('#'):
                continue
            
            if line.startswith('name:'):
                query['name'] = line[5:].strip()
            elif line.startswith('description:'):
                query['description'] = line[12:].strip()
            elif line.startswith('language:'):
                query['language'] = line[9:].strip()
            elif line.startswith('severity:'):
                query['severity'] = line[9:].strip()
            elif line.startswith('pattern:'):
                current_section = 'pattern'
            elif current_section == 'pattern':
                pattern_lines.append(line)
        
        if pattern_lines:
            query['pattern'] = '\n'.join(pattern_lines)
        
        if not query['pattern']:
            raise ValueError("Query must include a pattern section")
        
        return query
    
    def _build_code_database(self, project_dir: str,
                           ast_results: Optional[Dict[str, Any]] = None) -> None:

        self.code_database = {}
        
        if ast_results:
            # Use existing AST results if provided
            self.code_database['ast'] = ast_results
        
        # Add file contents to the database
        self.code_database['files'] = {}
        
        for root, _, files in os.walk(project_dir):
            for file in files:
                file_path = os.path.join(root, file)
                _, ext = os.path.splitext(file_path)
                
                # Skip binary files and other non-code files
                if ext in ['.pyc', '.jpg', '.png', '.gif', '.pdf', '.zip', '.gz', '.tar']:
                    continue
                
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    
                    rel_path = os.path.relpath(file_path, project_dir)
                    self.code_database['files'][rel_path] = {
                        'path': file_path,
                        'extension': ext,
                        'content': content,
                        'lines': content.split('\n')
                    }
                except Exception as e:
                    if self.verbose:
                        logger.debug(f"Error reading file {file_path}: {str(e)}")
    
    def _execute_python_query(self, query: Dict[str, Any], project_dir: str) -> List[Dict[str, Any]]:

        results = []
        query_type = query.get('type', 'regex')
        
        if query_type == 'regex':
            # Execute a regex-based query
            try:
                pattern = re.compile(query['pattern'], re.MULTILINE)
                
                # Search in all Python files
                for file_path, file_info in self.code_database['files'].items():
                    if not file_path.endswith('.py'):
                        continue
                    
                    content = file_info['content']
                    
                    for match in pattern.finditer(content):
                        # Get line number and context
                        line_start = content[:match.start()].count('\n') + 1
                        line_end = content[:match.end()].count('\n') + 1
                        
                        # Get matching lines for context
                        context_lines = []
                        for i in range(max(1, line_start - 2), min(len(file_info['lines']), line_end + 3)):
                            context_lines.append({
                                'line_num': i,
                                'content': file_info['lines'][i-1],
                                'is_match': i >= line_start and i <= line_end
                            })
                        
                        results.append({
                            'file': file_path,
                            'line_start': line_start,
                            'line_end': line_end,
                            'match': match.group(0),
                            'context': context_lines,
                            'query_id': query.get('id', 'custom'),
                            'severity': query.get('severity', 'Medium')
                        })
            
            except re.error as e:
                logger.error(f"Invalid regex pattern in query: {str(e)}")
                return []
        
        elif query_type == 'ast':
            # Execute an AST-based query
            if 'ast' not in self.code_database:
                logger.warning("AST analysis results not available for AST-based query")
                return []
            
            # Process AST query (simplified implementation)
            ast_pattern = query.get('pattern', '')
            ast_results = self.code_database['ast']
            
            # This would be a complex implementation in reality
            # Here we'll just do a simple demonstration using a predefined pattern
            
            if 'dangerous_eval' in ast_pattern:
                # Look for eval() calls
                for file_path, file_info in self.code_database['files'].items():
                    if not file_path.endswith('.py'):
                        continue
                    
                    content = file_info['content']
                    
                    # Simple detection of eval calls
                    for match in re.finditer(r'eval\s*\((.+?)\)', content):
                        # Get line number and context
                        line_num = content[:match.start()].count('\n') + 1
                        
                        # Get context lines
                        context_lines = []
                        for i in range(max(1, line_num - 2), min(len(file_info['lines']), line_num + 3)):
                            context_lines.append({
                                'line_num': i,
                                'content': file_info['lines'][i-1],
                                'is_match': i == line_num
                            })
                        
                        results.append({
                            'file': file_path,
                            'line_start': line_num,
                            'line_end': line_num,
                            'match': match.group(0),
                            'context': context_lines,
                            'query_id': query.get('id', 'custom'),
                            'severity': query.get('severity', 'High')
                        })
        
        return results
    
    def get_query_details(self, query_id: str) -> Dict[str, Any]:

        if query_id not in self.loaded_queries:
            return {
                "success": False,
                "error": f"Query {query_id} not found"
            }
        
        query = self.loaded_queries[query_id]
        
        return {
            "success": True,
            "query": query
        }
    
    def _init_query_library(self) -> None:
        """Initialize the default query library."""
        default_queries = {
            "py-eval-exec": {
                "id": "py-eval-exec",
                "name": "Dangerous Use of eval() or exec()",
                "description": "Detects potentially dangerous uses of eval() or exec() in Python code",
                "language": "python",
                "type": "regex",
                "pattern": r"(eval|exec)\s*\((.+?)\)",
                "severity": "High",
                "tags": ["security", "injection"]
            },
            "sql-injection": {
                "id": "sql-injection",
                "name": "SQL Injection Vulnerability",
                "description": "Detects potential SQL injection vulnerabilities in Python code",
                "language": "python",
                "type": "regex",
                "pattern": r"execute\s*\(\s*[\"']SELECT|UPDATE|INSERT|DELETE.+?%|format|f[\"']",
                "severity": "High",
                "tags": ["security", "injection", "sql"]
            },
            "hardcoded-secrets": {
                "id": "hardcoded-secrets",
                "name": "Hardcoded Secrets",
                "description": "Detects hardcoded API keys, tokens, or passwords in code",
                "language": "common",
                "type": "regex",
                "pattern": r"(?:api_key|apikey|token|secret|password|pwd|auth)\s*=\s*['\"]([a-zA-Z0-9_\-\.]{16,})['\"]",
                "severity": "High",
                "tags": ["security", "secrets"]
            },
            "py-os-command-injection": {
                "id": "py-os-command-injection",
                "name": "OS Command Injection in Python",
                "description": "Detects potential OS command injection vulnerabilities in Python code",
                "language": "python",
                "type": "regex",
                "pattern": r"os\.(system|popen|spawn|exec)|subprocess\.(call|run|Popen|check_output|check_call)",
                "severity": "High",
                "tags": ["security", "injection", "command"]
            },
            "insecure-deserialization": {
                "id": "insecure-deserialization",
                "name": "Insecure Deserialization",
                "description": "Detects insecure deserialization that might lead to remote code execution",
                "language": "python",
                "type": "regex",
                "pattern": r"(pickle|cPickle|marshal|yaml)\.(loads?|unsafe_loads?)",
                "severity": "High",
                "tags": ["security", "deserialization"]
            },
            "weak-crypto": {
                "id": "weak-crypto",
                "name": "Weak Cryptography",
                "description": "Detects uses of weak cryptographic algorithms or modes",
                "language": "python",
                "type": "regex",
                "pattern": r"(md5|sha1|DES|RC4)",
                "severity": "Medium",
                "tags": ["security", "crypto"]
            },
            "xxe-vulnerability": {
                "id": "xxe-vulnerability",
                "name": "XML External Entity (XXE) Vulnerability",
                "description": "Detects potential XXE vulnerabilities in XML parsing",
                "language": "python",
                "type": "regex",
                "pattern": r"(xml\.etree\.ElementTree|xml\.dom\.minidom|lxml\.etree)\.parse\([^,]*\)",
                "severity": "High",
                "tags": ["security", "xxe"]
            },
            "cors-misconfiguration": {
                "id": "cors-misconfiguration",
                "name": "CORS Misconfiguration",
                "description": "Detects potential CORS misconfigurations that allow unintended cross-origin access",
                "language": "python",
                "type": "regex",
                "pattern": r"(Access-Control-Allow-Origin).*[*]",
                "severity": "Medium",
                "tags": ["security", "cors"]
            },
            "directory-traversal": {
                "id": "directory-traversal",
                "name": "Directory Traversal",
                "description": "Detects code patterns that might allow directory traversal attacks",
                "language": "python",
                "type": "regex",
                "pattern": r"open\s*\(\s*[^,)]+\s*\+",
                "severity": "High",
                "tags": ["security", "file-access"]
            },
            "ssrf-vulnerability": {
                "id": "ssrf-vulnerability",
                "name": "Server-Side Request Forgery (SSRF)",
                "description": "Detects code patterns that might allow SSRF attacks",
                "language": "python",
                "type": "regex",
                "pattern": r"(urllib\.request\.urlopen|requests\.(get|post|put|delete))\s*\(\s*[^,)]*\)",
                "severity": "High",
                "tags": ["security", "ssrf"]
            }
        }
        
        # Load default queries into the query library
        self.loaded_queries.update(default_queries)
    
    def _create_default_queries(self, query_dir: str) -> None:

        # Write each default query to a file
        for query_id, query in self.loaded_queries.items():
            query_file = os.path.join(query_dir, f"{query_id}.json")
            
            try:
                with open(query_file, 'w') as f:
                    json.dump(query, f, indent=4)
                
                if self.verbose:
                    logger.debug(f"Created default query file: {query_file}")
            
            except Exception as e:
                logger.error(f"Error creating default query file {query_file}: {str(e)}")
    
    def create_query(self, query_data: Dict[str, Any]) -> Dict[str, Any]:
        # Validate required fields
        if not all(k in query_data for k in ['name', 'pattern', 'language']):
            return {
                "success": False,
                "error": "Missing required fields: name, pattern, language"
            }
        
        # Generate a unique ID if not provided
        if 'id' not in query_data:
            base_id = query_data['name'].lower().replace(' ', '-')
            query_id = base_id
            counter = 1
            
            while query_id in self.loaded_queries:
                query_id = f"{base_id}-{counter}"
                counter += 1
            
            query_data['id'] = query_id
        else:
            query_id = query_data['id']
            
            # Check if ID already exists
            if query_id in self.loaded_queries:
                return {
                    "success": False,
                    "error": f"Query ID '{query_id}' already exists"
                }
        
        # Add defaults for optional fields
        if 'description' not in query_data:
            query_data['description'] = f"Custom query: {query_data['name']}"
        
        if 'severity' not in query_data:
            query_data['severity'] = "Medium"
        
        if 'type' not in query_data:
            query_data['type'] = "regex"
        
        if 'tags' not in query_data:
            query_data['tags'] = ["custom"]
        
        # Add the query to the library
        self.loaded_queries[query_id] = query_data
        
        return {
            "success": True,
            "query_id": query_id,
            "query": query_data
        }