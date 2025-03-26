import os
import json
import re
import logging
import datetime
from typing import Dict, List, Any, Tuple, Optional, Set, Union
import pkg_resources
import sys
import subprocess

from utils.logger import get_logger

logger = get_logger()

class DependencyAnalyzer:
    """
    Analyzer for detecting vulnerabilities in project dependencies and third-party libraries.
    """
    
    def __init__(self, verbose=False):

        self.verbose = verbose
        self.dependency_files = {
            "python": ["requirements.txt", "Pipfile", "Pipfile.lock", "setup.py", "pyproject.toml"],
            "javascript": ["package.json", "package-lock.json", "yarn.lock", "npm-shrinkwrap.json"],
            "php": ["composer.json", "composer.lock"],
            "ruby": ["Gemfile", "Gemfile.lock"],
            "java": ["pom.xml", "build.gradle", "build.gradle.kts"],
            "dotnet": ["*.csproj", "packages.config", "project.json"],
            "go": ["go.mod", "go.sum", "Gopkg.lock", "Gopkg.toml"]
        }
        
        # Local vulnerability database (would be updated regularly in a real implementation)
        self.vulnerability_db = self._load_vulnerability_database()
        
        logger.info("Initialized dependency analyzer")
    
    def scan_dependencies(self, project_dir: str) -> Dict[str, Any]:

        # Find dependency files
        dependency_files = self._find_dependency_files(project_dir)
        
        if not dependency_files:
            logger.info(f"No dependency files found in {project_dir}")
            return {
                "success": False,
                "error": "No dependency files found"
            }
        
        # Parse dependencies from each file
        dependencies = {}
        for file_info in dependency_files:
            file_path = file_info["path"]
            language = file_info["language"]
            
            file_deps = self._parse_dependencies(file_path, language)
            
            if language not in dependencies:
                dependencies[language] = []
            
            dependencies[language].extend(file_deps)
        
        # Check for vulnerabilities
        vulnerabilities = self._check_vulnerabilities(dependencies)
        
        # Remove duplicates
        unique_vulns = self._deduplicate_vulnerabilities(vulnerabilities)
        
        return {
            "success": True,
            "project_dir": project_dir,
            "dependencies": dependencies,
            "vulnerabilities": unique_vulns,
            "stats": {
                "total_dependencies": sum(len(deps) for deps in dependencies.values()),
                "total_vulnerabilities": len(unique_vulns),
                "critical_vulnerabilities": sum(1 for vuln in unique_vulns if vuln.get("severity") == "Critical"),
                "high_vulnerabilities": sum(1 for vuln in unique_vulns if vuln.get("severity") == "High"),
                "medium_vulnerabilities": sum(1 for vuln in unique_vulns if vuln.get("severity") == "Medium"),
                "low_vulnerabilities": sum(1 for vuln in unique_vulns if vuln.get("severity") == "Low")
            }
        }
    
    def _find_dependency_files(self, project_dir: str) -> List[Dict[str, Any]]:

        dependency_files = []
        
        for root, _, files in os.walk(project_dir):
            for file in files:
                file_path = os.path.join(root, file)
                
                # Check if this file matches any known dependency file pattern
                for language, patterns in self.dependency_files.items():
                    for pattern in patterns:
                        if pattern.startswith("*"):
                            # Handle extension patterns like "*.csproj"
                            if file.endswith(pattern[1:]):
                                dependency_files.append({
                                    "path": file_path,
                                    "language": language,
                                    "type": pattern
                                })
                                break
                        elif file == pattern:
                            # Handle exact matches
                            dependency_files.append({
                                "path": file_path,
                                "language": language,
                                "type": pattern
                            })
                            break
        
        return dependency_files
    
    def _parse_dependencies(self, file_path: str, language: str) -> List[Dict[str, Any]]:

        dependencies = []
        
        # Get the file extension
        _, ext = os.path.splitext(file_path)
        file_name = os.path.basename(file_path)
        
        try:
            if language == "python":
                if file_name == "requirements.txt":
                    dependencies = self._parse_requirements_txt(file_path)
                elif file_name == "setup.py":
                    dependencies = self._parse_setup_py(file_path)
                elif file_name == "pyproject.toml":
                    dependencies = self._parse_pyproject_toml(file_path)
                elif file_name in ["Pipfile", "Pipfile.lock"]:
                    dependencies = self._parse_pipfile(file_path)
            
            elif language == "javascript":
                if file_name == "package.json":
                    dependencies = self._parse_package_json(file_path)
                elif file_name in ["package-lock.json", "npm-shrinkwrap.json"]:
                    dependencies = self._parse_package_lock(file_path)
                elif file_name == "yarn.lock":
                    dependencies = self._parse_yarn_lock(file_path)
            
            elif language == "php":
                if file_name in ["composer.json", "composer.lock"]:
                    dependencies = self._parse_composer_file(file_path)
            
            elif language == "java":
                if file_name == "pom.xml":
                    dependencies = self._parse_pom_xml(file_path)
                elif file_name.startswith("build.gradle"):
                    dependencies = self._parse_gradle_file(file_path)
            
            elif language == "dotnet":
                if ext == ".csproj" or file_name == "packages.config" or file_name == "project.json":
                    dependencies = self._parse_dotnet_deps(file_path)
            
            elif language == "go":
                if file_name in ["go.mod", "go.sum", "Gopkg.lock", "Gopkg.toml"]:
                    dependencies = self._parse_go_deps(file_path)
        
        except Exception as e:
            logger.error(f"Error parsing dependencies from {file_path}: {str(e)}")
            if self.verbose:
                logger.exception("Exception details:")
        
        return dependencies
    
    def _parse_requirements_txt(self, file_path: str) -> List[Dict[str, Any]]:

        dependencies = []
        
        try:
            with open(file_path, 'r') as f:
                lines = f.readlines()
            
            for line in lines:
                line = line.strip()
                
                # Skip comments and empty lines
                if not line or line.startswith('#'):
                    continue
                
                # Handle inline comments
                if '#' in line:
                    line = line.split('#')[0].strip()
                
                # Skip git/URL dependencies for simplicity
                if line.startswith(('git+', 'http:', 'https:')):
                    continue
                
                # Parse package and version
                if '==' in line:
                    package, version = line.split('==', 1)
                    version_constraint = "=="
                elif '>=' in line:
                    package, version = line.split('>=', 1)
                    version_constraint = ">="
                elif '<=' in line:
                    package, version = line.split('<=', 1)
                    version_constraint = "<="
                elif '>' in line:
                    package, version = line.split('>', 1)
                    version_constraint = ">"
                elif '<' in line:
                    package, version = line.split('<', 1)
                    version_constraint = "<"
                elif '~=' in line:
                    package, version = line.split('~=', 1)
                    version_constraint = "~="
                else:
                    # No version specified
                    package = line
                    version = ""
                    version_constraint = ""
                
                # Clean up package name
                package = package.strip()
                if version:
                    version = version.strip()
                
                # Skip complex requirements for simplicity
                if ';' in package:
                    package = package.split(';')[0].strip()
                
                dependencies.append({
                    "name": package,
                    "version": version,
                    "version_constraint": version_constraint,
                    "language": "python",
                    "source": "requirements.txt"
                })
        
        except Exception as e:
            logger.error(f"Error parsing requirements.txt: {str(e)}")
            if self.verbose:
                logger.exception("Exception details:")
        
        return dependencies
    
    def _parse_setup_py(self, file_path: str) -> List[Dict[str, Any]]:

        dependencies = []
        
        try:
            with open(file_path, 'r') as f:
                content = f.read()
            
            # Look for install_requires section
            install_requires_match = re.search(r'install_requires\s*=\s*\[(.*?)\]', content, re.DOTALL)
            if install_requires_match:
                install_requires = install_requires_match.group(1)
                
                # Extract package names using regex
                for match in re.finditer(r'[\'"]([^\'\"]+?)[\'"]', install_requires):
                    dep = match.group(1)
                    
                    # Parse package and version
                    if '==' in dep:
                        package, version = dep.split('==', 1)
                        version_constraint = "=="
                    elif '>=' in dep:
                        package, version = dep.split('>=', 1)
                        version_constraint = ">="
                    elif '<=' in dep:
                        package, version = dep.split('<=', 1)
                        version_constraint = "<="
                    elif '>' in dep:
                        package, version = dep.split('>', 1)
                        version_constraint = ">"
                    elif '<' in dep:
                        package, version = dep.split('<', 1)
                        version_constraint = "<"
                    elif '~=' in dep:
                        package, version = dep.split('~=', 1)
                        version_constraint = "~="
                    else:
                        # No version specified
                        package = dep
                        version = ""
                        version_constraint = ""
                    
                    dependencies.append({
                        "name": package.strip(),
                        "version": version.strip() if version else "",
                        "version_constraint": version_constraint,
                        "language": "python",
                        "source": "setup.py"
                    })
        
        except Exception as e:
            logger.error(f"Error parsing setup.py: {str(e)}")
            if self.verbose:
                logger.exception("Exception details:")
        
        return dependencies
    
    def _parse_pyproject_toml(self, file_path: str) -> List[Dict[str, Any]]:

        dependencies = []
        
        try:
            # Try to use tomli if available
            try:
                import tomli
                with open(file_path, 'rb') as f:
                    data = tomli.load(f)
            except ImportError:
                # Fallback to simple parsing
                with open(file_path, 'r') as f:
                    content = f.read()
                
                # Look for dependencies section
                deps_section = None
                if '[tool.poetry.dependencies]' in content:
                    deps_section = '[tool.poetry.dependencies]'
                elif '[project.dependencies]' in content:
                    deps_section = '[project.dependencies]'
                
                if deps_section:
                    # Extract dependencies using regex
                    section_match = re.search(f'{re.escape(deps_section)}(.*?)(\n\[|$)', content, re.DOTALL)
                    if section_match:
                        section_content = section_match.group(1)
                        
                        # Parse each dependency line
                        for line in section_content.split('\n'):
                            line = line.strip()
                            if not line or '=' not in line:
                                continue
                            
                            # Parse name and version
                            name_part, version_part = line.split('=', 1)
                            name = name_part.strip()
                            
                            # Handle quoted versions
                            version_match = re.search(r'[\'"]([^\'"]+)[\'"]', version_part)
                            version = version_match.group(1) if version_match else version_part.strip()
                            
                            dependencies.append({
                                "name": name,
                                "version": version,
                                "version_constraint": "==",  # Simplified
                                "language": "python",
                                "source": "pyproject.toml"
                            })
                
                return dependencies
            
            # Process data from tomli
            project_deps = []
            
            # Check for poetry dependencies
            if 'tool' in data and 'poetry' in data['tool'] and 'dependencies' in data['tool']['poetry']:
                poetry_deps = data['tool']['poetry']['dependencies']
                for name, version_info in poetry_deps.items():
                    if name == 'python':
                        continue  # Skip Python version requirement
                    
                    if isinstance(version_info, str):
                        version = version_info
                        version_constraint = "=="  # Simplified
                    elif isinstance(version_info, dict) and 'version' in version_info:
                        version = version_info['version']
                        version_constraint = "=="  # Simplified
                    else:
                        version = ""
                        version_constraint = ""
                    
                    project_deps.append({
                        "name": name,
                        "version": version,
                        "version_constraint": version_constraint,
                        "language": "python",
                        "source": "pyproject.toml (poetry)"
                    })
            
            # Check for PEP 621 project dependencies
            if 'project' in data and 'dependencies' in data['project']:
                for dep in data['project']['dependencies']:
                    if '>=' in dep:
                        name, version = dep.split('>=', 1)
                        version_constraint = ">="
                    elif '<=' in dep:
                        name, version = dep.split('<=', 1)
                        version_constraint = "<="
                    elif '==' in dep:
                        name, version = dep.split('==', 1)
                        version_constraint = "=="
                    elif '>' in dep:
                        name, version = dep.split('>', 1)
                        version_constraint = ">"
                    elif '<' in dep:
                        name, version = dep.split('<', 1)
                        version_constraint = "<"
                    elif '~=' in dep:
                        name, version = dep.split('~=', 1)
                        version_constraint = "~="
                    else:
                        # No version specified
                        name = dep
                        version = ""
                        version_constraint = ""
                    
                    project_deps.append({
                        "name": name.strip(),
                        "version": version.strip() if version else "",
                        "version_constraint": version_constraint,
                        "language": "python",
                        "source": "pyproject.toml (PEP 621)"
                    })
            
            dependencies.extend(project_deps)
        
        except Exception as e:
            logger.error(f"Error parsing pyproject.toml: {str(e)}")
            if self.verbose:
                logger.exception("Exception details:")
        
        return dependencies
    
    def _parse_pipfile(self, file_path: str) -> List[Dict[str, Any]]:

        dependencies = []
        
        try:
            # Pipfile.lock is JSON
            if file_path.endswith('.lock'):
                with open(file_path, 'r') as f:
                    data = json.load(f)
                
                # Process default dependencies
                if 'default' in data:
                    for name, info in data['default'].items():
                        version = info.get('version', '')
                        
                        # Clean up version string
                        if version.startswith('=='):
                            version = version[2:]
                        
                        dependencies.append({
                            "name": name,
                            "version": version,
                            "version_constraint": "==",
                            "language": "python",
                            "source": "Pipfile.lock (default)"
                        })
                
                # Process development dependencies
                if 'develop' in data:
                    for name, info in data['develop'].items():
                        version = info.get('version', '')
                        
                        # Clean up version string
                        if version.startswith('=='):
                            version = version[2:]
                        
                        dependencies.append({
                            "name": name,
                            "version": version,
                            "version_constraint": "==",
                            "language": "python",
                            "source": "Pipfile.lock (develop)"
                        })
            
            # Pipfile is TOML
            else:
                try:
                    import toml
                    with open(file_path, 'r') as f:
                        data = toml.load(f)
                    
                    # Process default packages
                    if 'packages' in data:
                        for name, version in data['packages'].items():
                            if isinstance(version, str):
                                version_str = version
                                version_constraint = "=="
                            else:
                                version_str = ""
                                version_constraint = ""
                            
                            dependencies.append({
                                "name": name,
                                "version": version_str,
                                "version_constraint": version_constraint,
                                "language": "python",
                                "source": "Pipfile (packages)"
                            })
                    
                    # Process development packages
                    if 'dev-packages' in data:
                        for name, version in data['dev-packages'].items():
                            if isinstance(version, str):
                                version_str = version
                                version_constraint = "=="
                            else:
                                version_str = ""
                                version_constraint = ""
                            
                            dependencies.append({
                                "name": name,
                                "version": version_str,
                                "version_constraint": version_constraint,
                                "language": "python",
                                "source": "Pipfile (dev-packages)"
                            })
                
                except ImportError:
                    logger.warning("toml package not available, skipping Pipfile parsing")
        
        except Exception as e:
            logger.error(f"Error parsing Pipfile: {str(e)}")
            if self.verbose:
                logger.exception("Exception details:")
        
        return dependencies
    
    def _parse_package_json(self, file_path: str) -> List[Dict[str, Any]]:

        dependencies = []
        
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            # Process dependencies
            if 'dependencies' in data:
                for name, version in data['dependencies'].items():
                    dependencies.append({
                        "name": name,
                        "version": version,
                        "version_constraint": version[0] if version and version[0] in ["^", "~", ">", "<", "="] else "==",
                        "language": "javascript",
                        "source": "package.json (dependencies)"
                    })
            
            # Process dev dependencies
            if 'devDependencies' in data:
                for name, version in data['devDependencies'].items():
                    dependencies.append({
                        "name": name,
                        "version": version,
                        "version_constraint": version[0] if version and version[0] in ["^", "~", ">", "<", "="] else "==",
                        "language": "javascript",
                        "source": "package.json (devDependencies)"
                    })
        
        except Exception as e:
            logger.error(f"Error parsing package.json: {str(e)}")
            if self.verbose:
                logger.exception("Exception details:")
        
        return dependencies
    
    def _parse_package_lock(self, file_path: str) -> List[Dict[str, Any]]:

        dependencies = []
        
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            # NPM lockfile v2 format (package-lock.json v2)
            if 'packages' in data:
                for path, info in data['packages'].items():
                    if path == "":
                        continue  # Skip root package
                    
                    # Extract package name (last part of the path)
                    name = path.split('/')[-1]
                    
                    if '@' in name:
                        # Handle scoped packages
                        name_parts = name.split('@')
                        if len(name_parts) > 2:
                            # Scoped package with version
                            name = '@' + name_parts[1]
                            version = name_parts[2]
                        else:
                            name = '@' + name_parts[1]
                            version = info.get('version', '')
                    else:
                        version = info.get('version', '')
                    
                    dependencies.append({
                        "name": name,
                        "version": version,
                        "version_constraint": "==",
                        "language": "javascript",
                        "source": os.path.basename(file_path)
                    })
            
            # NPM lockfile v1 format (package-lock.json v1)
            elif 'dependencies' in data:
                for name, info in data['dependencies'].items():
                    version = info.get('version', '')
                    dependencies.append({
                        "name": name,
                        "version": version,
                        "version_constraint": "==",
                        "language": "javascript",
                        "source": os.path.basename(file_path)
                    })
        
        except Exception as e:
            logger.error(f"Error parsing {os.path.basename(file_path)}: {str(e)}")
            if self.verbose:
                logger.exception("Exception details:")
        
        return dependencies
    
    def _parse_yarn_lock(self, file_path: str) -> List[Dict[str, Any]]:

        dependencies = []
        
        try:
            with open(file_path, 'r') as f:
                content = f.read()
            
            # Parse yarn.lock entries
            for match in re.finditer(r'([^\n"]+@[^\n"]+):\n\s+version\s+"([^"]+)"', content):
                package_spec = match.group(1)
                version = match.group(2)
                
                # Extract package name from spec
                name = package_spec.split('@')[0]
                
                # Handle scoped packages
                if name.startswith('"@'):
                    name = '@' + package_spec.split('@')[1].split('@')[0]
                
                dependencies.append({
                    "name": name,
                    "version": version,
                    "version_constraint": "==",
                    "language": "javascript",
                    "source": "yarn.lock"
                })
        
        except Exception as e:
            logger.error(f"Error parsing yarn.lock: {str(e)}")
            if self.verbose:
                logger.exception("Exception details:")
        
        return dependencies
    
    def _parse_composer_file(self, file_path: str) -> List[Dict[str, Any]]:

        dependencies = []
        
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            # Parse composer.lock
            if os.path.basename(file_path) == 'composer.lock':
                if 'packages' in data:
                    for package in data['packages']:
                        name = package.get('name', '')
                        version = package.get('version', '')
                        
                        dependencies.append({
                            "name": name,
                            "version": version,
                            "version_constraint": "==",
                            "language": "php",
                            "source": "composer.lock"
                        })
            
            # Parse composer.json
            else:
                # Process require dependencies
                if 'require' in data:
                    for name, version in data['require'].items():
                        if name == 'php':
                            continue  # Skip PHP version requirement
                        
                        dependencies.append({
                            "name": name,
                            "version": version,
                            "version_constraint": "==",  # Simplified
                            "language": "php",
                            "source": "composer.json (require)"
                        })
                
                # Process require-dev dependencies
                if 'require-dev' in data:
                    for name, version in data['require-dev'].items():
                        dependencies.append({
                            "name": name,
                            "version": version,
                            "version_constraint": "==",  # Simplified
                            "language": "php",
                            "source": "composer.json (require-dev)"
                        })
        
        except Exception as e:
            logger.error(f"Error parsing {os.path.basename(file_path)}: {str(e)}")
            if self.verbose:
                logger.exception("Exception details:")
        
        return dependencies
    
    def _parse_pom_xml(self, file_path: str) -> List[Dict[str, Any]]:

        dependencies = []
        
        try:
            with open(file_path, 'r') as f:
                content = f.read()
            
            # Find dependencies section
            deps_section_match = re.search(r'<dependencies>(.*?)</dependencies>', content, re.DOTALL)
            if deps_section_match:
                deps_section = deps_section_match.group(1)
                
                # Extract each dependency
                for dep_match in re.finditer(r'<dependency>(.*?)</dependency>', deps_section, re.DOTALL):
                    dep_content = dep_match.group(1)
                    
                    # Extract groupId
                    group_id_match = re.search(r'<groupId>(.*?)</groupId>', dep_content)
                    group_id = group_id_match.group(1) if group_id_match else ''
                    
                    # Extract artifactId
                    artifact_id_match = re.search(r'<artifactId>(.*?)</artifactId>', dep_content)
                    artifact_id = artifact_id_match.group(1) if artifact_id_match else ''
                    
                    # Extract version
                    version_match = re.search(r'<version>(.*?)</version>', dep_content)
                    version = version_match.group(1) if version_match else ''
                    
                    if group_id and artifact_id:
                        dependencies.append({
                            "name": f"{group_id}:{artifact_id}",
                            "version": version,
                            "version_constraint": "==",
                            "language": "java",
                            "source": "pom.xml"
                        })
        
        except Exception as e:
            logger.error(f"Error parsing pom.xml: {str(e)}")
            if self.verbose:
                logger.exception("Exception details:")
        
        return dependencies
    
    def _parse_gradle_file(self, file_path: str) -> List[Dict[str, Any]]:

        dependencies = []
        
        try:
            with open(file_path, 'r') as f:
                content = f.read()
            
            # Find dependencies section (both Groovy and Kotlin DSL)
            deps_regex = r'dependencies\s*\{(.*?)\}'
            deps_match = re.search(deps_regex, content, re.DOTALL)
            
            if deps_match:
                deps_section = deps_match.group(1)
                
                # Extract dependencies
                # Match patterns like:
                # - implementation 'group:artifact:version'
                # - implementation("group:artifact:version")
                # - api "group:artifact:version"
                dep_pattern = r'(?:implementation|api|compile|runtime|testImplementation|testRuntime|testCompile)\s*[\(\'"]([^:\'"]+):([^:\'"]+):([^\'"]+)[\)\'"]'
                
                for match in re.finditer(dep_pattern, deps_section):
                    group_id = match.group(1)
                    artifact_id = match.group(2)
                    version = match.group(3)
                    
                    dependencies.append({
                        "name": f"{group_id}:{artifact_id}",
                        "version": version,
                        "version_constraint": "==",
                        "language": "java",
                        "source": os.path.basename(file_path)
                    })
        
        except Exception as e:
            logger.error(f"Error parsing {os.path.basename(file_path)}: {str(e)}")
            if self.verbose:
                logger.exception("Exception details:")
        
        return dependencies
    
    def _parse_dotnet_deps(self, file_path: str) -> List[Dict[str, Any]]:

        dependencies = []
        
        try:
            with open(file_path, 'r') as f:
                content = f.read()
            
            file_name = os.path.basename(file_path)
            
            if file_name.endswith('.csproj'):
                # Parse PackageReference elements in .csproj
                for match in re.finditer(r'<PackageReference\s+Include="([^"]+)"\s+Version="([^"]+)"', content):
                    package_name = match.group(1)
                    version = match.group(2)
                    
                    dependencies.append({
                        "name": package_name,
                        "version": version,
                        "version_constraint": "==",
                        "language": "dotnet",
                        "source": file_name
                    })
            
            elif file_name == 'packages.config':
                # Parse packages.config
                for match in re.finditer(r'<package\s+id="([^"]+)"\s+version="([^"]+)"', content):
                    package_name = match.group(1)
                    version = match.group(2)
                    
                    dependencies.append({
                        "name": package_name,
                        "version": version,
                        "version_constraint": "==",
                        "language": "dotnet",
                        "source": "packages.config"
                    })
            
            elif file_name == 'project.json':
                # Parse project.json (older .NET Core format)
                try:
                    data = json.loads(content)
                    
                    if 'dependencies' in data:
                        for name, version in data['dependencies'].items():
                            if isinstance(version, str):
                                version_str = version
                            else:
                                version_str = version.get('version', '')
                            
                            dependencies.append({
                                "name": name,
                                "version": version_str,
                                "version_constraint": "==",
                                "language": "dotnet",
                                "source": "project.json"
                            })
                
                except json.JSONDecodeError:
                    logger.error(f"Error parsing project.json: Invalid JSON")
        
        except Exception as e:
            logger.error(f"Error parsing {os.path.basename(file_path)}: {str(e)}")
            if self.verbose:
                logger.exception("Exception details:")
        
        return dependencies
    
    def _parse_go_deps(self, file_path: str) -> List[Dict[str, Any]]:

        dependencies = []
        
        try:
            with open(file_path, 'r') as f:
                content = f.readlines()
            
            file_name = os.path.basename(file_path)
            
            if file_name == 'go.mod':
                # Process require statements in go.mod
                in_require_block = False
                
                for line in content:
                    line = line.strip()
                    
                    # Check for require block
                    if line == 'require (' and not in_require_block:
                        in_require_block = True
                        continue
                    elif line == ')' and in_require_block:
                        in_require_block = False
                        continue
                    
                    # Parse single-line require
                    require_match = re.match(r'require\s+([^ ]+)\s+(.+)', line)
                    if require_match:
                        module = require_match.group(1)
                        version = require_match.group(2).strip()
                        
                        # Clean up version string
                        version = version.strip('v')
                        
                        dependencies.append({
                            "name": module,
                            "version": version,
                            "version_constraint": "==",
                            "language": "go",
                            "source": "go.mod"
                        })
                        continue
                    
                    # Parse require block entry
                    if in_require_block:
                        parts = line.split()
                        if len(parts) >= 2:
                            module = parts[0]
                            version = parts[1].strip()
                            
                            # Clean up version string
                            version = version.strip('v')
                            
                            dependencies.append({
                                "name": module,
                                "version": version,
                                "version_constraint": "==",
                                "language": "go",
                                "source": "go.mod"
                            })
            
            elif file_name == 'Gopkg.toml':
                # Parse Gopkg.toml constraints
                for line in content:
                    line = line.strip()
                    
                    # Match [[constraint]] sections
                    constraint_match = re.match(r'name\s*=\s*"([^"]+)"', line)
                    if constraint_match:
                        module = constraint_match.group(1)
                        
                        # Look for version constraints
                        version = ""
                        for version_line in content:
                            version_match = re.match(r'version\s*=\s*"([^"]+)"', version_line.strip())
                            if version_match:
                                version = version_match.group(1)
                                break
                        
                        dependencies.append({
                            "name": module,
                            "version": version,
                            "version_constraint": "==",
                            "language": "go",
                            "source": "Gopkg.toml"
                        })
            
            elif file_name == 'Gopkg.lock':
                # Parse Gopkg.lock projects
                in_project = False
                current_project = {}
                
                for line in content:
                    line = line.strip()
                    
                    if line == '[[projects]]':
                        in_project = True
                        current_project = {}
                        continue
                    
                    if in_project:
                        name_match = re.match(r'name\s*=\s*"([^"]+)"', line)
                        if name_match:
                            current_project["name"] = name_match.group(1)
                        
                        version_match = re.match(r'version\s*=\s*"([^"]+)"', line)
                        if version_match:
                            current_project["version"] = version_match.group(1)
                        
                        # If we have both name and version, add to dependencies
                        if "name" in current_project and "version" in current_project:
                            dependencies.append({
                                "name": current_project["name"],
                                "version": current_project["version"],
                                "version_constraint": "==",
                                "language": "go",
                                "source": "Gopkg.lock"
                            })
                            in_project = False
            
            elif file_name == 'go.sum':
                # Parse go.sum file
                for line in content:
                    line = line.strip()
                    parts = line.split()
                    
                    if len(parts) >= 2:
                        # Format: module version [hash]
                        module_parts = parts[0].rsplit('/', 1)
                        if len(module_parts) > 1 and re.match(r'v\d+\.\d+\.\d+.*', module_parts[-1]):
                            # Skip version suffix in module path
                            continue
                        
                        module = parts[0]
                        version = parts[1]
                        
                        # Only add if not a checksum line
                        if not version.startswith('h1:'):
                            dependencies.append({
                                "name": module,
                                "version": version,
                                "version_constraint": "==",
                                "language": "go",
                                "source": "go.sum"
                            })
        
        except Exception as e:
            logger.error(f"Error parsing {os.path.basename(file_path)}: {str(e)}")
            if self.verbose:
                logger.exception("Exception details:")
        
        return dependencies
    
    def _check_vulnerabilities(self, dependencies: Dict[str, List[Dict[str, Any]]]) -> List[Dict[str, Any]]:

        vulnerabilities = []
        
        # Flatten dependencies to make it easier to search
        all_deps = []
        for language, deps in dependencies.items():
            all_deps.extend(deps)
        
        # Check each dependency against the vulnerability database
        for dep in all_deps:
            name = dep["name"]
            version = dep["version"]
            language = dep["language"]
            
            # Check against vulnerable packages
            for vuln in self.vulnerability_db:
                if vuln["language"] == language and vuln["package"] == name:
                    # Check if this version is affected
                    affected = self._is_version_affected(version, vuln["affected_versions"])
                    
                    if affected:
                        # Create a vulnerability entry
                        vulnerability = {
                            "language": language,
                            "package": name,
                            "version": version,
                            "vulnerability_id": vuln["id"],
                            "severity": vuln["severity"],
                            "title": vuln["title"],
                            "description": vuln["description"],
                            "affected_versions": vuln["affected_versions"],
                            "patched_versions": vuln["patched_versions"],
                            "references": vuln["references"],
                            "published_date": vuln["published_date"],
                            "source_file": dep["source"]
                        }
                        
                        vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _is_version_affected(self, version: str, affected_versions: List[str]) -> bool:

        # If no version information is available, assume it's affected
        if not version:
            return True
        
        # For simplicity, just check for exact matches and simple ranges
        # A real implementation would use a proper version comparison library
        for affected in affected_versions:
            if affected == version:
                return True
            
            # Check for version ranges
            if affected.startswith("<="):
                if self._version_compare(version, affected[2:]) <= 0:
                    return True
            elif affected.startswith(">="):
                if self._version_compare(version, affected[2:]) >= 0:
                    return True
            elif affected.startswith("<"):
                if self._version_compare(version, affected[1:]) < 0:
                    return True
            elif affected.startswith(">"):
                if self._version_compare(version, affected[1:]) > 0:
                    return True
            elif "-" in affected:
                # Range: start-end
                start, end = affected.split("-")
                if (self._version_compare(version, start) >= 0 and
                    self._version_compare(version, end) <= 0):
                    return True
        
        return False
    
    def _version_compare(self, version1: str, version2: str) -> int:
        """
            if version1 < version2, 0 if version1 == version2, 1 if version1 > version2
        """
        # Clean up versions
        v1 = version1.strip().lstrip("v")
        v2 = version2.strip().lstrip("v")
        
        # Split into components
        v1_parts = re.split(r'[.-]', v1)
        v2_parts = re.split(r'[.-]', v2)
        
        # Compare components
        for i in range(max(len(v1_parts), len(v2_parts))):
            if i >= len(v1_parts):
                return -1  # v1 is shorter, so it's less than v2
            
            if i >= len(v2_parts):
                return 1  # v2 is shorter, so v1 is greater
            
            try:
                v1_part = int(v1_parts[i])
                v2_part = int(v2_parts[i])
                
                if v1_part < v2_part:
                    return -1
                elif v1_part > v2_part:
                    return 1
            except ValueError:
                # If parts can't be converted to int, compare as strings
                if v1_parts[i] < v2_parts[i]:
                    return -1
                elif v1_parts[i] > v2_parts[i]:
                    return 1
        
        return 0  # Versions are equal
    
    def _deduplicate_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:

        unique_vulns = {}
        
        for vuln in vulnerabilities:
            key = f"{vuln['vulnerability_id']}:{vuln['package']}:{vuln['version']}"
            
            if key not in unique_vulns:
                unique_vulns[key] = vuln
        
        return list(unique_vulns.values())
    
    def _load_vulnerability_database(self) -> List[Dict[str, Any]]:

        # Create a sample vulnerability database
        today = datetime.datetime.now().strftime("%Y-%m-%d")
        
        vuln_db = [
            # Python vulnerabilities
            {
                "id": "CVE-2018-18074",
                "language": "python",
                "package": "requests",
                "affected_versions": ["<=2.19.1"],
                "patched_versions": [">=2.20.0"],
                "severity": "High",
                "title": "CRLF injection vulnerability in Requests",
                "description": "The Requests package before 2.20.0 for Python sends an HTTP Authorization header to an http URI upon redirects.",
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2018-18074"],
                "published_date": "2018-10-15"
            },
            {
                "id": "CVE-2019-11324",
                "language": "python",
                "package": "urllib3",
                "affected_versions": ["<1.24.2"],
                "patched_versions": [">=1.24.2"],
                "severity": "High",
                "title": "CRLF injection in urllib3",
                "description": "In urllib3 before 1.24.2, CRLF injection is possible if the attacker controls the request parameters.",
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2019-11324"],
                "published_date": "2019-04-13"
            },
            {
                "id": "CVE-2021-23727",
                "language": "python",
                "package": "jinja2",
                "affected_versions": ["<2.11.3"],
                "patched_versions": [">=2.11.3"],
                "severity": "Medium",
                "title": "Regular Expression Denial of Service in Jinja2",
                "description": "This affects the package jinja2 from 0.0.0 and before 2.11.3. The ReDoS vulnerability is mainly due to the `_punctuation_re regex` operator that is vulnerable to ReDoS attacks.",
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-23727"],
                "published_date": "2021-03-07"
            },
            
            # JavaScript vulnerabilities
            {
                "id": "CVE-2019-11358",
                "language": "javascript",
                "package": "jquery",
                "affected_versions": ["<3.4.0"],
                "patched_versions": [">=3.4.0"],
                "severity": "Medium",
                "title": "Prototype Pollution in jQuery",
                "description": "jQuery before 3.4.0 mishandles jQuery.extend(true, {}, ...) because of Object.prototype pollution.",
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2019-11358"],
                "published_date": "2019-04-20"
            },
            {
                "id": "CVE-2021-23337",
                "language": "javascript",
                "package": "lodash",
                "affected_versions": ["<4.17.21"],
                "patched_versions": [">=4.17.21"],
                "severity": "High",
                "title": "Command Injection in Lodash",
                "description": "Lodash versions prior to 4.17.21 are vulnerable to Command Injection via the template function.",
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-23337"],
                "published_date": "2021-02-15"
            },
            
            # Java vulnerabilities
            {
                "id": "CVE-2021-44228",
                "language": "java",
                "package": "org.apache.logging.log4j:log4j-core",
                "affected_versions": [">=2.0.0", "<=2.14.1"],
                "patched_versions": [">=2.15.0"],
                "severity": "Critical",
                "title": "Log4Shell Vulnerability in Log4j",
                "description": "Apache Log4j2 <=2.14.1 JNDI features used in configuration, log messages, and parameters do not protect against attacker-controlled LDAP and other JNDI related endpoints.",
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
                "published_date": "2021-12-10"
            },
            
            # PHP vulnerabilities
            {
                "id": "CVE-2019-10910",
                "language": "php",
                "package": "symfony/security-http",
                "affected_versions": ["<4.2.12", "<4.3.8"],
                "patched_versions": [">=4.2.12", ">=4.3.8"],
                "severity": "Medium",
                "title": "Symfony Security Session Fixation",
                "description": "In Symfony before 4.2.12 and 4.3.x before 4.3.8, a session fixation issue exists when using the remember me functionality.",
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2019-10910"],
                "published_date": "2019-10-09"
            },
            
            # .NET vulnerabilities
            {
                "id": "CVE-2020-1108",
                "language": "dotnet",
                "package": "Newtonsoft.Json",
                "affected_versions": ["<12.0.3"],
                "patched_versions": [">=12.0.3"],
                "severity": "Medium",
                "title": "JSON.NET Denial of Service",
                "description": "A denial of service vulnerability exists in Newtonsoft.Json before 12.0.3 when processing deeply nested JSON.",
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2020-1108"],
                "published_date": "2020-04-14"
            },
            
            # Go vulnerabilities
            {
                "id": "CVE-2020-36067",
                "language": "go",
                "package": "github.com/gin-gonic/gin",
                "affected_versions": ["<1.6.0"],
                "patched_versions": [">=1.6.0"],
                "severity": "Medium",
                "title": "Gin Path Traversal",
                "description": "A path traversal issue exists in Gin before 1.6.0 that allows attackers to read files outside the server root directory.",
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2020-36067"],
                "published_date": "2020-01-21"
            },
            
            # Ruby vulnerabilities
            {
                "id": "CVE-2020-8165",
                "language": "ruby",
                "package": "activesupport",
                "affected_versions": ["<5.2.5", "<6.0.4"],
                "patched_versions": [">=5.2.5", ">=6.0.4"],
                "severity": "Critical",
                "title": "Rails ActiveSupport Remote Code Execution",
                "description": "A deserialization of untrusted data vulnerability exists in Rails ActiveSupport before 5.2.5 and 6.0.x before 6.0.4 that can allow an attacker to execute arbitrary code.",
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2020-8165"],
                "published_date": "2020-05-18"
            }
        ]
        
        # In a real implementation, you would fetch vulnerabilities from a database or API
        return vuln_db