import os
import tempfile
import shutil
from rich.progress import Progress, SpinnerColumn, TextColumn
import git

from scanner.local_scanner import LocalScanner
from utils.logger import get_logger

logger = get_logger()

class GitHubScanner:
    """
    Scanner for GitHub repository analysis.
    """
    def __init__(self, repo_url, output_dir="output", language_extensions=None, 
                 verbose=False, scan_secrets=True, enable_call_graph=False):

        self.repo_url = repo_url
        self.output_dir = output_dir
        self.language_extensions = language_extensions
        self.verbose = verbose
        self.scan_secrets = scan_secrets
        self.enable_call_graph = enable_call_graph
        self.local_scanner = None
        self.temp_dir = None
        
        # Validate repository URL
        if not repo_url.startswith(('http://', 'https://', 'git://')):
            raise ValueError(f"Invalid repository URL: {repo_url}")
        
        logger.info(f"Initialized GitHub scanner for repository: {repo_url}")
    
    def scan(self):

        logger.info(f"Starting GitHub repository scan: {self.repo_url}")
        
        try:
            # Create a temporary directory
            self.temp_dir = tempfile.mkdtemp(prefix="zerohuntai_")
            logger.info(f"Created temporary directory: {self.temp_dir}")
            
            # Clone the repository
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
            ) as progress:
                task = progress.add_task("[cyan]Cloning repository...", total=None)
                
                try:
                    repo_path = self._clone_repository(self.temp_dir)
                    progress.update(task, description="[green]Repository cloned successfully!")
                except Exception as e:
                    progress.update(task, description=f"[red]Failed to clone repository: {str(e)}")
                    raise
            
            # Initialize local scanner with the cloned repository
            self.local_scanner = LocalScanner(
                repo_path,
                output_dir=self.output_dir,
                language_extensions=self.language_extensions,
                verbose=self.verbose,
                scan_secrets=self.scan_secrets,
                enable_call_graph=self.enable_call_graph
            )
            
            # Run the scan
            scan_result = self.local_scanner.scan()
            
            # Add repository information to the scan result
            scan_result['target'] = self.repo_url
            
            return scan_result
            
        except Exception as e:
            logger.error(f"Error scanning GitHub repository: {str(e)}")
            if self.verbose:
                logger.exception("Exception details:")
            raise
        finally:
            # Clean up the temporary directory
            if self.temp_dir and os.path.exists(self.temp_dir):
                logger.info(f"Cleaning up temporary directory: {self.temp_dir}")
                shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def _clone_repository(self, temp_dir):
        try:
            # Extract repository name from URL for the target directory
            repo_name = self.repo_url.rstrip('/').split('/')[-1]
            if repo_name.endswith('.git'):
                repo_name = repo_name[:-4]
            
            repo_path = os.path.join(temp_dir, repo_name)
            
            # Clone the repository
            git.Repo.clone_from(self.repo_url, repo_path, depth=1)
            
            logger.info(f"Repository cloned successfully to: {repo_path}")
            return repo_path
            
        except git.GitCommandError as e:
            logger.error(f"Git command error: {str(e)}")
            raise ValueError(f"Failed to clone repository: {str(e)}")
        except Exception as e:
            logger.error(f"Error cloning repository: {str(e)}")
            raise ValueError(f"Failed to clone repository: {str(e)}")
    
    def generate_report(self, format='json'):

        if not self.local_scanner:
            raise ValueError("No scan results available. Run scan() first.")
        
        return self.local_scanner.generate_report(format)
    
    def generate_call_graph(self):

        if not self.enable_call_graph or not self.local_scanner:
            return None
        
        return self.local_scanner.generate_call_graph()
