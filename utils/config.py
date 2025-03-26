"""
Configuration Module

This module handles loading and managing configuration settings for ZeroHuntAI.
"""
import os
import json
import logging
from utils.logger import get_logger

logger = get_logger()

# Default configuration settings
DEFAULT_CONFIG = {
    # Scanner settings
    "scanner": {
        "output_dir": "output",
        "report_format": "both",  # json, html, or both
        "language_extensions": [],  # Empty list means all supported extensions
        "enable_call_graph": False,
        "enable_secrets_scan": True,
        "high_entropy_threshold": 4.5,  # Threshold for identifying high entropy strings
        "scan_timeout": 300,  # Maximum time in seconds for scanning a single file
        "max_files": 10000,  # Maximum number of files to scan
        "excluded_dirs": [".git", "node_modules", "venv", "__pycache__", "dist", "build"],
        "excluded_files": [".DS_Store", "*.pyc", "*.min.js", "*.min.css"],
    },
    
    # Vulnerability detection settings
    "detection": {
        "severity_threshold": "Low",  # High, Medium, Low
        "aggressive_mode": False,  # More thorough scanning but might produce false positives
        "custom_patterns": {},  # Custom vulnerability patterns
        "false_positive_patterns": [],  # Patterns to be treated as false positives
    },
    
    # AI model settings
    "ai_model": {
        "confidence_threshold": 0.6,  # Minimum confidence score to report a vulnerability
        "max_analysis_size": 1024 * 1024,  # Maximum file size in bytes for AI analysis
        "enable_exploit_generation": True,  # Generate proof-of-concept exploits
    },
    
    # Reporting settings
    "reporting": {
        "include_code_context": True,  # Include code snippets in reports
        "max_context_lines": 5,  # Number of context lines before and after vulnerable code
        "include_timestamp": True,  # Include timestamp in reports
        "include_severity_stats": True,  # Include severity statistics in reports
        "include_file_stats": True,  # Include file statistics in reports
    },
    
    # UI settings (for web interface)
    "ui": {
        "theme": "dark",  # dark or light
        "default_sort": "severity",  # severity, file, vulnerability_type
        "default_filter": "all",  # all, high, medium, low
        "max_results_per_page": 50,  # Maximum number of results per page
    }
}

# Singleton Config class
class Config:
    """
    Singleton class for managing ZeroHuntAI configuration.
    """
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(Config, cls).__new__(cls)
            cls._instance._config = DEFAULT_CONFIG.copy()
            cls._instance._config_file = os.path.join(os.getcwd(), "zerohuntai_config.json")
            cls._instance._load_config()
        return cls._instance
    
    def _load_config(self):
        """Load configuration from file if it exists."""
        try:
            if os.path.exists(self._config_file):
                with open(self._config_file, 'r') as f:
                    user_config = json.load(f)
                    # Update default config with user settings
                    self._update_nested_dict(self._config, user_config)
                logger.info(f"Configuration loaded from {self._config_file}")
            else:
                logger.info("No configuration file found, using default settings")
        except Exception as e:
            logger.error(f"Error loading configuration: {str(e)}")
    
    def _update_nested_dict(self, d, u):
        """Update a nested dictionary with another nested dictionary."""
        for k, v in u.items():
            if isinstance(v, dict) and k in d and isinstance(d[k], dict):
                self._update_nested_dict(d[k], v)
            else:
                d[k] = v
    
    def save_config(self):
        """Save current configuration to file."""
        try:
            with open(self._config_file, 'w') as f:
                json.dump(self._config, f, indent=4)
            logger.info(f"Configuration saved to {self._config_file}")
            return True
        except Exception as e:
            logger.error(f"Error saving configuration: {str(e)}")
            return False
    
    def get(self, section, key=None):

        if section not in self._config:
            return None
        
        if key is None:
            return self._config[section]
        
        if key not in self._config[section]:
            return None
            
        return self._config[section][key]
    
    def set(self, section, key, value):

        if section not in self._config:
            self._config[section] = {}
        
        self._config[section][key] = value
        return True
    
    def update_section(self, section, values):

        if not isinstance(values, dict):
            return False
        
        if section not in self._config:
            self._config[section] = {}
        
        self._update_nested_dict(self._config[section], values)
        return True
    
    def export_config(self):

        return self._config.copy()
    
    def create_default_config_file(self):

        if os.path.exists(self._config_file):
            logger.warning(f"Configuration file already exists: {self._config_file}")
            return False
        
        return self.save_config()


# Convenience function to get configuration
def get_config():

    return Config()