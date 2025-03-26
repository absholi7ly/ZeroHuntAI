import os
import logging
from logging.handlers import RotatingFileHandler
import sys

# Global logger instance
_logger = None

def setup_logger(log_dir="logs", log_level=logging.INFO):
    """
    Set up and configure the logger.
    
    Args:
        log_dir (str): Directory to store log files
        log_level (int): Logging level (e.g., logging.INFO, logging.DEBUG)
        
    Returns:
        logging.Logger: Configured logger instance
    """
    global _logger
    
    if _logger:
        return _logger
    
    # Create logger
    logger = logging.getLogger("zerohuntai")
    logger.setLevel(log_level)
    
    # Create formatters
    file_formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    console_formatter = logging.Formatter(
        "%(levelname)s: %(message)s"
    )
    
    # Create console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)
    console_handler.setFormatter(console_formatter)
    
    # Create file handler if log directory is provided
    if log_dir:
        # Create log directory if it doesn't exist
        os.makedirs(log_dir, exist_ok=True)
        
        # Create file handler
        log_file = os.path.join(log_dir, "zerohuntai.log")
        file_handler = RotatingFileHandler(
            log_file, maxBytes=10*1024*1024, backupCount=5
        )
        file_handler.setLevel(log_level)
        file_handler.setFormatter(file_formatter)
        
        # Add file handler to logger
        logger.addHandler(file_handler)
    
    # Add console handler to logger
    logger.addHandler(console_handler)
    
    # Store the logger for future use
    _logger = logger
    
    return logger

def get_logger():
    """
    Get the configured logger instance.
    
    Returns:
        logging.Logger: Logger instance
    """
    global _logger
    
    if not _logger:
        _logger = setup_logger()
    
    return _logger
