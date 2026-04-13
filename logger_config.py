#!/usr/bin/env python3

"""
logger_config.py v7.01 (stable)
Centralized logging configuration for TE API Scanner.
Features:
  - Rotating file handler with configurable size and backup count
  - ISO 8601 timestamp format
  - Console output for real-time monitoring
  - Error resilience with console fallback
  - Mid-execution rotation support for watch mode
"""

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
import sys
from typing import Optional


def setup_logging(log_dir: Optional[Path] = None, log_level=logging.INFO, 
                  max_bytes=10*1024*1024, backup_count=5):
    """
    Configure application-wide logging with file rotation.
    
    Args:
        log_dir: Directory for log files (default: ./logs)
        log_level: Logging level (default: INFO)
        max_bytes: Maximum size per log file before rotation (default: 10MB)
        backup_count: Number of backup files to keep (default: 5)
    
    Returns:
        logging.Logger: Configured root logger
    """
    try:
        if log_dir is None:
            log_dir = Path(__file__).parent / 'logs'
        log_dir.mkdir(parents=True, exist_ok=True)
        
        log_file = log_dir / 'te_scanner.log'
        
        # ISO 8601 timestamp format
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%dT%H:%M:%S'
        )
        
        # File handler with rotation - mid-execution rotation supported
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding='utf-8'
        )
        file_handler.setFormatter(formatter)
        
        # Console handler for real-time output during testing
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        
        # Configure root logger
        root_logger = logging.getLogger('te_scanner')
        root_logger.setLevel(log_level)
        
        # Avoid duplicate handlers if setup_logging is called multiple times
        if not root_logger.handlers:
            root_logger.addHandler(file_handler)
            root_logger.addHandler(console_handler)
        
        return root_logger
        
    except Exception as e:
        # Fallback to console-only if file logging fails
        print(f"WARNING: Could not setup file logging: {e}")
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%dT%H:%M:%S'
        ))
        root_logger = logging.getLogger('te_scanner')
        root_logger.setLevel(log_level)
        if not root_logger.handlers:
            root_logger.addHandler(console_handler)
        return root_logger
