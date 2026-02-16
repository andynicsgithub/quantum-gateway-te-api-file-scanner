#!/usr/bin/env python3

"""
config_manager.py
Type-safe configuration management for TE API Scanner.
Supports loading from config file, command-line arguments, and environment variables.
"""

import os
import configparser
import argparse
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple
from path_handler import PathHandler


@dataclass
class ScannerConfig:
    """
    Type-safe configuration for TE API Scanner.
    All paths are stored as pathlib.Path objects.
    """
    input_directory: Path
    reports_directory: Path
    benign_directory: Path
    quarantine_directory: Path
    error_directory: Path
    appliance_ip: str
    concurrency: int = 4
    seconds_to_wait: int = 15
    max_retries: int = 120
    watch_mode: bool = False
    
    def validate(self) -> Tuple[bool, List[str]]:
        """
        Validate configuration settings.
        
        Returns:
            Tuple of (is_valid: bool, error_messages: List[str])
        """
        errors = []
        
        # Validate appliance IP
        if not self.appliance_ip:
            errors.append("appliance_ip is required")
        
        # Validate input directory exists
        valid, msg = PathHandler.validate_path(self.input_directory, create=False)
        if not valid:
            errors.append(f"input_directory: {msg}")
        
        # Validate/create output directories
        for dir_name, dir_path in [
            ('reports_directory', self.reports_directory),
            ('benign_directory', self.benign_directory),
            ('quarantine_directory', self.quarantine_directory),
            ('error_directory', self.error_directory)
        ]:
            valid, msg = PathHandler.validate_path(dir_path, create=True)
            if not valid:
                errors.append(f"{dir_name}: {msg}")
        
        # Validate numeric settings
        if self.concurrency < 1:
            errors.append("concurrency must be at least 1")
        
        if self.seconds_to_wait < 1:
            errors.append("seconds_to_wait must be at least 1")
        
        if self.max_retries < 1:
            errors.append("max_retries must be at least 1")
        
        return (len(errors) == 0, errors)
    
    @classmethod
    def from_sources(cls, config_file: str = 'config.ini', 
                     cli_args: Optional[argparse.Namespace] = None,
                     env_prefix: str = 'TE_') -> 'ScannerConfig':
        """
        Load configuration from multiple sources with precedence:
        1. Hardcoded defaults (lowest priority)
        2. Environment variables
        3. Config file
        4. Command-line arguments (highest priority)
        
        Args:
            config_file: Path to config file (default: config.ini)
            cli_args: Parsed command-line arguments
            env_prefix: Prefix for environment variables (default: TE_)
            
        Returns:
            ScannerConfig instance
        """
        # 1. Start with defaults
        config_data = {
            'input_directory': 'input_files',
            'reports_directory': 'te_response_data',
            'benign_directory': 'benign_files',
            'quarantine_directory': 'quarantine_files',
            'error_directory': 'error_files',
            'appliance_ip': '',
            'concurrency': 4,
            'seconds_to_wait': 15,
            'max_retries': 120,
            'watch_mode': False
        }
        
        # 2. Override with environment variables
        for key in config_data.keys():
            env_key = env_prefix + key.upper()
            if env_key in os.environ:
                value = os.environ[env_key]
                # Convert types appropriately
                if key in ['concurrency', 'seconds_to_wait', 'max_retries']:
                    try:
                        config_data[key] = int(value)
                    except ValueError:
                        print(f"Warning: Invalid integer value for {env_key}: {value}")
                elif key == 'watch_mode':
                    config_data[key] = value.lower() in ['true', '1', 'yes', 'on']
                else:
                    config_data[key] = value
        
        # 3. Override with config file
        if os.path.exists(config_file):
            parser = configparser.ConfigParser()
            parser.read(config_file)
            
            if 'DEFAULT' in parser:
                section = parser['DEFAULT']
                
                for key in config_data.keys():
                    if key in section:
                        value = section[key]
                        # Convert types appropriately
                        if key in ['concurrency', 'seconds_to_wait', 'max_retries']:
                            try:
                                config_data[key] = int(value)
                            except ValueError:
                                print(f"Warning: Invalid integer value in config for {key}: {value}")
                        elif key == 'watch_mode':
                            config_data[key] = value.lower() in ['true', '1', 'yes', 'on']
                        else:
                            config_data[key] = value
        
        # 4. Override with command-line arguments (highest priority)
        if cli_args:
            if hasattr(cli_args, 'input_directory') and cli_args.input_directory:
                config_data['input_directory'] = cli_args.input_directory
            if hasattr(cli_args, 'reports_directory') and cli_args.reports_directory:
                config_data['reports_directory'] = cli_args.reports_directory
            if hasattr(cli_args, 'appliance_ip') and cli_args.appliance_ip:
                config_data['appliance_ip'] = cli_args.appliance_ip
            if hasattr(cli_args, 'benign_directory') and cli_args.benign_directory:
                config_data['benign_directory'] = cli_args.benign_directory
            if hasattr(cli_args, 'quarantine_directory') and cli_args.quarantine_directory:
                config_data['quarantine_directory'] = cli_args.quarantine_directory
            if hasattr(cli_args, 'error_directory') and cli_args.error_directory:
                config_data['error_directory'] = cli_args.error_directory
            if hasattr(cli_args, 'concurrency') and cli_args.concurrency:
                config_data['concurrency'] = cli_args.concurrency
            if hasattr(cli_args, 'watch') and cli_args.watch:
                config_data['watch_mode'] = cli_args.watch
        
        # Normalize all paths
        path_keys = ['input_directory', 'reports_directory', 'benign_directory', 
                     'quarantine_directory', 'error_directory']
        for key in path_keys:
            config_data[key] = PathHandler.normalize_path(config_data[key])
        
        # Create and return ScannerConfig instance
        return cls(**config_data)
    
    def print_summary(self):
        """Print configuration summary for user verification."""
        print("Configuration Summary:")
        print(f"  Input directory:       {self.input_directory}")
        print(f"  Reports directory:     {self.reports_directory}")
        print(f"  Benign directory:      {self.benign_directory}")
        print(f"  Quarantine directory:  {self.quarantine_directory}")
        print(f"  Error directory:       {self.error_directory}")
        print(f"  Appliance IP:          {self.appliance_ip}")
        print(f"  Concurrency:           {self.concurrency}")
        print(f"  Seconds to wait:       {self.seconds_to_wait}")
        print(f"  Max retries:           {self.max_retries}")
        print(f"  Watch mode:            {'Enabled' if self.watch_mode else 'Disabled'}")
        
        # Show path type warnings
        for name, path in [
            ('Input', self.input_directory),
            ('Benign', self.benign_directory),
            ('Quarantine', self.quarantine_directory),
            ('Error', self.error_directory)
        ]:
            if PathHandler.is_smb_path(path):
                print(f"  Note: {name} directory is on network path (SMB) - operations may be slower")
