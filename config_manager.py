#!/usr/bin/env python3

"""
config_manager.py v10.0 (alpha)
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
    
    # Watcher-specific configuration
    watch_batch_delay: int = 5
    watch_min_batch: int = 0
    watch_max_batch: int = 0
    
    # Email notification configuration
    email_enabled: bool = False
    email_smtp_server: str = ''
    email_smtp_port: int = 587
    email_use_tls: bool = True
    email_username: str = ''
    email_password: str = ''
    email_from: str = ''
    email_to: str = ''
    email_verbose: bool = False
    
    # Zip archive configuration
    zip_archive_directory: Path = field(default_factory=lambda: Path('test_zip_archives'))
    zip_password: str = ''
    
    # TEX (Scrub) configuration
    tex_enabled: bool = False
    tex_url: str = ''
    tex_api_key: str = ''
    tex_response_info_directory: str = 'tex_response_info'
    tex_clean_files_directory: str = 'tex_clean_files'
    tex_supported_file_types: set = field(default_factory=set)
    tex_scrubbed_parts_codes: set = field(default_factory=set)
    
    # Logging configuration
    log_level: str = 'INFO'
    log_dir: Path = field(default_factory=lambda: Path('logs'))
    max_log_size_mb: int = 10
    backup_count: int = 5
    
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
        
        # Validate watcher settings
        if self.watch_batch_delay < 1:
            errors.append("watch_batch_delay must be at least 1")
        elif self.watch_batch_delay > 60:
            errors.append("watch_batch_delay must be at most 60")
        
        if self.watch_min_batch < 0:
            errors.append("watch_min_batch cannot be negative")
        
        if self.watch_max_batch < 0:
            errors.append("watch_max_batch cannot be negative")
        
        # Validate zip archive settings
        if self.zip_password and not self.zip_archive_directory:
            errors.append("zip_archive_directory is required when zip_password is set")
        
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
            'watch_mode': False,
            'watch_batch_delay': 5,
            'watch_min_batch': 0,
            'watch_max_batch': 0,
            'log_level': 'INFO',
            'log_dir': 'logs',
            'max_log_size_mb': 10,
            'backup_count': 5,
            'email_enabled': False,
            'email_smtp_server': '',
            'email_smtp_port': 587,
            'email_use_tls': True,
            'email_username': '',
            'email_password': '',
            'email_from': '',
            'email_to': '',
            'email_verbose': False,
            'zip_archive_directory': 'test_zip_archives',
            'zip_password': '',
            'tex_enabled': False,
            'tex_url': '',
            'tex_api_key': '',
            'tex_response_info_directory': 'tex_response_info',
            'tex_clean_files_directory': 'tex_clean_files',
            'tex_supported_file_types': set(),
            'tex_scrubbed_parts_codes': set()
        }
        
        # 2. Override with environment variables
        for key in config_data.keys():
            env_key = env_prefix + key.upper()
            if env_key in os.environ:
                value = os.environ[env_key]
                # Convert types appropriately
                if key in ['concurrency', 'seconds_to_wait', 'max_retries', 'max_log_size_mb', 'backup_count',
                           'watch_batch_delay', 'watch_min_batch', 'watch_max_batch', 'email_smtp_port']:
                    try:
                        config_data[key] = int(value)
                    except ValueError:
                        print(f"Warning: Invalid integer value for {env_key}: {value}")
                elif key in ['watch_mode', 'email_enabled', 'email_use_tls']:
                    config_data[key] = value.lower() in ['true', '1', 'yes', 'on']
                else:
                    config_data[key] = value
        
        # 3. Override with config file
        if os.path.exists(config_file):
            parser = configparser.ConfigParser()
            parser.read(config_file)
            
            # Read from DEFAULT section
            if 'DEFAULT' in parser:
                section = parser['DEFAULT']
                
                for key in config_data.keys():
                    if key in section:
                        value = section[key]
                        # Convert types appropriately
                        if key in ['concurrency', 'seconds_to_wait', 'max_retries', 'max_log_size_mb', 'backup_count',
                                   'watch_batch_delay', 'watch_min_batch', 'watch_max_batch']:
                            try:
                                config_data[key] = int(value)
                            except ValueError:
                                print(f"Warning: Invalid integer value in config for {key}: {value}")
                        elif key in ['watch_mode']:
                            config_data[key] = value.lower() in ['true', '1', 'yes', 'on']
                        else:
                            config_data[key] = value
            
            # Read from LOGGING section
            if 'LOGGING' in parser:
                section = parser['LOGGING']
                
                for key in config_data.keys():
                    if key in section:
                        value = section[key]
                        # Convert types appropriately
                        if key in ['max_log_size_mb', 'backup_count', 'watch_batch_delay', 'watch_min_batch', 'watch_max_batch']:
                            try:
                                config_data[key] = int(value)
                            except ValueError:
                                print(f"Warning: Invalid integer value in config for {key}: {value}")
                        elif key in ['watch_mode']:
                            config_data[key] = value.lower() in ['true', '1', 'yes', 'on']
                        else:
                            config_data[key] = value
            
            # Read from WATCHER section
            if 'WATCHER' in parser:
                section = parser['WATCHER']
                
                for key in config_data.keys():
                    if key in section:
                        value = section[key]
                        # Convert types appropriately
                        if key in ['watch_batch_delay', 'watch_min_batch', 'watch_max_batch']:
                            try:
                                config_data[key] = int(value)
                            except ValueError:
                                print(f"Warning: Invalid integer value in config for {key}: {value}")
                        else:
                            config_data[key] = value
            
           # Read from TEX section
            if 'TEX' in parser:
                section = parser['TEX']
                
                for key in config_data.keys():
                    if key in section:
                        value = section[key]
                        if key in ['tex_enabled']:
                            config_data[key] = value.lower() in ['true', '1', 'yes', 'on']
                        else:
                            config_data[key] = value.strip()
            
            # Read from TEX_SUPPORTED_FILE_TYPES section
            if 'TEX_SUPPORTED_FILE_TYPES' in parser:
                section = parser['TEX_SUPPORTED_FILE_TYPES']
                enabled_types = set()
                for ext, value in section.items():
                    if value.lower() in ['true', '1', 'yes', 'on']:
                        enabled_types.add(ext.lower())
                if enabled_types:
                    config_data['tex_supported_file_types'] = enabled_types
            
            # Read from TEX_SCRUBBED_PARTS section
            if 'TEX_SCRUBBED_PARTS' in parser:
                section = parser['TEX_SCRUBBED_PARTS']
                enabled_parts = set()
                for code, value in section.items():
                    val = value.split(';')[0].strip().lower()
                    if val in ['true', '1', 'yes', 'on']:
                        enabled_parts.add(int(code))
                if enabled_parts:
                    config_data['tex_scrubbed_parts_codes'] = enabled_parts
            
            # Read from EMAIL section
            if 'EMAIL' in parser:
                section = parser['EMAIL']
                
                for key in config_data.keys():
                    if key in section:
                        value = section[key]
                        # Convert types appropriately
                        if key in ['email_smtp_port']:
                            try:
                                config_data[key] = int(value)
                            except ValueError:
                                print(f"Warning: Invalid integer value in config for {key}: {value}")
                        elif key in ['email_enabled', 'email_use_tls', 'email_verbose']:
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
            # Watcher-specific CLI args
            if hasattr(cli_args, 'watch_delay') and cli_args.watch_delay:
                config_data['watch_batch_delay'] = cli_args.watch_delay
            if hasattr(cli_args, 'watch_min') and cli_args.watch_min:
                config_data['watch_min_batch'] = cli_args.watch_min
            if hasattr(cli_args, 'watch_max') and cli_args.watch_max:
                config_data['watch_max_batch'] = cli_args.watch_max
            
            # Email CLI args
            if hasattr(cli_args, 'email_enabled') and cli_args.email_enabled:
                config_data['email_enabled'] = cli_args.email_enabled
            if hasattr(cli_args, 'email_smtp_server') and cli_args.email_smtp_server:
                config_data['email_smtp_server'] = cli_args.email_smtp_server
            if hasattr(cli_args, 'email_smtp_port') and cli_args.email_smtp_port:
                config_data['email_smtp_port'] = cli_args.email_smtp_port
            if hasattr(cli_args, 'email_use_tls') and cli_args.email_use_tls:
                config_data['email_use_tls'] = cli_args.email_use_tls
            if hasattr(cli_args, 'email_username') and cli_args.email_username:
                config_data['email_username'] = cli_args.email_username
            if hasattr(cli_args, 'email_password') and cli_args.email_password:
                config_data['email_password'] = cli_args.email_password
            if hasattr(cli_args, 'email_from') and cli_args.email_from:
                config_data['email_from'] = cli_args.email_from
            if hasattr(cli_args, 'email_to') and cli_args.email_to:
                config_data['email_to'] = cli_args.email_to
            if hasattr(cli_args, 'email_verbose') and cli_args.email_verbose:
                config_data['email_verbose'] = cli_args.email_verbose
            
            # Zip archive CLI args
            if hasattr(cli_args, 'zip_archive_directory') and cli_args.zip_archive_directory:
                config_data['zip_archive_directory'] = cli_args.zip_archive_directory
            if hasattr(cli_args, 'zip_password') and cli_args.zip_password is not None:
                config_data['zip_password'] = cli_args.zip_password
            
           # TEX CLI args
            if hasattr(cli_args, 'tex_enabled') and cli_args.tex_enabled:
                config_data['tex_enabled'] = cli_args.tex_enabled
            if hasattr(cli_args, 'tex_url') and cli_args.tex_url:
                config_data['tex_url'] = cli_args.tex_url
            if hasattr(cli_args, 'tex_api_key') and cli_args.tex_api_key:
                config_data['tex_api_key'] = cli_args.tex_api_key
            if hasattr(cli_args, 'tex_response_info_directory') and cli_args.tex_response_info_directory:
                config_data['tex_response_info_directory'] = cli_args.tex_response_info_directory
            if hasattr(cli_args, 'tex_clean_files_directory') and cli_args.tex_clean_files_directory:
                config_data['tex_clean_files_directory'] = cli_args.tex_clean_files_directory
        
        # Normalize all paths
        path_keys = ['input_directory', 'reports_directory', 'benign_directory',
                      'quarantine_directory', 'error_directory', 'zip_archive_directory', 'log_dir']
        for key in path_keys:
            config_data[key] = PathHandler.normalize_path(config_data[key])
        
        # Ensure all integer fields are actually integers (configparser returns strings)
        int_fields = ['concurrency', 'seconds_to_wait', 'max_retries', 'max_log_size_mb', 'backup_count', 'email_smtp_port']
        for key in int_fields:
            if key in config_data and not isinstance(config_data[key], int):
                try:
                    config_data[key] = int(config_data[key])
                except (ValueError, TypeError):
                    print(f"Warning: Could not convert {key} to integer, using default")
                    # Reset to default value based on field
                    defaults = {'concurrency': 4, 'seconds_to_wait': 15, 'max_retries': 120, 
                                'max_log_size_mb': 10, 'backup_count': 5, 'email_smtp_port': 587}
                    config_data[key] = defaults.get(key, 0)
        
        # Ensure watch_mode is boolean
        if 'watch_mode' in config_data and not isinstance(config_data['watch_mode'], bool):
            config_data['watch_mode'] = str(config_data['watch_mode']).lower() in ['true', '1', 'yes', 'on']
        
        # Ensure email boolean fields are actually booleans
        if 'email_enabled' in config_data and not isinstance(config_data['email_enabled'], bool):
            config_data['email_enabled'] = str(config_data['email_enabled']).lower() in ['true', '1', 'yes', 'on']
        if 'email_use_tls' in config_data and not isinstance(config_data['email_use_tls'], bool):
            config_data['email_use_tls'] = str(config_data['email_use_tls']).lower() in ['true', '1', 'yes', 'on']
        if 'email_verbose' in config_data and not isinstance(config_data['email_verbose'], bool):
            config_data['email_verbose'] = str(config_data['email_verbose']).lower() in ['true', '1', 'yes', 'on']
        
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
        if self.watch_mode:
            print(f"  Batch delay:           {self.watch_batch_delay}s")
            print(f"  Min batch size:        {self.watch_min_batch if self.watch_min_batch > 0 else 'N/A'}")
            print(f"  Max batch size:        {self.watch_max_batch if self.watch_max_batch > 0 else 'Unlimited'}")
        print()
        print("Logging Configuration:")
        print(f"  Log level:             {self.log_level}")
        print(f"  Log directory:         {self.log_dir}")
        print(f"  Max log size (MB):     {self.max_log_size_mb}")
        print(f"  Backup count:          {self.backup_count}")
        
        print("Email Notification:")
        print(f"  Enabled:               {'Yes' if self.email_enabled else 'No'}")
        if self.email_enabled:
            print(f"  SMTP server:           {self.email_smtp_server}:{self.email_smtp_port}")
            print(f"  TLS:                   {'Yes' if self.email_use_tls else 'No'}")
            print(f"  From:                  {self.email_from}")
            print(f"  To:                    {self.email_to}")
            if self.email_username:
                print(f"  Username:              {self.email_username}")
            else:
                print(f"  Username:              (none - will attempt anonymous connect)")
            print(f"  Verbose:               {'Yes' if self.email_verbose else 'No'}")
        
        # Zip Archive Configuration
        print("Zip Archive:")
        print(f"  Archive directory:     {self.zip_archive_directory}")
        print(f"  Password set:          {'Yes' if self.zip_password else 'No'}")
        
        print("TEX (Scrub):")
        print(f"  Enabled:               {'Yes' if self.tex_enabled else 'No'}")
        if self.tex_enabled:
            print(f"  URL:                   {self.tex_url}")
            print(f"  API key set:           {'Yes' if self.tex_api_key else 'No'}")
            print(f"  Response info dir:     {self.tex_response_info_directory}")
            print(f"  Clean files dir:       {self.tex_clean_files_directory}")
            print(f"  Supported file types:  {len(self.tex_supported_file_types)} enabled")
            print(f"  Scrubbed parts:        {len(self.tex_scrubbed_parts_codes)} enabled")
        
        # Show path type warnings
        for name, path in [
            ('Input', self.input_directory),
            ('Benign', self.benign_directory),
            ('Quarantine', self.quarantine_directory),
            ('Error', self.error_directory)
        ]:
            if PathHandler.is_smb_path(path):
                print(f"  Note: {name} directory is on network path (SMB) - operations may be slower")

