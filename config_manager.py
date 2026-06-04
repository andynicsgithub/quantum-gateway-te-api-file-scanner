#!/usr/bin/env python3

"""
config_manager.py v11.2 (alpha)
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
    seconds_to_wait: int = 10
    max_retries: int = 120
    watch_mode: bool = False

    # Watcher-specific configuration
    watch_batch_delay: int = 5
    watch_min_batch: int = 0
    watch_max_batch: int = 0

    # Archive file types
    archive_extensions: set[str] = field(default_factory=set)

    # Email notification configuration
    email_enabled: bool = False
    email_smtp_server: str = ""
    email_smtp_port: int = 587
    email_use_tls: bool = True
    email_skip_tls_verify: bool = False
    email_username: str = ""
    email_password: str = ""
    email_from: str = ""
    email_to: str = ""
    email_subject_template: str = ""
    email_template_file: str = "data/email_template.txt"

    # IMAP - save sent copies
    email_imap_enabled: bool = False
    email_imap_server: str = ""
    email_imap_port: int = 993
    email_imap_use_ssl: bool = True
    email_imap_username: str = ""
    email_imap_password: str = ""
    email_imap_folder: str = "Sent"

    # Zip archive configuration
    zip_archive_directory: Path = field(
        default_factory=lambda: Path("test_zip_archives")
    )
    zip_password: str = ""

    # TEX (Scrub) configuration
    tex_enabled: bool = False
    tex_url: str = ""
    tex_api_key: str = ""
    tex_response_info_directory: Path = field(
        default_factory=lambda: Path("tex_response_info")
    )
    tex_clean_files_directory: Path = field(
        default_factory=lambda: Path("tex_clean_files")
    )
    tex_supported_file_types: set[str] = field(default_factory=set)
    tex_scrubbed_parts_codes: set[int] = field(default_factory=set)

    # Logging configuration
    log_level: str = "INFO"
    log_dir: Path = field(default_factory=lambda: Path("logs"))
    max_log_size_mb: int = 10
    log_retention_days: int = 90

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
            ("reports_directory", self.reports_directory),
            ("benign_directory", self.benign_directory),
            ("quarantine_directory", self.quarantine_directory),
            ("error_directory", self.error_directory),
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
    def from_sources(
        cls,
        config_file: str = "config.ini",
        cli_args: Optional[argparse.Namespace] = None,
        env_prefix: str = "TE_",
    ) -> "ScannerConfig":
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
            "input_directory": "input_files",
            "reports_directory": "te_response_data",
            "benign_directory": "benign_files",
            "quarantine_directory": "quarantine_files",
            "error_directory": "error_files",
            "appliance_ip": "",
            "concurrency": 4,
            "seconds_to_wait": 10,
            "max_retries": 120,
            "watch_mode": False,
            "watch_batch_delay": 5,
            "watch_min_batch": 0,
            "watch_max_batch": 0,
            "log_level": "INFO",
            "log_dir": "logs",
            "max_log_size_mb": 10,
            "log_retention_days": 90,
            "email_enabled": False,
            "email_smtp_server": "",
            "email_smtp_port": 587,
            "email_use_tls": True,
            "email_skip_tls_verify": False,
            "email_username": "",
            "email_password": "",
            "email_from": "",
            "email_to": "",
            "email_subject_template": "",
            "email_template_file": "data/email_template.txt",
            "email_imap_enabled": False,
            "email_imap_server": "",
            "email_imap_port": 993,
            "email_imap_use_ssl": True,
            "email_imap_username": "",
            "email_imap_password": "",
            "email_imap_folder": "Sent",
            "zip_archive_directory": "test_zip_archives",
            "zip_password": "",
            "tex_enabled": False,
            "tex_url": "",
            "tex_api_key": "",
            "tex_response_info_directory": "tex_response_info",
            "tex_clean_files_directory": "tex_clean_files",
            "tex_supported_file_types": set(),
            "tex_scrubbed_parts_codes": set(),
            "archive_extensions": set(),
        }

        # 2. Override with environment variables
        for key in config_data.keys():
            env_key = env_prefix + key.upper()
            if env_key in os.environ:
                value = os.environ[env_key]
                # Convert types appropriately
                if key in [
                    "concurrency",
                    "seconds_to_wait",
                    "max_retries",
                    "max_log_size_mb",
                    "log_retention_days",
                    "watch_batch_delay",
                    "watch_min_batch",
                    "watch_max_batch",
                    "email_smtp_port",
                ]:
                    try:
                        config_data[key] = int(value)
                    except ValueError:
                        print(f"Warning: Invalid integer value for {env_key}: {value}")
                elif key in [
                    "watch_mode",
                    "email_enabled",
                    "email_use_tls",
                    "email_skip_tls_verify",
                    "email_imap_enabled",
                    "email_imap_use_ssl",
                ]:
                    config_data[key] = value.lower() in ["true", "1", "yes", "on"]
                else:
                    config_data[key] = value

        # 3. Override with config file
        if os.path.exists(config_file):
            parser = configparser.ConfigParser()
            parser.read(config_file)

            # Read from DEFAULT section
            if "DEFAULT" in parser:
                section = parser["DEFAULT"]

                for key in config_data.keys():
                    if key in section:
                        value = section[key]
                        # Convert types appropriately
                        if key in [
                            "concurrency",
                            "seconds_to_wait",
                            "max_retries",
                            "max_log_size_mb",
                            "log_retention_days",
                            "watch_batch_delay",
                            "watch_min_batch",
                            "watch_max_batch",
                        ]:
                            try:
                                config_data[key] = int(value)
                            except ValueError:
                                print(
                                    f"Warning: Invalid integer value in config for {key}: {value}"
                                )
                        elif key in ["watch_mode"]:
                            config_data[key] = value.lower() in [
                                "true",
                                "1",
                                "yes",
                                "on",
                            ]
                        else:
                            config_data[key] = value

            # Read from LOGGING section
            if "LOGGING" in parser:
                section = parser["LOGGING"]

                for key in config_data.keys():
                    if key in section:
                        value = section[key]
                        # Convert types appropriately
                        if key in [
                            "max_log_size_mb",
                            "log_retention_days",
                            "watch_batch_delay",
                            "watch_min_batch",
                            "watch_max_batch",
                        ]:
                            try:
                                config_data[key] = int(value)
                            except ValueError:
                                print(
                                    f"Warning: Invalid integer value in config for {key}: {value}"
                                )
                        elif key in ["watch_mode"]:
                            config_data[key] = value.lower() in [
                                "true",
                                "1",
                                "yes",
                                "on",
                            ]
                        else:
                            config_data[key] = value

            # Read from WATCHER section
            if "WATCHER" in parser:
                section = parser["WATCHER"]

                for key in config_data.keys():
                    if key in section:
                        value = section[key]
                        # Convert types appropriately
                        if key in [
                            "watch_batch_delay",
                            "watch_min_batch",
                            "watch_max_batch",
                        ]:
                            try:
                                config_data[key] = int(value)
                            except ValueError:
                                print(
                                    f"Warning: Invalid integer value in config for {key}: {value}"
                                )
                        else:
                            config_data[key] = value

            # Read from TEX section
            if "TEX" in parser:
                section = parser["TEX"]

                for key in config_data.keys():
                    if key in section:
                        value = section[key]
                        if key in ["tex_enabled"]:
                            config_data[key] = value.lower() in [
                                "true",
                                "1",
                                "yes",
                                "on",
                            ]
                        else:
                            config_data[key] = value.strip()

            # Read from TEX_SUPPORTED_FILE_TYPES section
            if "TEX_SUPPORTED_FILE_TYPES" in parser:
                section = parser["TEX_SUPPORTED_FILE_TYPES"]
                enabled_types = set()
                for ext, value in section.items():
                    if value.lower() in ["true", "1", "yes", "on"]:
                        enabled_types.add(ext.lower())
                if enabled_types:
                    config_data["tex_supported_file_types"] = enabled_types

            # Read from TEX_SCRUBBED_PARTS section
            if "TEX_SCRUBBED_PARTS" in parser:
                section = parser["TEX_SCRUBBED_PARTS"]
                enabled_parts = set()
                for code, value in section.items():
                    val = value.split("#")[0].strip().lower()
                    if val in ["true", "1", "yes", "on"]:
                        enabled_parts.add(int(code))
                if enabled_parts:
                    config_data["tex_scrubbed_parts_codes"] = enabled_parts

            # Read from ARCHIVE_FILE_TYPES section
            if "ARCHIVE_FILE_TYPES" in parser:
                section = parser["ARCHIVE_FILE_TYPES"]
                enabled_types = set()
                for ext, value in section.items():
                    if value.lower() in ["true", "1", "yes", "on"]:
                        enabled_types.add(ext.lower())
                if enabled_types:
                    config_data["archive_extensions"] = enabled_types

            # Read from EMAIL section
            if "EMAIL" in parser:
                section = parser["EMAIL"]

                for key in config_data.keys():
                    if key in section:
                        value = section[key]
                        # Convert types appropriately
                        if key in ["email_smtp_port", "email_imap_port"]:
                            try:
                                config_data[key] = int(value)
                            except ValueError:
                                print(
                                    f"Warning: Invalid integer value in config for {key}: {value}"
                                )
                        elif key in [
                            "email_enabled",
                            "email_use_tls",
                            "email_imap_enabled",
                            "email_imap_use_ssl",
                        ]:
                            config_data[key] = value.lower() in [
                                "true",
                                "1",
                                "yes",
                                "on",
                            ]
                        else:
                            config_data[key] = value

        # 4. Override with command-line arguments (highest priority)
        if cli_args:
            # (cli_attr, config_key) mappings — applies getattr(cli_args, attr) if truthy
            _cli_mappings = [
                ("input_directory", "input_directory"),
                ("reports_directory", "reports_directory"),
                ("appliance_ip", "appliance_ip"),
                ("benign_directory", "benign_directory"),
                ("quarantine_directory", "quarantine_directory"),
                ("error_directory", "error_directory"),
                ("concurrency", "concurrency"),
                ("watch", "watch_mode"),
                ("watch_delay", "watch_batch_delay"),
                ("watch_min", "watch_min_batch"),
                ("watch_max", "watch_max_batch"),
                ("email_enabled", "email_enabled"),
                ("email_smtp_server", "email_smtp_server"),
                ("email_smtp_port", "email_smtp_port"),
                ("email_use_tls", "email_use_tls"),
                ("email_skip_tls_verify", "email_skip_tls_verify"),
                ("email_username", "email_username"),
                ("email_from", "email_from"),
                ("email_to", "email_to"),
                ("email_subject_template", "email_subject_template"),
                ("email_template_file", "email_template_file"),
                ("email_imap_enabled", "email_imap_enabled"),
                ("email_imap_server", "email_imap_server"),
                ("email_imap_port", "email_imap_port"),
                ("email_imap_use_ssl", "email_imap_use_ssl"),
                ("email_imap_username", "email_imap_username"),
                ("email_imap_folder", "email_imap_folder"),
                ("zip_archive_directory", "zip_archive_directory"),
                ("tex_enabled", "tex_enabled"),
                ("tex_url", "tex_url"),
                ("tex_response_info_directory", "tex_response_info_directory"),
                ("tex_clean_files_directory", "tex_clean_files_directory"),
            ]
            for cli_attr, config_key in _cli_mappings:
                val = getattr(cli_args, cli_attr, None)
                if val:
                    config_data[config_key] = val

            # zip_password uses `is not None` because empty string is falsy but valid
            if getattr(cli_args, "zip_password", None) is not None:
                config_data["zip_password"] = cli_args.zip_password

        # Normalize all paths
        path_keys = [
            "input_directory",
            "reports_directory",
            "benign_directory",
            "quarantine_directory",
            "error_directory",
            "zip_archive_directory",
            "log_dir",
            "tex_response_info_directory",
            "tex_clean_files_directory",
        ]
        for key in path_keys:
            config_data[key] = PathHandler.normalize_path(config_data[key])

        # Ensure all integer fields are actually integers (configparser returns strings)
        int_fields = [
            "concurrency",
            "seconds_to_wait",
            "max_retries",
            "max_log_size_mb",
            "log_retention_days",
            "email_smtp_port",
            "email_imap_port",
        ]
        for key in int_fields:
            if key in config_data and not isinstance(config_data[key], int):
                try:
                    config_data[key] = int(config_data[key])
                except (ValueError, TypeError):
                    print(f"Warning: Could not convert {key} to integer, using default")
                    # Reset to default value based on field
                    defaults = {
                        "concurrency": 4,
                        "seconds_to_wait": 10,
                        "max_retries": 120,
                        "max_log_size_mb": 10,
                        "log_retention_days": 90,
                        "email_smtp_port": 587,
                        "email_imap_port": 993,
                    }
                    config_data[key] = defaults.get(key, 0)

        # Ensure watch_mode is boolean
        if "watch_mode" in config_data and not isinstance(
            config_data["watch_mode"], bool
        ):
            config_data["watch_mode"] = str(config_data["watch_mode"]).lower() in [
                "true",
                "1",
                "yes",
                "on",
            ]

        # Ensure email boolean fields are actually booleans
        if "email_enabled" in config_data and not isinstance(
            config_data["email_enabled"], bool
        ):
            config_data["email_enabled"] = str(
                config_data["email_enabled"]
            ).lower() in ["true", "1", "yes", "on"]
        if "email_use_tls" in config_data and not isinstance(
            config_data["email_use_tls"], bool
        ):
            config_data["email_use_tls"] = str(
                config_data["email_use_tls"]
            ).lower() in ["true", "1", "yes", "on"]
        if "email_imap_enabled" in config_data and not isinstance(
            config_data["email_imap_enabled"], bool
        ):
            config_data["email_imap_enabled"] = str(
                config_data["email_imap_enabled"]
            ).lower() in ["true", "1", "yes", "on"]
        if "email_imap_use_ssl" in config_data and not isinstance(
            config_data["email_imap_use_ssl"], bool
        ):
            config_data["email_imap_use_ssl"] = str(
                config_data["email_imap_use_ssl"]
            ).lower() in ["true", "1", "yes", "on"]

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
        print(
            f"  Watch mode:            {'Enabled' if self.watch_mode else 'Disabled'}"
        )
        if self.watch_mode:
            print(f"  Batch delay:           {self.watch_batch_delay}s")
            print(
                f"  Min batch size:        {self.watch_min_batch if self.watch_min_batch > 0 else 'N/A'}"
            )
            print(
                f"  Max batch size:        {self.watch_max_batch if self.watch_max_batch > 0 else 'Unlimited'}"
            )
        print()
        print("Logging Configuration:")
        print(f"  Log level:             {self.log_level}")
        print(f"  Log directory:         {self.log_dir}")
        print(f"  Max log size (MB):     {self.max_log_size_mb}")
        print(f"  Log retention (days):  {self.log_retention_days}")

        print("Email Notification:")
        print(f"  Enabled:               {'Yes' if self.email_enabled else 'No'}")
        if self.email_enabled:
            print(
                f"  SMTP server:           {self.email_smtp_server}:{self.email_smtp_port}"
            )
            print(f"  TLS:                   {'Yes' if self.email_use_tls else 'No'}")
            if self.email_use_tls:
                print(
                    f"  Skip TLS verify:       {'Yes' if self.email_skip_tls_verify else 'No'}"
                )
            print(f"  From:                  {self.email_from}")
            print(f"  To:                    {self.email_to}")
            if self.email_username:
                print(f"  Username:              {self.email_username}")
            else:
                print(
                    "  Username:              (none - will attempt anonymous connect)"
                )
            print(
                f"  Subject template:      {'Custom' if self.email_subject_template else 'Default'}"
            )
            print(f"  Body template:         {self.email_template_file}")
        if self.email_imap_enabled:
            print("  IMAP enabled:          Yes")
            print(
                f"  IMAP server:           {self.email_imap_server}:{self.email_imap_port}"
            )
            print(
                f"  IMAP SSL:              {'Yes' if self.email_imap_use_ssl else 'No'}"
            )
            print(f"  IMAP folder:           {self.email_imap_folder}")

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
            print(
                f"  Supported file types:  {len(self.tex_supported_file_types)} enabled"
            )
            print(
                f"  Scrubbed parts:        {len(self.tex_scrubbed_parts_codes)} enabled"
            )

        # Show path type warnings
        for name, path in [
            ("Input", self.input_directory),
            ("Benign", self.benign_directory),
            ("Quarantine", self.quarantine_directory),
            ("Error", self.error_directory),
        ]:
            if PathHandler.is_smb_path(path):
                print(
                    f"  Note: {name} directory is on network path (SMB) - operations may be slower"
                )
