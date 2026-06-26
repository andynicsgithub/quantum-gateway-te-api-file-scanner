#!/usr/bin/env python3

"""
config_manager.py v13.2 (alpha)
Type-safe configuration management for TE API Scanner.
Supports loading from config file, command-line arguments, and environment variables.
"""

import os
import re
import configparser
import argparse
import logging
import ipaddress
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple, Set
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
    appliance_skip_tls_verify: bool = False
    concurrency: int = 4
    seconds_to_wait: int = 10
    max_retries: int = 120
    watch_mode: bool = False

    # Watcher-specific configuration
    watch_batch_delay: int = 5
    watch_max_batch: int = 0

    # Archive file types
    archive_extensions: Set[str] = field(default_factory=set)

    # Email notification configuration
    email_enabled: bool = False
    email_malicious_only: bool = False
    email_smtp_server: str = ""
    email_smtp_port: int = 587
    email_tls_method: str = "starttls"
    email_skip_tls_verify: bool = False
    email_username: str = ""
    email_password: str = ""
    email_from: str = ""
    email_to: str = ""
    email_subject_template: str = ""
    email_template_file: str = "data/email_template.txt"
    email_include_log: bool = False

    # IMAP - save sent copies
    email_imap_enabled: bool = False
    email_imap_server: str = ""
    email_imap_port: int = 993
    email_imap_use_ssl: bool = True
    email_imap_skip_tls_verify: bool = False
    email_imap_username: str = ""
    email_imap_password: str = ""
    email_imap_folder: str = "Sent"

    # Zip archive configuration
    zip_archive_directory: Optional[Path] = None
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
    tex_supported_file_types: Set[str] = field(default_factory=set)
    tex_scrubbed_parts_codes: Set[int] = field(default_factory=set)
    tex_max_file_size_mb: int = 15  # Files >= this (MB) skip TEX processing

    # OS images for TE analysis: list of dicts with keys "id", "revision", "name", "is_default", "enabled"
    os_images: List[dict] = field(default_factory=list)

    save_response_info: bool = True

    # AV fallback configuration
    av_fallback_enabled: bool = False
    ssh_username: str = ""
    ssh_password: str = ""
    av_remote_directory: str = "/var/log/apiclient"
    av_rule_id: int = 1
    te_to_av_fallback_at_mb: int = 100  # Files >= this (MB) skip TE, go to AV
    av_to_signature_fallback_at_mb: int = 2048  # Files >= this (MB) skip AV, use MD5 signature check only

    # Health check configuration
    healthcheck_directory: Path = field(default_factory=lambda: Path("healthcheck"))

    # Logging configuration
    log_level: str = "INFO"
    log_dir: Path = field(default_factory=lambda: Path("logs"))
    max_log_size_mb: int = 10
    log_retention_days: int = 90

    def __post_init__(self):
        """Ensure integer fields loaded from config/env are actually ints."""
        for attr in ("te_to_av_fallback_at_mb", "av_to_signature_fallback_at_mb", "av_rule_id", "tex_max_file_size_mb"):
            current = getattr(self, attr)
            if not isinstance(current, int):
                try:
                    object.__setattr__(self, attr, int(current))
                except (ValueError, TypeError):
                    pass

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
        else:
            try:
                ipaddress.ip_address(self.appliance_ip)
            except ValueError:
                errors.append(f"appliance_ip '{self.appliance_ip}' is not a valid IPv4 or IPv6 address")

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

        if self.watch_max_batch < 0:
            errors.append("watch_max_batch cannot be negative")

        # Validate log level
        if not hasattr(logging, self.log_level.upper()):
            valid_levels = [level for level in dir(logging) if level.isupper() and not level.startswith('_')]
            errors.append(f"log_level must be one of: {', '.join(sorted(valid_levels))}")

        # Validate zip archive settings
        if self.zip_password and not self.zip_archive_directory:
            errors.append("zip_archive_directory is required when zip_password is set")

        # Validate TEX settings
        if self.tex_enabled and not self.tex_url:
            errors.append("tex_url is required when tex_enabled is true")
        if self.tex_enabled and not self.tex_api_key:
            errors.append("tex_api_key is required when tex_enabled is true")

        # Validate AV fallback settings
        if self.av_fallback_enabled and not self.ssh_username:
            errors.append("ssh_username is required when av_fallback_enabled is true")
        if self.av_fallback_enabled and not self.ssh_password:
            errors.append("ssh_password is required when av_fallback_enabled is true")
        if self.av_rule_id < 1:
            errors.append("av_rule_id must be at least 1")
        if self.te_to_av_fallback_at_mb < 1:
            errors.append("te_to_av_fallback_at_mb must be at least 1")
        if self.av_to_signature_fallback_at_mb < self.te_to_av_fallback_at_mb:
            errors.append(
                f"av_to_signature_fallback_at_mb ({self.av_to_signature_fallback_at_mb} MB) "
                f"must not be less than te_to_av_fallback_at_mb ({self.te_to_av_fallback_at_mb} MB)"
            )

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
        2. Config file
        3. Environment variables
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
            "appliance_skip_tls_verify": False,
            "concurrency": 4,
            "seconds_to_wait": 10,
            "max_retries": 120,
            "watch_mode": False,
            "watch_batch_delay": 5,
            "watch_max_batch": 0,
            "log_level": "INFO",
            "log_dir": "logs",
            "max_log_size_mb": 10,
            "log_retention_days": 90,
            "email_enabled": False,
            "email_malicious_only": False,
            "email_smtp_server": "",
            "email_smtp_port": 587,
            "email_tls_method": "starttls",
            "email_skip_tls_verify": False,
            "email_username": "",
            "email_password": "",
            "email_from": "",
            "email_to": "",
            "email_subject_template": "",
            "email_template_file": "data/email_template.txt",
            "email_include_log": False,
            "email_imap_enabled": False,
            "email_imap_server": "",
            "email_imap_port": 993,
            "email_imap_use_ssl": True,
            "email_imap_skip_tls_verify": False,
            "email_imap_username": "",
            "email_imap_password": "",
            "email_imap_folder": "Sent",
            "zip_archive_directory": None,
            "zip_password": "",
            "tex_enabled": False,
            "tex_url": "",
            "tex_api_key": "",
            "tex_response_info_directory": "tex_response_info",
            "tex_clean_files_directory": "tex_clean_files",
            "tex_supported_file_types": set(),
            "tex_scrubbed_parts_codes": set(),
            "archive_extensions": set(),
            "save_response_info": True,
            "os_images": [],
           "av_fallback_enabled": False,
            "ssh_username": "",
            "ssh_password": "",
            "av_remote_directory": "/var/log/apiclient",
            "av_rule_id": 1,
            "te_to_av_fallback_at_mb": 100,
            "av_to_signature_fallback_at_mb": 2048,
            "tex_max_file_size_mb": 15,
            "healthcheck_directory": "healthcheck",
        }

        # 2. Override with config file
        if os.path.exists(config_file):
            parser = configparser.ConfigParser()
            parser.read(config_file, encoding='utf-8-sig')

            # Read from DEFAULT section
            # NOTE: Unlike LOGGING/WATCHER/EMAIL/TEX sections, we do NOT use
            # "key not in parser.defaults()" here because every key in the
            # DEFAULT section is an intentional default we want to read.
            # The other sections use that filter to skip keys inherited FROM
            # the DEFAULT section when iterating over them.
            if "DEFAULT" in parser:
                section = parser["DEFAULT"]

                for key in section:
                    if key in config_data:
                        value = section[key]
                        # Convert types appropriately
                        if key in [
                            "concurrency",
                            "seconds_to_wait",
                            "max_retries",
                            "max_log_size_mb",
                            "log_retention_days",
                            "watch_batch_delay",
                            "watch_max_batch",
                        ]:
                            try:
                                config_data[key] = int(value)
                            except ValueError:
                                print(
                                    f"Warning: Invalid integer value in config for {key}: {value}"
                                )
                        elif key == "appliance_skip_tls_verify":
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

                for key in section:
                    if key in config_data and key not in parser.defaults():
                        value = section[key]
                        # Convert types appropriately
                        if key in [
                            "max_log_size_mb",
                            "log_retention_days",
                        ]:
                            try:
                                config_data[key] = int(value)
                            except ValueError:
                                print(
                                    f"Warning: Invalid integer value in config for {key}: {value}"
                                )
                        elif key == "save_response_info":
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

                for key in section:
                    if key in config_data and key not in parser.defaults():
                        value = section[key]
                        # Convert types appropriately
                        if key in [
                            "watch_batch_delay",
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

                for key in section:
                    if key in config_data and key not in parser.defaults():
                        value = section[key]
                        if key in ["tex_enabled"]:
                            config_data[key] = value.lower() in [
                                "true",
                                "1",
                                "yes",
                                "on",
                            ]
                        elif key == "tex_max_file_size_mb":
                            try:
                                config_data[key] = int(value)
                            except ValueError:
                                print(
                                    f"Warning: Invalid integer value in config for {key}: {value}"
                                )
                        else:
                            config_data[key] = value.strip()

            # Read from TEX_SUPPORTED_FILE_TYPES section
            if "TEX_SUPPORTED_FILE_TYPES" in parser:
                section = parser["TEX_SUPPORTED_FILE_TYPES"]
                enabled_types = set()
                for ext, value in section.items():
                    if ext in parser.defaults():
                        continue
                    if value.lower() in ["true", "1", "yes", "on"]:
                        enabled_types.add(ext.lower())
                if enabled_types:
                    config_data["tex_supported_file_types"] = enabled_types

            # Read from TEX_SCRUBBED_PARTS section
            if "TEX_SCRUBBED_PARTS" in parser:
                section = parser["TEX_SCRUBBED_PARTS"]
                enabled_parts = set()
                for code, value in section.items():
                    if code in parser.defaults():
                        continue
                    val = value.split("#")[0].strip().lower()
                    if val in ["true", "1", "yes", "on"]:
                        enabled_parts.add(int(code))
                if enabled_parts:
                    config_data["tex_scrubbed_parts_codes"] = enabled_parts
                else:
                    config_data["tex_scrubbed_parts_codes"] = None

            # Read from ARCHIVE_FILE_TYPES section
            if "ARCHIVE_FILE_TYPES" in parser:
                section = parser["ARCHIVE_FILE_TYPES"]
                enabled_types = set()
                for ext, value in section.items():
                    if ext in parser.defaults():
                        continue
                    if value.lower() in ["true", "1", "yes", "on"]:
                        enabled_types.add(ext.lower())
                if enabled_types:
                    config_data["archive_extensions"] = enabled_types

            # Read from EMAIL section
            if "EMAIL" in parser:
                section = parser["EMAIL"]

                for key in section:
                    if key in config_data and key not in parser.defaults():
                        value = section[key]
                        # Convert types appropriately
                        if key in ["email_smtp_port", "email_imap_port"]:
                            try:
                                config_data[key] = int(value)
                            except ValueError:
                                print(
                                    f"Warning: Invalid integer value in config for {key}: {value}"
                                )
                        elif key == "email_tls_method":
                            config_data[key] = value.strip().lower()
                        elif key in [
                            "email_enabled",
                            "email_skip_tls_verify",
                            "email_imap_enabled",
                 "email_imap_use_ssl",
                            "email_imap_skip_tls_verify",
                            "email_malicious_only",
                            "email_include_log",
                        ]:
                            config_data[key] = value.lower() in [
                                "true",
                                "1",
                                "yes",
                                "on",
                            ]
                        else:
                            config_data[key] = value

            # Read from OS_IMAGES section - manual parsing to preserve inline comments
            if "OS_IMAGES" in parser:
                os_images_list = []
                uuid_pattern = re.compile(
                    r'^([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\s*=\s*(true|false)\s*(#.*)?$'
                )

                try:
                    with open(config_file, "r", encoding='utf-8-sig') as f:
                        in_section = False
                        for line in f:
                            stripped = line.strip()
                            if stripped == "[OS_IMAGES]":
                                in_section = True
                                continue
                            elif stripped and stripped[0] == "[" and stripped[-1] == "]":
                                in_section = False
                                continue
                            if in_section and stripped and not stripped.startswith("#"):
                                match = uuid_pattern.match(stripped)
                                if match:
                                    uuid_val = match.group(1).lower()
                                    enabled_val = match.group(2).lower() == "true"
                                    comment = match.group(3) or ""
                                    name = comment.lstrip("#").strip()
                                    is_default = "[DEFAULT]" in name
                                    if is_default:
                                        name = name.replace("[DEFAULT]", "").strip()
                                    os_images_list.append({
                                        "id": uuid_val,
                                        "revision": 1,
                                        "name": name,
                                        "is_default": is_default,
                                        "enabled": is_default or enabled_val,
                                    })
                except (IOError, OSError):
                    pass

                if os_images_list:
                    config_data["os_images"] = os_images_list

            # Read from AV_FALLBACK section
            if "AV_FALLBACK" in parser:
                section = parser["AV_FALLBACK"]
                for key in section:
                    if key not in parser.defaults():
                        # Handle deprecated key name
                        if key == "av_te_threshold_mb":
                            print(
                                f"Warning: [AV_FALLBACK] key 'av_te_threshold_mb' is deprecated, "
                                f"use 'te_to_av_fallback_at_mb' instead. "
                                f"Using value {section[key]} for backward compatibility."
                            )
                            config_data["te_to_av_fallback_at_mb"] = section[key]
                            continue
                        if key not in config_data:
                            continue
                        value = section[key]
                        if key == "av_fallback_enabled":
                            config_data[key] = value.lower() in [
                                "true",
                                "1",
                                "yes",
                                "on",
                            ]
                        elif key in ("av_rule_id", "te_to_av_fallback_at_mb", "av_to_signature_fallback_at_mb"):
                            try:
                                config_data[key] = int(value)
                            except ValueError:
                                print(
                                    f"Warning: Invalid integer value in config for {key}: {value}"
                                )
                        elif key == "tex_max_file_size_mb":
                            try:
                                config_data[key] = int(value)
                            except ValueError:
                                print(
                                    f"Warning: Invalid integer value in config for {key}: {value}"
                                )
                        else:
                            config_data[key] = value

            # Read from HEALTHCHECK section
            if "HEALTHCHECK" in parser:
                section = parser["HEALTHCHECK"]
                for key in section:
                    if key in config_data and key not in parser.defaults():
                        config_data[key] = section[key]

        # 3. Override with environment variables
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
                    "watch_max_batch",
                    "email_smtp_port",
                    "email_imap_port",
                ]:
                    try:
                        config_data[key] = int(value)
                    except ValueError:
                        print(f"Warning: Invalid integer value for {env_key}: {value}")
                elif key == "email_tls_method":
                    config_data[key] = value.strip().lower()
                elif key in [
                    "watch_mode",
                    "email_enabled",
                    "email_skip_tls_verify",
                    "email_imap_enabled",
 "email_imap_use_ssl",
                    "email_imap_skip_tls_verify",
                    "email_malicious_only",
                    "email_include_log",
                    "appliance_skip_tls_verify",
                    "tex_enabled",
                    "save_response_info",
                ]:
                    config_data[key] = value.lower() in ["true", "1", "yes", "on"]
                elif key in ["archive_extensions", "tex_supported_file_types"]:
                    config_data[key] = set(v.strip().lower() for v in value.split(",") if v.strip())
                elif key == "tex_scrubbed_parts_codes":
                    try:
                        config_data[key] = set(int(v.strip()) for v in value.split(",") if v.strip())
                    except ValueError:
                        print(f"Warning: Invalid integer value for {env_key}: {value}")
                else:
                    config_data[key] = value

        # AV fallback env vars
        _av_env_keys = {"av_fallback_enabled", "ssh_username", "ssh_password", "av_remote_directory", "av_rule_id", "te_to_av_fallback_at_mb", "av_to_signature_fallback_at_mb"}
        for key in _av_env_keys:
            env_key = env_prefix + key.upper()
            if env_key in os.environ:
                value = os.environ[env_key]
                if key == "av_fallback_enabled":
                    config_data[key] = value.lower() in ["true", "1", "yes", "on"]
                elif key in ("av_rule_id", "te_to_av_fallback_at_mb", "av_to_signature_fallback_at_mb"):
                    try:
                        config_data[key] = int(value)
                    except ValueError:
                        print(f"Warning: Invalid integer value for {env_key}: {value}")
                else:
                    config_data[key] = value

        # TEX env vars
        _tex_env_keys = {"tex_max_file_size_mb"}
        for key in _tex_env_keys:
            env_key = env_prefix + key.upper()
            if env_key in os.environ:
                value = os.environ[env_key]
                try:
                    config_data[key] = int(value)
                except ValueError:
                    print(f"Warning: Invalid integer value for {env_key}: {value}")

        # Health check env vars
        _hc_env_keys = {"healthcheck_directory"}
        for key in _hc_env_keys:
            env_key = env_prefix + key.upper()
            if env_key in os.environ:
                config_data[key] = os.environ[env_key]

        # 4. Override with command-line arguments (highest priority)
        if cli_args:
            # (cli_attr, config_key) mappings — applies getattr(cli_args, attr) if truthy
            _cli_override_keys = {
                "appliance_skip_tls_verify",  # bool with default=None → use "is not None"
                "save_response_info",  # bool with default=None → use "is not None"
            }
            _cli_mappings = [
                ("input_directory", "input_directory"),
                ("reports_directory", "reports_directory"),
                ("appliance_ip", "appliance_ip"),
                ("appliance_skip_tls_verify", "appliance_skip_tls_verify"),
                ("save_response_info", "save_response_info"),
                ("benign_directory", "benign_directory"),
                ("quarantine_directory", "quarantine_directory"),
                ("error_directory", "error_directory"),
                ("concurrency", "concurrency"),
                ("seconds_to_wait", "seconds_to_wait"),
                ("max_retries", "max_retries"),
                ("watch", "watch_mode"),
                ("watch_delay", "watch_batch_delay"),
                ("watch_max", "watch_max_batch"),
                ("email_enabled", "email_enabled"),
                ("email_smtp_server", "email_smtp_server"),
                ("email_smtp_port", "email_smtp_port"),
                ("email_tls_method", "email_tls_method"),
                ("email_skip_tls_verify", "email_skip_tls_verify"),
                ("email_username", "email_username"),
                ("email_from", "email_from"),
                ("email_to", "email_to"),
                ("email_subject_template", "email_subject_template"),
("email_template_file", "email_template_file"),
            ("email_malicious_only", "email_malicious_only"),
            ("email_include_log", "email_include_log"),
            ("email_imap_enabled", "email_imap_enabled"),
                ("email_imap_server", "email_imap_server"),
                ("email_imap_port", "email_imap_port"),
                ("email_imap_use_ssl", "email_imap_use_ssl"),
                ("email_imap_skip_tls_verify", "email_imap_skip_tls_verify"),
                ("email_imap_username", "email_imap_username"),
                ("email_imap_folder", "email_imap_folder"),
                ("av_enabled", "av_fallback_enabled"),
                ("av_username", "ssh_username"),
                ("av_password", "ssh_password"),
                ("av_remote_dir", "av_remote_directory"),
                ("av_rule_id", "av_rule_id"),
                ("av_te_threshold_mb", "te_to_av_fallback_at_mb"),  # deprecated CLI name, maps to new key
                ("av_to_signature_threshold_mb", "av_to_signature_fallback_at_mb"),
                ("zip_archive_directory", "zip_archive_directory"),
                ("tex_enabled", "tex_enabled"),
                ("tex_url", "tex_url"),
                ("tex_response_info_dir", "tex_response_info_directory"),
                ("tex_clean_files_dir", "tex_clean_files_directory"),
                ("tex_max_file_size_mb", "tex_max_file_size_mb"),
                ("healthcheck_dir", "healthcheck_directory"),
            ]
            _int_cli_keys = {
                "concurrency",
                "seconds_to_wait",
                "max_retries",
                "watch_batch_delay",
                "watch_max_batch",
                "email_smtp_port",
                "email_imap_port",
                "av_rule_id",
                "te_to_av_fallback_at_mb",
                "av_to_signature_fallback_at_mb",
                "tex_max_file_size_mb",
            }
            for cli_attr, config_key in _cli_mappings:
                val = getattr(cli_args, cli_attr, None)
                if config_key in _int_cli_keys:
                    if val is not None:
                        config_data[config_key] = val
                elif config_key in _cli_override_keys:
                    if val is not None:
                        config_data[config_key] = val
                elif val:
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
            if config_data[key] is not None:
                config_data[key] = PathHandler.normalize_path(config_data[key])
            else:
                config_data[key] = None

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

        # Ensure all boolean fields are actually booleans
        _bool_fields = [
            "watch_mode",
            "appliance_skip_tls_verify",
            "tex_enabled",
            "save_response_info",
            "email_enabled",
            "email_skip_tls_verify",
            "email_imap_enabled",
 "email_imap_use_ssl",
            "email_imap_skip_tls_verify",
            "email_malicious_only",
            "email_include_log",
        ]
        for key in _bool_fields:
            if key in config_data and not isinstance(config_data[key], bool):
                config_data[key] = str(config_data[key]).lower() in [
                    "true",
                    "1",
                    "yes",
                    "on",
                ]

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
        if self.email_enabled and self.email_malicious_only:
            print(f"  Malicious only:        Yes")
        if self.email_enabled:
            print(
                f"  SMTP server:           {self.email_smtp_server}:{self.email_smtp_port}"
            )
            print(f"  TLS method:            {self.email_tls_method}")
            if self.email_tls_method != "none":
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
            print(f"  Max file size (MB):    {self.tex_max_file_size_mb}")

        # AV Fallback Configuration
        print("AV Fallback:")
        print(f"  Enabled:               {'Yes' if self.av_fallback_enabled else 'No'}")
        if self.av_fallback_enabled:
            print(f"  SSH Username:          {self.ssh_username}")
            print(f"  SSH Password:          {'Set' if self.ssh_password else '(empty)'}")
            print(f"  Remote Directory:      {self.av_remote_directory}")
            print(f"  AV Rule ID:            {self.av_rule_id}")
            print(f"  TE → AV Threshold:     {self.te_to_av_fallback_at_mb} MB")
            print(f"  AV → Sig Threshold:    {self.av_to_signature_fallback_at_mb} MB")

        # Health Check Configuration
        print("Health Check:")
        print(f"  Directory:             {self.healthcheck_directory}")

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
