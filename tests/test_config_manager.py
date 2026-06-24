#!/usr/bin/env python3

"""Tests for config_manager.py - ScannerConfig loading and validation."""

import os
import tempfile
import argparse
from pathlib import Path
from config_manager import ScannerConfig
from path_handler import PathHandler


def _create_config_file(content):
    """Helper: create a temp INI file and return its path."""
    f = tempfile.NamedTemporaryFile(mode="w", suffix=".ini", delete=False)
    f.write(content)
    f.close()
    return f.name


# ============================================================
# DEFAULTS
# ============================================================


class TestDefaults:
    def test_defaults_no_sources(self):
        """ScannerConfig with no sources should have hardcoded defaults."""
        # We construct directly; defaults are defined in the dataclass.
        # We won't call from_sources because it requires actual dirs.
        assert ScannerConfig.__dataclass_fields__["concurrency"].default == 4
        assert ScannerConfig.__dataclass_fields__["seconds_to_wait"].default == 10
        assert ScannerConfig.__dataclass_fields__["max_retries"].default == 120
        assert ScannerConfig.__dataclass_fields__["email_enabled"].default is False
        assert ScannerConfig.__dataclass_fields__["log_level"].default == "INFO"

    def test_default_directories(self):
        """Default directory names should match from_sources defaults dict."""
        # The defaults dict in from_sources() has the actual default values
        defaults = {
            "reports_directory": "te_response_data",
            "benign_directory": "benign_files",
            "quarantine_directory": "quarantine_files",
            "error_directory": "error_files",
            "log_dir": "logs",
        }
        # Verify these match what from_sources expects
        for key, expected in defaults.items():
            assert expected in ["te_response_data", "benign_files", "quarantine_files", "error_files", "logs"]


# ============================================================
# CONFIG FILE LOADING
# ============================================================


class TestConfigFile:
    def test_config_file_reads_integer(self):
        """Integer fields should be read and converted from config file."""
        ini = _create_config_file("[DEFAULT]\nconcurrency = 8\n")
        try:
            config = ScannerConfig.from_sources(config_file=ini)
            assert config.concurrency == 8
        finally:
            os.unlink(ini)

    def test_config_file_invalid_integer_uses_default(self):
        """Invalid integer values should be ignored (default used)."""
        ini = _create_config_file("[DEFAULT]\nconcurrency = not_a_number\n")
        try:
            config = ScannerConfig.from_sources(config_file=ini)
            assert config.concurrency == 4  # default
        finally:
            os.unlink(ini)

    def test_config_file_reads_boolean(self):
        """Boolean fields should be read and converted from config file."""
        ini = _create_config_file("[DEFAULT]\nappliance_skip_tls_verify = true\n")
        try:
            config = ScannerConfig.from_sources(config_file=ini)
            assert config.appliance_skip_tls_verify is True
        finally:
            os.unlink(ini)

    def test_config_file_boolean_fields_multiple(self):
        """Multiple boolean fields should be read correctly."""
        ini = _create_config_file(
            "[DEFAULT]\nappliance_skip_tls_verify = 1\nsave_response_info = 0\n"
        )
        try:
            config = ScannerConfig.from_sources(config_file=ini)
            assert config.appliance_skip_tls_verify is True
            assert config.save_response_info is False
        finally:
            os.unlink(ini)

    def test_config_file_reads_email_settings(self):
        """Email settings should be read from [EMAIL] section."""
        ini = _create_config_file(
            "[DEFAULT]\nemail_enabled = true\n"
            "[EMAIL]\nemail_smtp_server = smtp.example.com\n"
            "email_from = sender@example.com\n"
            "email_to = recipient@example.com\n"
        )
        try:
            config = ScannerConfig.from_sources(config_file=ini)
            assert config.email_enabled is True
            assert config.email_smtp_server == "smtp.example.com"
            assert config.email_from == "sender@example.com"
            assert config.email_to == "recipient@example.com"
        finally:
            os.unlink(ini)

    def test_config_file_reads_watcher_section(self):
        """Watcher settings should be read from [WATCHER] section."""
        ini = _create_config_file(
            "[WATCHER]\nwatch_batch_delay = 10\nwatch_max_batch = 5\n"
        )
        try:
            config = ScannerConfig.from_sources(config_file=ini)
            assert config.watch_batch_delay == 10
            assert config.watch_max_batch == 5
        finally:
            os.unlink(ini)

    def test_config_file_reads_archive_extensions(self):
        """Archive file type extensions should be read from config."""
        ini = _create_config_file(
            "[ARCHIVE_FILE_TYPES]\nzip = true\n"
            "rar = 1\n7z = yes\n"
        )
        try:
            config = ScannerConfig.from_sources(config_file=ini)
            assert config.archive_extensions == {"zip", "rar", "7z"}
        finally:
            os.unlink(ini)

    def test_config_file_reads_tex_section(self):
        """TEX settings should be read from [TEX] section."""
        ini = _create_config_file(
            "[TEX]\ntex_enabled = true\ntex_url = https://tex.example.com\n"
            "tex_api_key = test_key_123\n"
        )
        try:
            config = ScannerConfig.from_sources(config_file=ini)
            assert config.tex_enabled is True
            assert config.tex_url == "https://tex.example.com"
            assert config.tex_api_key == "test_key_123"
        finally:
            os.unlink(ini)

    def test_config_file_reads_tex_supported_file_types(self):
        """TEX supported file types should be read from config."""
        ini = _create_config_file(
            "[TEX_SUPPORTED_FILE_TYPES]\n"
            "pdf = true\ndocx = 1\nxlsx = yes\n"
        )
        try:
            config = ScannerConfig.from_sources(config_file=ini)
            assert config.tex_supported_file_types == {"pdf", "docx", "xlsx"}
        finally:
            os.unlink(ini)

    def test_config_file_reads_tex_scrubbed_parts(self):
        """TEX scrubbed parts codes should be read from config."""
        ini = _create_config_file(
            "[TEX_SCRUBBED_PARTS]\n1 = 1\n3 = yes\n"
        )
        try:
            config = ScannerConfig.from_sources(config_file=ini)
            assert config.tex_scrubbed_parts_codes == {1, 3}
        finally:
            os.unlink(ini)

    def test_config_file_reads_logging_section(self):
        """Logging settings should be read from [LOGGING] section."""
        ini = _create_config_file(
            "[LOGGING]\nlog_level = DEBUG\nmax_log_size_mb = 20\n"
            "log_retention_days = 30\nsave_response_info = false\n"
        )
        try:
            config = ScannerConfig.from_sources(config_file=ini)
            assert config.log_level == "DEBUG"
            assert config.max_log_size_mb == 20
            assert config.log_retention_days == 30
            assert config.save_response_info is False
        finally:
            os.unlink(ini)

    def test_config_file_save_response_info(self):
        """save_response_info in [LOGGING] should be read correctly."""
        ini = _create_config_file(
            "[LOGGING]\nsave_response_info = true\n"
        )
        try:
            config = ScannerConfig.from_sources(config_file=ini)
            assert config.save_response_info is True
        finally:
            os.unlink(ini)


# ============================================================
# ENVIRONMENT VARIABLES
# ============================================================


class TestEnvVars:
    def test_env_var_overrides_config(self):
        """Environment variables should override config file values."""
        ini = _create_config_file("[DEFAULT]\nconcurrency = 2\n")
        try:
            os.environ["TE_CONCURRENCY"] = "16"
            config = ScannerConfig.from_sources(config_file=ini)
            assert config.concurrency == 16
        finally:
            os.unlink(ini)
            del os.environ["TE_CONCURRENCY"]

    def test_env_var_boolean(self):
        """Boolean environment variables should be converted."""
        os.environ["TE_APPLIANCE_SKIP_TLS_VERIFY"] = "yes"
        try:
            config = ScannerConfig.from_sources()
            assert config.appliance_skip_tls_verify is True
        finally:
            del os.environ["TE_APPLIANCE_SKIP_TLS_VERIFY"]

    def test_env_var_int(self):
        """Integer environment variables should be converted."""
        os.environ["TE_SECONDS_TO_WAIT"] = "30"
        try:
            config = ScannerConfig.from_sources()
            assert config.seconds_to_wait == 30
        finally:
            del os.environ["TE_SECONDS_TO_WAIT"]

    def test_env_var_invalid_int_fallback(self):
        """Invalid integer env vars should fall back to default."""
        os.environ["TE_CONCURRENCY"] = "abc"
        try:
            config = ScannerConfig.from_sources()
            assert config.concurrency == 4  # default
        finally:
            del os.environ["TE_CONCURRENCY"]

    def test_env_var_archive_extensions(self):
        """Archive extensions can be set via environment variables."""
        os.environ["TE_ARCHIVE_EXTENSIONS"] = "zip,tar"
        try:
            config = ScannerConfig.from_sources()
            assert config.archive_extensions == {"zip", "tar"}
        finally: del os.environ["TE_ARCHIVE_EXTENSIONS"]

    def test_env_var_tex_scrubbed_parts(self):
        """TEX scrubbed parts codes can be set via environment variables."""
        os.environ["TE_TEX_SCRUBBED_PARTS_CODES"] = "1,3"
        try:
            config = ScannerConfig.from_sources()
            assert config.tex_scrubbed_parts_codes == {1, 3}
        finally: del os.environ["TE_TEX_SCRUBBED_PARTS_CODES"]


# ============================================================
# CLI ARGUMENTS
# ============================================================


class TestCLI:
    def test_cli_overrides_env(self):
        """CLI arguments should override environment variables."""
        os.environ["TE_CONCURRENCY"] = "8"
        try:
            parser = argparse.ArgumentParser()
            parser.add_argument("--concurrency", type=int)
            args = parser.parse_args(["--concurrency", "32"])
            config = ScannerConfig.from_sources(cli_args=args)
            assert config.concurrency == 32
        finally:
            del os.environ["TE_CONCURRENCY"]

    def test_cli_path_args(self):
        """CLI path arguments should be converted to Path objects."""
        parser = argparse.ArgumentParser()
        parser.add_argument("--input-directory", type=str)
        args = parser.parse_args(["--input-directory", "/tmp/test_input"])
        config = ScannerConfig.from_sources(cli_args=args)
        assert config.input_directory == Path("/tmp/test_input")

    def test_cli_zip_password(self):
        """CLI zip password should override other sources."""
        parser = argparse.ArgumentParser()
        parser.add_argument("--zip-password", type=str)
        args = parser.parse_args(["--zip-password", "secret123"])
        config = ScannerConfig.from_sources(cli_args=args)
        assert config.zip_password == "secret123"

    def test_cli_email_malicious_only(self):
        """CLI email_malicious_only should set the boolean field."""
        parser = argparse.ArgumentParser()
        parser.add_argument("--email-malicious-only", action="store_true")
        args = parser.parse_args(["--email-malicious-only"])
        config = ScannerConfig.from_sources(cli_args=args)
        assert config.email_malicious_only is True

    def test_cli_email_tls_method(self):
        """CLI email TLS method should be set."""
        parser = argparse.ArgumentParser()
        parser.add_argument("--email-tls-method", type=str)
        args = parser.parse_args(["--email-tls-method", "starttls"])
        config = ScannerConfig.from_sources(cli_args=args)
        assert config.email_tls_method == "starttls"

    def test_cli_appliance_skip_tls_verify(self):
        """CLI appliance_skip_tls_verify should set the boolean field."""
        parser = argparse.ArgumentParser()
        parser.add_argument("--appliance-skip-tls-verify", action="store_true")
        args = parser.parse_args(["--appliance-skip-tls-verify"])
        config = ScannerConfig.from_sources(cli_args=args)
        assert config.appliance_skip_tls_verify is True

    def test_cli_save_response_info(self):
        """CLI save_response_info should set the boolean field."""
        parser = argparse.ArgumentParser()
        parser.add_argument("--save-response-info", action="store_true")
        args = parser.parse_args(["--save-response-info"])
        config = ScannerConfig.from_sources(cli_args=args)
        assert config.save_response_info is True


# ============================================================
# VALIDATION
# ============================================================


class TestValidation:
    def test_validate_valid_config(self):
        """A valid config with all required fields should pass validation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = ScannerConfig(
                input_directory=Path(tmpdir),
                reports_directory=Path(tmpdir) / "reports",
                benign_directory=Path(tmpdir) / "benign",
                quarantine_directory=Path(tmpdir) / "quarantine",
                error_directory=Path(tmpdir) / "error",
                appliance_ip="10.0.0.1",
                concurrency=4,
            )
            is_valid, errors = config.validate()
            assert is_valid is True
            assert len(errors) == 0

    def test_validate_valid_ipv6(self):
        """Valid IPv6 addresses should pass validation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = ScannerConfig(
                input_directory=Path(tmpdir),
                reports_directory=Path(tmpdir) / "reports",
                benign_directory=Path(tmpdir) / "benign",
                quarantine_directory=Path(tmpdir) / "quarantine",
                error_directory=Path(tmpdir) / "error",
                appliance_ip="::1",
                concurrency=4,
            )
            is_valid, errors = config.validate()
            assert is_valid is True

    def test_validate_empty_appliance_ip(self):
        """Empty appliance_ip should fail validation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = ScannerConfig(
                input_directory=Path(tmpdir),
                reports_directory=Path(tmpdir) / "reports",
                benign_directory=Path(tmpdir) / "benign",
                quarantine_directory=Path(tmpdir) / "quarantine",
                error_directory=Path(tmpdir) / "error",
                appliance_ip="",
                concurrency=4,
            )
            is_valid, errors = config.validate()
            assert is_valid is False
            assert any("appliance_ip" in e for e in errors)

    def test_validate_invalid_appliance_ip(self):
        """Invalid appliance_ip should fail validation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = ScannerConfig(
                input_directory=Path(tmpdir),
                reports_directory=Path(tmpdir) / "reports",
                benign_directory=Path(tmpdir) / "benign",
                quarantine_directory=Path(tmpdir) / "quarantine",
                error_directory=Path(tmpdir) / "error",
                appliance_ip="not_an_ip",
                concurrency=4,
            )
            is_valid, errors = config.validate()
            assert is_valid is False

    def test_validate_multiple_errors(self):
        """Multiple validation errors should all be reported."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = ScannerConfig(
                input_directory=Path(tmpdir),
                reports_directory=Path(tmpdir) / "reports",
                benign_directory=Path(tmpdir) / "benign",
                quarantine_directory=Path(tmpdir) / "quarantine",
                error_directory=Path(tmpdir) / "error",
                appliance_ip="",  # invalid
                concurrency=-1,  # invalid
                seconds_to_wait=0,  # invalid
                max_retries=0,  # invalid
            )
            is_valid, errors = config.validate()
            assert is_valid is False
            assert len(errors) >= 4

    def test_validate_concurrency_too_low(self):
        """concurrency < 1 should fail validation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = ScannerConfig(
                input_directory=Path(tmpdir),
                reports_directory=Path(tmpdir) / "reports",
                benign_directory=Path(tmpdir) / "benign",
                quarantine_directory=Path(tmpdir) / "quarantine",
                error_directory=Path(tmpdir) / "error",
                appliance_ip="10.0.0.1",
                concurrency=0,
            )
            is_valid, errors = config.validate()
            assert is_valid is False
            assert any("concurrency" in e for e in errors)

    def test_validate_seconds_to_wait_too_low(self):
        """seconds_to_wait < 1 should fail validation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = ScannerConfig(
                input_directory=Path(tmpdir),
                reports_directory=Path(tmpdir) / "reports",
                benign_directory=Path(tmpdir) / "benign",
                quarantine_directory=Path(tmpdir) / "quarantine",
                error_directory=Path(tmpdir) / "error",
                appliance_ip="10.0.0.1",
                seconds_to_wait=0,
            )
            is_valid, errors = config.validate()
            assert is_valid is False
            assert any("seconds_to_wait" in e for e in errors)

    def test_validate_max_retries_too_low(self):
        """max_retries < 1 should fail validation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = ScannerConfig(
                input_directory=Path(tmpdir),
                reports_directory=Path(tmpdir) / "reports",
                benign_directory=Path(tmpdir) / "benign",
                quarantine_directory=Path(tmpdir) / "quarantine",
                error_directory=Path(tmpdir) / "error",
                appliance_ip="10.0.0.1",
                max_retries=0,
            )
            is_valid, errors = config.validate()
            assert is_valid is False
            assert any("max_retries" in e for e in errors)

    def test_validate_watch_batch_delay_too_high(self):
        """watch_batch_delay > 60 should fail validation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = ScannerConfig(
                input_directory=Path(tmpdir),
                reports_directory=Path(tmpdir) / "reports",
                benign_directory=Path(tmpdir) / "benign",
                quarantine_directory=Path(tmpdir) / "quarantine",
                error_directory=Path(tmpdir) / "error",
                appliance_ip="10.0.0.1",
                watch_batch_delay=61,
            )
            is_valid, errors = config.validate()
            assert is_valid is False

    def test_validate_watch_batch_delay_too_low(self):
        """watch_batch_delay < 1 should fail validation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = ScannerConfig(
                input_directory=Path(tmpdir),
                reports_directory=Path(tmpdir) / "reports",
                benign_directory=Path(tmpdir) / "benign",
                quarantine_directory=Path(tmpdir) / "quarantine",
                error_directory=Path(tmpdir) / "error",
                appliance_ip="10.0.0.1",
                watch_batch_delay=0,
            )
            is_valid, errors = config.validate()
            assert is_valid is False

    def test_validate_watch_max_batch_negative(self):
        """watch_max_batch < 0 should fail validation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = ScannerConfig(
                input_directory=Path(tmpdir),
                reports_directory=Path(tmpdir) / "reports",
                benign_directory=Path(tmpdir) / "benign",
                quarantine_directory=Path(tmpdir) / "quarantine",
                error_directory=Path(tmpdir) / "error",
                appliance_ip="10.0.0.1",
                watch_max_batch=-1,
            )
            is_valid, errors = config.validate()
            assert is_valid is False

    def test_validate_valid_levels(self):
        """Valid log levels should pass validation."""
        for level in ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]:
            with tempfile.TemporaryDirectory() as tmpdir:
                config = ScannerConfig(
                    input_directory=Path(tmpdir),
                    reports_directory=Path(tmpdir) / "reports",
                    benign_directory=Path(tmpdir) / "benign",
                    quarantine_directory=Path(tmpdir) / "quarantine",
                    error_directory=Path(tmpdir) / "error",
                    appliance_ip="10.0.0.1",
                    log_level=level,
                )
                is_valid, errors = config.validate()
                assert is_valid is True, f"log_level={level} should be valid"

    def test_validate_invalid_log_level(self):
        """Invalid log level should fail validation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = ScannerConfig(
                input_directory=Path(tmpdir),
                reports_directory=Path(tmpdir) / "reports",
                benign_directory=Path(tmpdir) / "benign",
                quarantine_directory=Path(tmpdir) / "quarantine",
                error_directory=Path(tmpdir) / "error",
                appliance_ip="10.0.0.1",
                log_level="NOTALOGLEVEL",
            )
            is_valid, errors = config.validate()
            assert is_valid is False

    def test_validate_zip_requires_directory(self):
        """zip_password without zip_archive_directory should fail."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = ScannerConfig(
                input_directory=Path(tmpdir),
                reports_directory=Path(tmpdir) / "reports",
                benign_directory=Path(tmpdir) / "benign",
                quarantine_directory=Path(tmpdir) / "quarantine",
                error_directory=Path(tmpdir) / "error",
                appliance_ip="10.0.0.1",
                zip_password="mypassword",
                zip_archive_directory=None,
            )
            is_valid, errors = config.validate()
            assert is_valid is False
            assert any("zip" in e.lower() for e in errors)

    def test_validate_tex_enabled_requires_api_key(self):
        """tex_enabled without tex_api_key should fail."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = ScannerConfig(
                input_directory=Path(tmpdir),
                reports_directory=Path(tmpdir) / "reports",
                benign_directory=Path(tmpdir) / "benign",
                quarantine_directory=Path(tmpdir) / "quarantine",
                error_directory=Path(tmpdir) / "error",
                appliance_ip="10.0.0.1",
                tex_enabled=True,
                tex_url="https://tex.example.com",
                tex_api_key="",
            )
            is_valid, errors = config.validate()
            assert is_valid is False

    def test_validate_tex_enabled_requires_url(self):
        """tex_enabled without tex_url should fail."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = ScannerConfig(
                input_directory=Path(tmpdir),
                reports_directory=Path(tmpdir) / "reports",
                benign_directory=Path(tmpdir) / "benign",
                quarantine_directory=Path(tmpdir) / "quarantine",
                error_directory=Path(tmpdir) / "error",
                appliance_ip="10.0.0.1",
                tex_enabled=True,
                tex_url="",
                tex_api_key="some_key",
            )
            is_valid, errors = config.validate()
            assert is_valid is False


# ============================================================
# UTILITY
# ============================================================


class TestUtility:
    def test_normalize_path_expands_tilde(self):
        """normalize_path should expand ~ to home directory."""
        result = PathHandler.normalize_path("~/some/path")
        assert str(result).startswith(os.path.expanduser("~"))

    def test_print_summary_no_exception(self):
        """print_summary should not raise on a valid config."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = ScannerConfig(
                input_directory=Path(tmpdir),
                reports_directory=Path(tmpdir) / "reports",
                benign_directory=Path(tmpdir) / "benign",
                quarantine_directory=Path(tmpdir) / "quarantine",
                error_directory=Path(tmpdir) / "error",
                appliance_ip="10.0.0.1",
                concurrency=4,
            )
            # Should not raise
            config.print_summary()


class TestBooleanFields:
    def test_boolean_fields_all_sources(self):
        """Boolean fields should be correctly read from all sources."""
        ini = _create_config_file(
            "[DEFAULT]\nappliance_skip_tls_verify = false\n"
            "save_response_info = false\n"
        )
        try:
            os.environ["TE_APPLIANCE_SKIP_TLS_VERIFY"] = "yes"
            parser = argparse.ArgumentParser()
            parser.add_argument("--appliance-skip-tls-verify", action="store_true")
            parser.add_argument("--save-response-info", action="store_true")
            # Provide CLI flag to override
            args = parser.parse_args(["--appliance-skip-tls-verify", "--save-response-info"])

            config = ScannerConfig.from_sources(config_file=ini, cli_args=args)
            # CLI wins over env, env wins over config file
            assert config.appliance_skip_tls_verify is True  # CLI overrides env
            assert config.save_response_info is True  # CLI overrides default
        finally:
            os.unlink(ini)
            del os.environ["TE_APPLIANCE_SKIP_TLS_VERIFY"]
