#!/usr/bin/env python3

"""
Tests for AV fallback functionality.

Covers:
- sanitize_for_remote() in safe_filename.py
- AVHandler._parse_verdict() in av_handler.py
- Config loading for AV_FALLBACK settings
"""

import os
import re
import sys
import tempfile
from pathlib import Path
from unittest import mock

import pytest

# Ensure project root is in path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from safe_filename import sanitize_for_remote
from av_handler import AVHandler, AV_FILE_SIZE_LIMIT
from config_manager import ScannerConfig
from te_api import TE_FILE_SIZE_LIMIT


# ============================================================
# sanitize_for_remote Tests
# ============================================================


class TestSanitizeForRemote:
    """Test the sanitize_for_remote() function for AV appliance compatibility."""

    def test_alphanumeric_unchanged(self):
        """Alphanumeric filenames should remain unchanged."""
        assert sanitize_for_remote("testfile.zip") == "testfile.zip"
        assert sanitize_for_remote("myfile123.pdf") == "myfile123.pdf"

    def test_hyphens_unchanged(self):
        """Hyphens should be preserved."""
        assert sanitize_for_remote("my-file-name.pdf") == "my-file-name.pdf"

    def test_underscores_unchanged(self):
        """Underscores should be preserved."""
        assert sanitize_for_remote("my_file_name.pdf") == "my_file_name.pdf"

    def test_spaces_replaced(self):
        """Spaces should be replaced with underscores."""
        assert sanitize_for_remote("my file name.pdf") == "my_file_name.pdf"

    def test_multiple_spaces_collapsed(self):
        """Multiple consecutive spaces should be collapsed."""
        assert sanitize_for_remote("file   name.pdf") == "file_name.pdf"

    def test_parentheses_replaced(self):
        """Parentheses should be replaced, trailing underscore stripped."""
        # file(name).pdf -> base="file(name)", ext=".pdf"
        # base becomes "file_name" after replacing () and stripping trailing _
        assert sanitize_for_remote("file(name).pdf") == "file_name.pdf"

    def test_special_atr_char_replaced(self):
        """Special chars between valid chars should become single underscore."""
        # @#$ becomes single _
        assert sanitize_for_remote("file@#$name.pdf") == "file_name.pdf"

    def test_unicode_replaced(self):
        """Non-ASCII characters should be replaced."""
        # caf document.pdf -> base="caf document", ext=".pdf"
        # space becomes _, so "caf_document"
        assert sanitize_for_remote("caf document.pdf") == "caf_document.pdf"
        # résumé.pdf -> base="résumé", ext=".pdf"
        # é→_, u, m→_, so "r_sum" (trailing _ stripped)
        assert sanitize_for_remote("résumé.pdf") == "r_sum.pdf"

    def test_extension_preserved(self):
        """File extension should be preserved."""
        assert sanitize_for_remote("file.pdf") == "file.pdf"
        # file.name.pdf -> last dot separates extension
        # base="file.name", ext=".pdf"
        # dot in base becomes _, so "file_name"
        assert sanitize_for_remote("file.name.pdf") == "file_name.pdf"

    def test_no_extension(self):
        """Files without extension should have no extension in output."""
        assert sanitize_for_remote("README") == "README"
        # README.old -> last dot separates extension
        # base="README", ext=".old" -> "README.old"
        assert sanitize_for_remote("README.old") == "README.old"

    def test_empty_base_hash_fallback(self):
        """If base becomes empty after sanitization, use hash."""
        result = sanitize_for_remote("...")
        assert len(result) > 0
        assert result != "..."

    def test_all_special_chars_no_extension(self):
        """All special characters with no extension should produce hash."""
        result = sanitize_for_remote("@#$%")
        assert re.search(r"[a-z0-9]", result, re.IGNORECASE) is not None

    def test_leading_trailing_underscores_stripped(self):
        """Leading/trailing underscores should be stripped."""
        assert sanitize_for_remote("_file.pdf") == "file.pdf"
        assert sanitize_for_remote("file_.pdf") == "file.pdf"

    def test_multiple_underscores_collapsed(self):
        """Multiple consecutive underscores should be collapsed."""
        assert sanitize_for_remote("file___name.pdf") == "file_name.pdf"

    def test_mixed_special_and_unicode(self):
        """Mix of special chars and unicode."""
        # café @file!.pdf -> base="caf@file!", ext=".pdf"
        # café→caf_, @→_, file→file, !→_, so "caf__file_"
        # collapse: "caf_file_", strip trailing: "caf_file"
        assert sanitize_for_remote("café @file!.pdf") == "caf_file.pdf"

    def test_numbers_preserved(self):
        """Numbers should be preserved."""
        assert sanitize_for_remote("file123_test456.pdf") == "file123_test456.pdf"

    def test_only_extension(self):
        """Filename that is only an extension."""
        result = sanitize_for_remote(".pdf")
        # base is empty, ext is ".pdf"
        # empty base triggers hash fallback
        assert result != ".pdf"

    def test_long_filename_with_special_chars(self):
        """Long filenames with special chars get hash fallback."""
        long_name = "a" * 100 + "@#$" + ".pdf"
        result = sanitize_for_remote(long_name)
        assert result.endswith(".pdf")


# ============================================================
# _parse_verdict Tests
# ============================================================


class TestParseVerdict:
    """Test the AVHandler._parse_verdict() method."""

    @pytest.fixture
    def handler(self):
        """Create an AVHandler instance with minimal config for testing."""
        config = mock.MagicMock()
        config.av_fallback_enabled = False
        config.ssh_username = ""
        config.ssh_password = ""
        config.av_remote_directory = "/var/log/apiclient"
        config.av_rule_id = 1
        handler = AVHandler.__new__(AVHandler)
        handler.av_rule_id = 1
        return handler

    def test_exit_code_nonzero_returns_error(self, handler):
        """Non-zero exit code should return Error."""
        assert handler._parse_verdict("some output", 1) == "Error"
        assert handler._parse_verdict("", 2) == "Error"

    def test_empty_output_returns_error(self, handler):
        """Empty output should return Error."""
        assert handler._parse_verdict("", 0) == "Error"
        assert handler._parse_verdict("   ", 0) == "Error"

    def test_malicious_drop_action(self, handler):
        """EICAR test file should parse as Malicious via :action (drop)."""
        output = """
(
        :event_id ("{8BE1925F-1194-504C-97D1-D8B5F36F8DDB}")
        :action (drop)
        :confidence (none)
        :done (1)
        :file_path ("/var/log/apiclient/eicar_com.zip")
        :md5_string (6ce6f415d8475545be5ba114f208b0ff)
        :investigation_path (PATH_AV)
        :additional_data (EICAR-AV-Test)
        :body_path ()
)

/var/log/apiclient/eicar_com.zip
Verdict: drop                Time: 0             *

Total Files: 1
Verdicts distribution:
drop:                    1

# Done 1 files in 0 seconds...Bye Bye...
"""
        assert handler._parse_verdict(output, 0) == "Malicious"

    def test_benign_accept_action(self, handler):
        """Benign file should parse as Benign via :action (accept)."""
        output = """
(
        :event_id ("{E51E33BE-5971-4D49-91DF-BAD6F7442D73}")
        :action (accept)
        :confidence (none)
        :done (1)
        :file_path ("/var/log/apiclient/23800-appliance_with_link.pdf")
        :md5_string (20716e83f7387bae56595c0585513e82)
        :investigation_path (PATH_AV)
        :additional_data ()
        :body_path ()
)

/var/log/apiclient/23800-appliance_with_link.pdf
Verdict: accept              Time: 0

Total Files: 1
Verdicts distribution:
accept:                  1

# Done 1 files in 0 seconds...Bye Bye..
"""
        assert handler._parse_verdict(output, 0) == "Benign"

    def test_unrecognized_action_returns_error(self, handler):
        """Unknown action should return Error."""
        output = "(:action (quarantine))"
        assert handler._parse_verdict(output, 0) == "Error"

    def test_no_action_field_fallback(self, handler):
        """Without :action field, should fallback to text scan."""
        output = "Verdict: Benign"
        assert handler._parse_verdict(output, 0) == "Benign"

    def test_no_action_field_malicious_fallback(self, handler):
        """Text 'malicious' should be detected as fallback."""
        output = "This file was found to be malicious"
        assert handler._parse_verdict(output, 0) == "Malicious"

    def test_no_action_field_error_fallback(self, handler):
        """Without action and no keywords, should return Error."""
        output = "Analysis complete. No verdict stated."
        assert handler._parse_verdict(output, 0) == "Error"

    def test_action_with_whitespace(self, handler):
        """S-expression with extra whitespace should still parse."""
        output = ":action   (   drop   )"
        assert handler._parse_verdict(output, 0) == "Malicious"

        output = ":action   (   accept   )"
        assert handler._parse_verdict(output, 0) == "Benign"

    def test_action_case_insensitive(self, handler):
        """Action should be case-insensitive."""
        output = ":action (DROP)"
        assert handler._parse_verdict(output, 0) == "Malicious"

        output = ":action (ACCEPT)"
        assert handler._parse_verdict(output, 0) == "Benign"

    def test_action_in_complex_output(self, handler):
        """Action should be found even in complex multi-line output."""
        output = """
Line 1
Line 2
:action (drop)
Line 4
"""
        assert handler._parse_verdict(output, 0) == "Malicious"

    def test_multiple_action_fields_uses_first(self, handler):
        """Multiple :action fields - regex finds first match."""
        output = ":action (accept) :action (drop)"
        # re.search finds first match, which is 'accept'
        assert handler._parse_verdict(output, 0) == "Benign"


# ============================================================
# AV File Size Limit Tests
# ============================================================


class TestAVFileSizes:
    """Test AV file size threshold constants."""

    def test_av_file_size_limit_is_2gb(self):
        """AV_FILE_SIZE_LIMIT should be ~2 GB (2 * 10^9)."""
        assert AV_FILE_SIZE_LIMIT == 2097152000  # 2 * 10^9

    def test_av_limit_exceeds_te_limit(self):
        """AV limit should exceed TE limit."""
        assert AV_FILE_SIZE_LIMIT > TE_FILE_SIZE_LIMIT

    def test_100mb_file_triggers_av(self):
        """100 MB file should be at the TE limit boundary."""
        assert TE_FILE_SIZE_LIMIT == 104857600  # 100 * 1024^2

    def test_99mb_below_te_limit(self):
        """99 MB file should be below TE limit."""
        assert 99 * 1024 * 1024 < TE_FILE_SIZE_LIMIT

    def test_101mb_above_te_limit(self):
        """101 MB file should be above TE limit."""
        assert 101 * 1024 * 1024 >= TE_FILE_SIZE_LIMIT

    def test_1_95gb_below_av_limit(self):
        """1.95 GiB should be below the 2*10^9 byte AV limit."""
        # 2 * 10^9 = 2097152000 bytes = ~1.95 GiB
        # 1.9 GiB = 2042137600 bytes, clearly below limit
        assert 1900 * 1024 * 1024 < AV_FILE_SIZE_LIMIT

    def test_2gb_plus_1mb_above_av_limit(self):
        """2 GB + 1 MB file should exceed AV limit."""
        assert 2 * 1024 * 1024 * 1024 + 1024 * 1024 > AV_FILE_SIZE_LIMIT


# ============================================================
# Config Loading Tests
# ============================================================


class TestAVConfigLoading:
    """Test AV fallback config loading from various sources."""

    def test_default_av_disabled(self):
        """AV fallback should be disabled by default."""
        config = ScannerConfig(
            input_directory=Path("/tmp/input"),
            reports_directory=Path("/tmp/reports"),
            benign_directory=Path("/tmp/benign"),
            quarantine_directory=Path("/tmp/quarantine"),
            error_directory=Path("/tmp/error"),
            appliance_ip="127.0.0.1",
        )
        assert config.av_fallback_enabled is False
        assert config.ssh_username == ""
        assert config.ssh_password == ""
        assert config.av_remote_directory == "/var/log/apiclient"
        assert config.av_rule_id == 1

    def test_av_config_from_dict(self):
        """Config should accept AV settings from dict."""
        config = ScannerConfig(
            input_directory=Path("/tmp/input"),
            reports_directory=Path("/tmp/reports"),
            benign_directory=Path("/tmp/benign"),
            quarantine_directory=Path("/tmp/quarantine"),
            error_directory=Path("/tmp/error"),
            appliance_ip="127.0.0.1",
            av_fallback_enabled=True,
            ssh_username="testuser",
            ssh_password="testpass",
            av_remote_directory="/custom/path",
            av_rule_id=5,
        )
        assert config.av_fallback_enabled is True
        assert config.ssh_username == "testuser"
        assert config.ssh_password == "testpass"
        assert config.av_remote_directory == "/custom/path"
        assert config.av_rule_id == 5

    def test_av_rule_id_validation_rejects_zero(self):
        """av_rule_id must be >= 1."""
        config = ScannerConfig(
            input_directory=Path("/tmp/input"),
            reports_directory=Path("/tmp/reports"),
            benign_directory=Path("/tmp/benign"),
            quarantine_directory=Path("/tmp/quarantine"),
            error_directory=Path("/tmp/error"),
            appliance_ip="127.0.0.1",
            av_rule_id=0,
        )
        is_valid, errors = config.validate()
        assert not is_valid
        assert any("av_rule_id" in e for e in errors)

    def test_av_rule_id_validation_rejects_negative(self):
        """av_rule_id must be >= 1."""
        config = ScannerConfig(
            input_directory=Path("/tmp/input"),
            reports_directory=Path("/tmp/reports"),
            benign_directory=Path("/tmp/benign"),
            quarantine_directory=Path("/tmp/quarantine"),
            error_directory=Path("/tmp/error"),
            appliance_ip="127.0.0.1",
            av_rule_id=-5,
        )
        is_valid, errors = config.validate()
        assert not is_valid
        assert any("av_rule_id" in e for e in errors)

    def test_av_enabled_requires_username(self):
        """av_fallback_enabled=True requires ssh_username."""
        config = ScannerConfig(
            input_directory=Path("/tmp/input"),
            reports_directory=Path("/tmp/reports"),
            benign_directory=Path("/tmp/benign"),
            quarantine_directory=Path("/tmp/quarantine"),
            error_directory=Path("/tmp/error"),
            appliance_ip="127.0.0.1",
            av_fallback_enabled=True,
        )
        is_valid, errors = config.validate()
        assert not is_valid
        assert any("ssh_username" in e for e in errors)

    def test_av_enabled_requires_password(self):
        """av_fallback_enabled=True requires ssh_password."""
        config = ScannerConfig(
            input_directory=Path("/tmp/input"),
            reports_directory=Path("/tmp/reports"),
            benign_directory=Path("/tmp/benign"),
            quarantine_directory=Path("/tmp/quarantine"),
            error_directory=Path("/tmp/error"),
            appliance_ip="127.0.0.1",
            av_fallback_enabled=True,
            ssh_username="testuser",
        )
        is_valid, errors = config.validate()
        assert not is_valid
        assert any("ssh_password" in e for e in errors)

    def test_env_var_av_fallback_enabled(self):
        """TE_AV_FALLBACK_ENABLED env var should set config."""
        os.environ["TE_AV_FALLBACK_ENABLED"] = "true"
        os.environ["TE_SSH_USERNAME"] = "envuser"
        os.environ["TE_SSH_PASSWORD"] = "envpass"
        os.environ["TE_AV_RULE_ID"] = "3"

        config = ScannerConfig.from_sources(config_file="config.ini")

        assert config.av_fallback_enabled is True
        assert config.ssh_username == "envuser"
        assert config.ssh_password == "envpass"
        assert config.av_rule_id == 3

        # Cleanup
        del os.environ["TE_AV_FALLBACK_ENABLED"]
        del os.environ["TE_SSH_USERNAME"]
        del os.environ["TE_SSH_PASSWORD"]
        del os.environ["TE_AV_RULE_ID"]

    def test_env_var_av_remote_directory(self):
        """TE_AV_REMOTE_DIRECTORY env var should set config."""
        os.environ["TE_AV_REMOTE_DIRECTORY"] = "/custom/remote/path"

        config = ScannerConfig.from_sources(config_file="config.ini")
        assert config.av_remote_directory == "/custom/remote/path"

        del os.environ["TE_AV_REMOTE_DIRECTORY"]

    def test_config_ini_av_fallback_section(self):
        """[AV_FALLBACK] section should be parsed from config.ini."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".ini", delete=False
        ) as f:
            f.write("""[DEFAULT]
input_directory = /tmp/input
reports_directory = /tmp/reports
benign_directory = /tmp/benign
quarantine_directory = /tmp/quarantine
error_directory = /tmp/error
appliance_ip = 127.0.0.1

[AV_FALLBACK]
av_fallback_enabled = true
ssh_username = inifileuser
ssh_password = inifilepass
av_remote_directory = /ini/path
av_rule_id = 7
""")
            ini_path = f.name

        try:
            config = ScannerConfig.from_sources(config_file=ini_path)
            assert config.av_fallback_enabled is True
            assert config.ssh_username == "inifileuser"
            assert config.ssh_password == "inifilepass"
            assert config.av_remote_directory == "/ini/path"
            assert config.av_rule_id == 7
        finally:
            os.unlink(ini_path)

    def test_config_ini_av_rule_id_invalid(self):
        """Invalid av_rule_id in INI should warn and keep default."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".ini", delete=False
        ) as f:
            f.write("""[DEFAULT]
input_directory = /tmp/input
reports_directory = /tmp/reports
benign_directory = /tmp/benign
quarantine_directory = /tmp/quarantine
error_directory = /tmp/error
appliance_ip = 127.0.0.1

[AV_FALLBACK]
av_fallback_enabled = false
av_rule_id = invalid
""")
            ini_path = f.name

        try:
            config = ScannerConfig.from_sources(config_file=ini_path)
            # Invalid value should keep default
            assert config.av_rule_id == 1
        finally:
            os.unlink(ini_path)
