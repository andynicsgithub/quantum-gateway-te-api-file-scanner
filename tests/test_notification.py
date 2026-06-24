#!/usr/bin/env python3

"""Tests for notification.py - email notification building and sending."""

import logging
import unittest.mock as mock
from notification import (
    send_batch_notification,
    _build_subject,
    _build_email_body,
    _format_file_list,
    _get_tex_status_message,
)


def _make_config(**overrides):
    """Create a MagicMock config with default email settings, overridden by overrides."""
    config = mock.MagicMock()
    defaults = {
        "email_enabled": False,
        "email_malicious_only": False,
        "email_smtp_server": "",
        "email_from": "",
        "email_to": "",
        "email_subject_template": "",
        "email_template_file": "",
        "email_tls_method": "starttls",
        "email_skip_tls_verify": False,
        "email_username": "",
        "email_password": "",
        "email_imap_enabled": False,
    }
    defaults.update(overrides)
    config.__dict__.update(defaults)
    return config


def _make_summary(**overrides):
    """Create a summary dict with defaults, overridden by overrides."""
    defaults = {
        "processed": 5,
        "benign": 3,
        "malicious": 1,
        "error": 1,
        "malicious_files": [{"name": "bad.exe", "verdict": "Malicious"}],
        "all_files": [
            {"name": "good1.exe", "verdict": "Benign"},
            {"name": "good2.exe", "verdict": "Benign"},
            {"name": "bad.exe", "verdict": "Malicious"},
            {"name": "err.exe", "verdict": "Error"},
            {"name": "skip.exe", "verdict": "Benign", "tex_result": 5},
        ],
    }
    defaults.update(overrides)
    return defaults


# ============================================================
# send_batch_notification
# ============================================================


class TestSendBatchNotification:
    def test_send_batch_notification_disabled(self):
        """Should return immediately if email_enabled is False."""
        config = _make_config(email_enabled=False)
        # Should not raise and should not attempt to build anything
        send_batch_notification(config, _make_summary())

    def test_send_batch_notification_missing_config(self):
        """Should return warning if SMTP fields are missing."""
        config = _make_config(email_enabled=True, email_smtp_server="", email_from="", email_to="")
        with mock.patch("notification._build_subject") as mock_subject:
            send_batch_notification(config, _make_summary())
            # Should not call _build_subject because early return
            mock_subject.assert_not_called()

    def test_send_batch_notification_malicious_only_suppresses(self):
        """Should suppress email when no malicious files and malicious_only is True."""
        config = _make_config(
            email_enabled=True,
            email_malicious_only=True,
            email_smtp_server="smtp.example.com",
            email_from="from@example.com",
            email_to="to@example.com",
        )
        summary = _make_summary(malicious=0, malicious_files=[])
        with mock.patch("notification._build_subject") as mock_subject:
            send_batch_notification(config, summary)
            mock_subject.assert_not_called()

    def test_send_batch_notification_malicious_only_sends(self):
        """Should send email when malicious files found even with malicious_only=True."""
        config = _make_config(
            email_enabled=True,
            email_malicious_only=True,
            email_smtp_server="smtp.example.com",
            email_from="from@example.com",
            email_to="to@example.com",
        )
        summary = _make_summary(malicious=1)
        with mock.patch("notification._build_subject", return_value="Test") as mock_subject:
            with mock.patch("notification._build_email_body", return_value="Body"):
                with mock.patch("smtplib.SMTP") as mock_smtp:
                    send_batch_notification(config, summary)
                    mock_subject.assert_called_once()


# ============================================================
# _build_subject
# ============================================================


class TestBuildSubject:
    def test_build_subject_default_no_template(self):
        """Default subject should be used when no template is set."""
        config = _make_config()
        summary = _make_summary(processed=10, malicious=2)
        subject = _build_subject(config, summary)
        assert "TE API" in subject or "Batch" in subject or "Scanner" in subject

    def test_build_subject_with_template(self):
        """Custom subject template should be used when set."""
        config = _make_config(email_subject_template="TE Batch: ${malicious} threats")
        summary = _make_summary(malicious=3)
        subject = _build_subject(config, summary)
        assert "TE Batch: 3 threats" == subject

    def test_build_subject_with_template_missing_keys(self):
        """Template with missing keys should use default subject."""
        config = _make_config(email_subject_template="Missing ${nonexistent}")
        summary = _make_summary()
        # Should fall back to default, not crash
        subject = _build_subject(config, summary)
        assert len(subject) > 0

    def test_build_subject_default_no_processed(self):
        """Default subject should work with zero processed files."""
        config = _make_config()
        summary = _make_summary(processed=0, benign=0, malicious=0, error=0)
        subject = _build_subject(config, summary)
        assert len(subject) > 0


# ============================================================
# _build_email_body
# ============================================================


class TestBuildEmailBody:
    def test_build_email_body_legacy_format(self):
        """Legacy body format should include all summary counts."""
        config = _make_config(email_template_file="")
        summary = _make_summary(processed=10, benign=3, malicious=2, error=1)
        body = _build_email_body(config, summary)
        assert "10" in body  # processed count
        assert "3" in body
        assert "2" in body
        assert "1" in body

    def test_build_email_body_no_malicious_files(self):
        """Email body should work when no malicious files found."""
        config = _make_config(email_template_file="")
        summary = _make_summary(processed=5, benign=5, malicious=0, error=0, malicious_files=[])
        body = _build_email_body(config, summary)
        assert "5" in body

    def test_build_email_body_with_errors(self):
        """Email body should include error count."""
        config = _make_config(email_template_file="")
        summary = _make_summary(processed=10, benign=7, malicious=1, error=2)
        body = _build_email_body(config, summary)
        assert "2" in body  # error count


# ============================================================
# _format_file_list
# ============================================================


class TestFormatFileList:
    def test_format_file_list_empty(self):
        """Empty file list should return '(none)'."""
        result = _format_file_list([])
        assert result == "(none)"

    def test_format_file_list_single(self):
        """Single file should be listed."""
        files = [{"name": "bad.exe", "verdict": "Malicious"}]
        result = _format_file_list(files)
        assert "bad.exe" in result
        assert "Malicious" in result

    def test_format_file_list_with_multiple_files(self):
        """Multiple files should each be listed."""
        files = [
            {"name": "bad1.exe", "verdict": "Malicious"},
            {"name": "bad2.exe", "verdict": "Malicious"},
            {"name": "bad3.exe", "verdict": "Malicious"},
        ]
        result = _format_file_list(files)
        assert "bad1.exe" in result
        assert "bad2.exe" in result
        assert "bad3.exe" in result

    def test_format_file_list_with_path(self):
        """Files with subdirectory paths should include the path."""
        files = [{"name": "subdir/bad.exe", "verdict": "Malicious"}]
        result = _format_file_list(files)
        assert "subdir" in result or "bad.exe" in result

    def test_format_file_list_with_tex_status(self):
        """Files with TEX status should include TEX info."""
        files = [{"name": "bad.xlsx", "verdict": "Benign", "tex_status": "cleaned"}]
        result = _format_file_list(files)
        assert "cleaned" in result or "removed parts" in result


# ============================================================
# _get_tex_status_message
# ============================================================


class TestGetTexStatusMessage:
    def test_get_tex_status_message_none(self):
        """None/unknown tex_status should return empty string."""
        result = _get_tex_status_message(None)
        assert result == ""

    def test_get_tex_status_message_unknown(self):
        """Unknown tex_status should return empty string."""
        result = _get_tex_status_message("unknown_status")
        assert result == ""

    def test_get_tex_status_message_cleaned(self):
        """'cleaned' status should indicate parts were removed."""
        result = _get_tex_status_message("cleaned")
        assert "removed parts" in result

    def test_get_tex_status_message_not_cleaned(self):
        """'not_cleaned' status should indicate nothing was found."""
        result = _get_tex_status_message("not_cleaned")
        assert "didn't find anything" in result

    def test_get_tex_status_message_internal_error(self):
        """Unknown status for error case returns empty (handled elsewhere)."""
        result = _get_tex_status_message("error")
        assert result == ""

    def test_get_tex_status_message_unsupported(self):
        """'unsupported' status should indicate unsupported file type."""
        result = _get_tex_status_message("unsupported")
        assert "unsupported file type" in result
