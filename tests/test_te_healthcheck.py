#!/usr/bin/env python3

"""Tests for te_healthcheck.py - TE API and AV health checks."""

import os
from pathlib import Path
import unittest.mock as mock


def _make_config(**overrides):
    """Create a MagicMock config with default healthcheck settings."""
    config = mock.MagicMock()
    # Set attributes directly on the MagicMock (not via __dict__)
    config.appliance_ip = "10.0.0.1"
    config.appliance_skip_tls_verify = False
    for key, value in overrides.items():
        setattr(config, key, value)
    return config


class TestCheckTEHealth:
    def test_check_te_health_healthy(self):
        """Healthy TE API should return healthy=True with Benign verdict."""
        import requests
        mock_response = mock.MagicMock()
        mock_response.json.return_value = {
            "response": [
                {
                    "status": {"code": "0", "label": "FOUND"},
                    "te_eb": {
                        "status": {"label": "FOUND"},
                        "combined_verdict": "Benign",
                    },
                }
            ]
        }
        hc_dir = Path(__file__).parent / "_test_hc_te1"
        hc_dir.mkdir(parents=True, exist_ok=True)
        #   Write the test file
        (hc_dir / "test_clean.pdf").write_bytes(
            b"X5O!P%@AP[4\x5cPZX54(P^)7CC)7}$EICAR"
        )

        try:
            from te_healthcheck import check_te_health
            with mock.patch("requests.post", return_value=mock_response):
                result = check_te_health(_make_config(), hc_dir)
            assert result["healthy"] is True
            assert "Benign" in result["message"]
        finally:
            (hc_dir / "test_clean.pdf").unlink(missing_ok=True)

    def test_check_te_health_unhealthy(self):
        """Unhealthy TE API should return healthy=False."""
        import requests
        hc_dir = Path(__file__).parent / "_test_hc_te2"
        hc_dir.mkdir(parents=True, exist_ok=True)
        (hc_dir / "test_clean.pdf").write_bytes(b"test")

        try:
            from te_healthcheck import check_te_health
            with mock.patch("requests.post", side_effect=requests.exceptions.ConnectionError()):
                result = check_te_health(_make_config(), hc_dir)
            assert result["healthy"] is False
        finally:
            (hc_dir / "test_clean.pdf").unlink(missing_ok=True)

    def test_check_te_health_wrong_verdict(self):
        """TE API returning Malicious should fail health check."""
        import requests
        mock_response = mock.MagicMock()
        mock_response.json.return_value = {
            "response": [
                {
                    "status": {"code": "0", "label": "FOUND"},
                    "te_eb": {
                        "status": {"label": "FOUND"},
                        "combined_verdict": "Malicious",
                    },
                }
            ]
        }
        hc_dir = Path(__file__).parent / "_test_hc_te3"
        hc_dir.mkdir(parents=True, exist_ok=True)
        (hc_dir / "test_clean.pdf").write_bytes(b"test")

        try:
            from te_healthcheck import check_te_health
            with mock.patch("requests.post", return_value=mock_response):
                result = check_te_health(_make_config(), hc_dir)
            assert result["healthy"] is False
            assert "Malicious" in result["message"]
        finally:
            (hc_dir / "test_clean.pdf").unlink(missing_ok=True)

    def test_check_te_health_timeout(self):
        """TE API timeout should return healthy=False."""
        import requests
        hc_dir = Path(__file__).parent / "_test_hc_te4"
        hc_dir.mkdir(parents=True, exist_ok=True)
        (hc_dir / "test_clean.pdf").write_bytes(b"test")

        try:
            from te_healthcheck import check_te_health
            with mock.patch("requests.post", side_effect=TimeoutError("request timed out")):
                result = check_te_health(_make_config(), hc_dir)
            assert result["healthy"] is False
        finally:
            (hc_dir / "test_clean.pdf").unlink(missing_ok=True)


class TestCheckAVHealth:
    def test_check_av_health_healthy(self):
        """Healthy AV system should return healthy=True."""
        import paramiko
        
        # Mock the SFTP client for file transfer
        mock_sftp = mock.MagicMock()
        
        # Mock the SSH client and channel
        mock_client = mock.MagicMock()
        mock_client.open_sftp.return_value = mock_sftp
        mock_channel = mock.MagicMock()
        mock_channel.recv_exit_status.return_value = 0
        mock_stdout = mock.MagicMock()
        mock_stdout.channel = mock_channel
        mock_stdout.read.return_value = b":action (accept) :status (0)"
        mock_client.exec_command.return_value = (mock.MagicMock(), mock_stdout, mock.MagicMock())

        hc_dir = Path(__file__).parent / "_test_hc_av1"
        hc_dir.mkdir(parents=True, exist_ok=True)
        (hc_dir / "test_clean.docx").write_bytes(b"test zip")

        try:
            from te_healthcheck import check_av_health
            config = _make_config(
                av_fallback_enabled=True,
                ssh_username="testuser",
                ssh_password="testpass",
                av_remote_directory="/var/log/test",
                av_rule_id=1,
            )
            with mock.patch("paramiko.SSHClient", return_value=mock_client):
                result = check_av_health(config, hc_dir)
            assert result["healthy"] is True, f"Expected healthy, got: {result}"
        finally:
            (hc_dir / "test_clean.docx").unlink(missing_ok=True)

    def test_check_av_health_disabled(self):
        """AV health check still runs when called, even if av_fallback_enabled=False.
        The caller (te_api.py) gates the call on av_fallback_enabled."""
        hc_dir = Path(__file__).parent / "_test_hc_av2"
        hc_dir.mkdir(parents=True, exist_ok=True)
        (hc_dir / "test_clean.docx").write_bytes(b"test")

        try:
            import paramiko
            mock_client = mock.MagicMock()
            mock_sftp = mock.MagicMock()
            mock_client.open_sftp.return_value = mock_sftp
            mock_channel = mock.MagicMock()
            mock_channel.recv_exit_status.return_value = 0
            mock_stdout = mock.MagicMock()
            mock_stdout.channel = mock_channel
            mock_stdout.read.return_value = b":action (accept) :status (0)"
            mock_stderr = mock.MagicMock()
            mock_stderr.read.return_value = b""
            mock_client.exec_command.return_value = (mock.MagicMock(), mock_stdout, mock_stderr)

            from te_healthcheck import check_av_health
            config = _make_config(
                av_fallback_enabled=False,
                ssh_username="testuser",
                ssh_password="testpass",
                av_remote_directory="/var/log/test",
                av_rule_id=1,
            )
            with mock.patch("paramiko.SSHClient", return_value=mock_client):
                result = check_av_health(config, hc_dir)
            # check_av_health still runs even if disabled - the caller gates this
            assert result["healthy"] is True, f"Expected healthy, got: {result}"
        finally:
            (hc_dir / "test_clean.docx").unlink(missing_ok=True)

    def test_check_av_health_remote_dir_not_found(self):
        """AV SFTP put with missing remote directory should return actionable error."""
        import paramiko
        mock_client = mock.MagicMock()
        mock_sftp = mock.MagicMock()
        mock_sftp.put.side_effect = OSError(2, "No such file")
        mock_client.open_sftp.return_value = mock_sftp

        hc_dir = Path(__file__).parent / "_test_hc_av4"
        hc_dir.mkdir(parents=True, exist_ok=True)
        (hc_dir / "test_clean.docx").write_bytes(b"test")

        try:
            from te_healthcheck import check_av_health
            config = _make_config(
                av_fallback_enabled=True,
                ssh_username="testuser",
                ssh_password="testpass",
                av_remote_directory="/var/log/apiclient",
            )
            with mock.patch("paramiko.SSHClient", return_value=mock_client):
                result = check_av_health(config, hc_dir)
            assert result["healthy"] is False, f"Expected healthy=False, got: {result}"
            assert "AV destination directory does not exist" in result["av"]
            assert "config.ini" in result["av"]
            assert "[Errno 2]" not in result["av"]
        finally:
            (hc_dir / "test_clean.docx").unlink(missing_ok=True)

    def test_check_av_health_connection_failed(self):
        """AV SSH connection failure should return healthy=False."""
        import paramiko
        mock_client = mock.MagicMock()
        mock_client.connect.side_effect = paramiko.ssh_exception.SSHException("connection failed")

        hc_dir = Path(__file__).parent / "_test_hc_av3"
        hc_dir.mkdir(parents=True, exist_ok=True)
        (hc_dir / "test_clean.docx").write_bytes(b"test")

        try:
            from te_healthcheck import check_av_health
            config = _make_config(
                av_fallback_enabled=True,
                ssh_username="testuser",
                ssh_password="testpass",
            )
            with mock.patch("paramiko.SSHClient", return_value=mock_client):
                result = check_av_health(config, hc_dir)
            assert result["healthy"] is False
        finally:
            (hc_dir / "test_clean.docx").unlink(missing_ok=True)
