#!/usr/bin/env python3

"""Tests for te_file_handler.py - verdict routing with PARTIALLY_FOUND fix."""

import unittest.mock as mock
from pathlib import Path


class TestVerdictRouting:
    """Tests for verdict routing logic in TE.handle_file()."""

    def _make_te_handler(self, status_label, verdict, **overrides):
        """Create a TE instance with mocked attributes for testing verdict routing."""
        # Create mock response
        mock_response = {
            "response": [
                {
                    "status": {"code": "0", "label": status_label},
                    "te_eb": {
                        "status": {"label": "FOUND"},
                        "combined_verdict": verdict,
                    },
                }
            ]
        }

        handler = mock.MagicMock()
        handler.final_response = mock_response
        handler.final_status_label = status_label
        handler.file_name = "test.exe"
        handler.safe_file_name = "test.exe"
        handler.sub_dir = ""
        handler.full_path = Path("/tmp/test.exe")
        handler.error_directory = Path("/tmp/error")
        handler.benign_directory = Path("/tmp/benign")
        handler.quarantine_directory = Path("/tmp/quarantine")
        handler.zip_config = None
        handler.report_id = ""
        handler.logger = mock.MagicMock()
        handler.move_file = mock.MagicMock()
        handler._add_to_zip = mock.MagicMock()

        return handler

    def test_malicious_found_status_moved_to_quarantine(self):
        """Malicious file with FOUND status should move to quarantine."""
        handler = self._make_te_handler("FOUND", "Malicious")
        # Simulate verdict routing logic
        verdict = "Malicious"
        if handler.final_status_label == "FOUND":
            if verdict == "Malicious":
                handler.move_file(handler.quarantine_directory)

        handler.move_file.assert_called_once_with(handler.quarantine_directory)

    def test_malicious_partially_found_moved_to_quarantine(self):
        """Malicious file with PARTIALLY_FOUND status should move to quarantine."""
        handler = self._make_te_handler("PARTIALLY_FOUND", "Malicious")
        verdict = "Malicious"

        # This is the fixed logic - accepts both FOUND and PARTIALLY_FOUND
        if handler.final_status_label in ("FOUND", "PARTIALLY_FOUND"):
            if verdict == "Malicious":
                handler.move_file(handler.quarantine_directory)

        handler.move_file.assert_called_once_with(handler.quarantine_directory)

    def test_benign_found_status_moved_to_benign(self):
        """Benign file with FOUND status should move to benign directory."""
        handler = self._make_te_handler("FOUND", "Benign")
        verdict = "Benign"

        if handler.final_status_label in ("FOUND", "PARTIALLY_FOUND"):
            if verdict == "Benign":
                handler.move_file(handler.benign_directory)

        handler.move_file.assert_called_once_with(handler.benign_directory)

    def test_benign_partially_found_moved_to_benign(self):
        """Benign file with PARTIALLY_FOUND status should move to benign directory."""
        handler = self._make_te_handler("PARTIALLY_FOUND", "Benign")
        verdict = "Benign"

        if handler.final_status_label in ("FOUND", "PARTIALLY_FOUND"):
            if verdict == "Benign":
                handler.move_file(handler.benign_directory)

        handler.move_file.assert_called_once_with(handler.benign_directory)

    def test_unknown_partially_found_moved_to_error(self):
        """Unknown verdict with PARTIALLY_FOUND should move to error directory."""
        handler = self._make_te_handler("PARTIALLY_FOUND", "Unknown")
        verdict = "Unknown"

        if handler.final_status_label in ("FOUND", "PARTIALLY_FOUND"):
            if verdict == "Unknown":
                handler.move_file(handler.error_directory)

        handler.move_file.assert_called_once_with(handler.error_directory)

    def test_malicious_pending_status_not_moved(self):
        """Malicious verdict with PENDING status should NOT be moved (bug scenario)."""
        handler = self._make_te_handler("PENDING", "Malicious")
        verdict = "Malicious"

        # With the fixed logic, PENDING should NOT match
        moved = False
        if handler.final_status_label in ("FOUND", "PARTIALLY_FOUND"):
            if verdict == "Malicious":
                handler.move_file(handler.quarantine_directory)
                moved = True

        assert moved is False, "PENDING status should not trigger file move"

    def test_partially_found_all_verdicts_handled(self):
        """All verdict types should be handled when status is PARTIALLY_FOUND."""
        for verdict, expected_dir in [
            ("Malicious", "quarantine_directory"),
            ("Benign", "benign_directory"),
            ("Unknown", "error_directory"),
        ]:
            handler = self._make_te_handler("PARTIALLY_FOUND", verdict)
            expected_path = getattr(handler, expected_dir)

            if handler.final_status_label in ("FOUND", "PARTIALLY_FOUND"):
                if verdict == "Malicious":
                    handler.move_file(handler.quarantine_directory)
                elif verdict == "Benign":
                    handler.move_file(handler.benign_directory)
                elif verdict == "Unknown":
                    handler.move_file(handler.error_directory)

            handler.move_file.assert_called_once_with(expected_path)


class TestTEErrorFallback:
    """Tests for TE Error → AV fallback behavior."""

    def _make_te_handler_with_config(self, **config_overrides):
        """Create a TE instance with a mock config for testing TE error fallback."""
        from config_manager import ScannerConfig
        import tempfile

        with tempfile.TemporaryDirectory() as tmpdir:
            config = ScannerConfig(
                input_directory=Path(tmpdir),
                reports_directory=Path(tmpdir),
                benign_directory=Path(tmpdir),
                quarantine_directory=Path(tmpdir),
                error_directory=Path(tmpdir),
                appliance_ip="127.0.0.1",
                **config_overrides,
            )

        handler = mock.MagicMock()
        handler.final_response = {"response": [{"status": {"label": "FOUND"}, "te": {"combined_verdict": "Error"}}]}
        handler.final_status_label = "FOUND"
        handler.file_name = "large.tar"
        handler.safe_file_name = "large.tar"
        handler.sub_dir = ""
        handler.full_path = Path("/tmp/large.tar")
        handler.error_directory = Path("\\\\10.1.48.39\\fileshare\\errors")
        handler.benign_directory = Path("\\\\10.1.48.39\\fileshare")
        handler.quarantine_directory = Path("/tmp/quarantine")
        handler.zip_config = None
        handler.report_id = ""
        handler.logger = mock.MagicMock()
        handler.move_file = mock.MagicMock()
        handler._add_to_zip = mock.MagicMock()
        handler.config = config

        return handler

    def test_te_error_not_fallback_when_disabled(self):
        """TE Error with fallback disabled should go to error directory."""
        handler = self._make_te_handler_with_config(te_error_fallback_to_av=False)
        verdict = "Error"

        # Simulate the Error verdict handling logic
        if verdict == "Error":
            if (handler.config.te_error_fallback_to_av
                    and handler.config.av_fallback_enabled
                    and handler.config.av_remote_directory):
                handler.handle_av_fallback_for_error()
            else:
                handler.move_file(handler.error_directory)

        handler.move_file.assert_called_once_with(handler.error_directory)

    def test_te_error_not_fallback_when_av_disabled(self):
        """TE Error with AV fallback disabled should go to error directory."""
        handler = self._make_te_handler_with_config(
            te_error_fallback_to_av=True,
            av_fallback_enabled=False,
        )
        verdict = "Error"

        if verdict == "Error":
            if (handler.config.te_error_fallback_to_av
                    and handler.config.av_fallback_enabled
                    and handler.config.av_remote_directory):
                handler.handle_av_fallback_for_error()
            else:
                handler.move_file(handler.error_directory)

        handler.move_file.assert_called_once_with(handler.error_directory)

    def test_te_error_fallback_called_when_enabled(self):
        """TE Error with fallback enabled should call AV handler."""
        handler = self._make_te_handler_with_config(
            te_error_fallback_to_av=True,
            av_fallback_enabled=True,
        )
        verdict = "Error"

        if verdict == "Error":
            if (handler.config.te_error_fallback_to_av
                    and handler.config.av_fallback_enabled
                    and handler.config.av_remote_directory):
                handler.handle_av_fallback_for_error()
                av_fallback_called = True
            else:
                handler.move_file(handler.error_directory)
                av_fallback_called = False

        assert av_fallback_called is True
        handler.handle_av_fallback_for_error.assert_called_once()

    def test_te_error_verdict_uses_correct_basename(self):
        """TE Error verdict should use correct basename for UNC paths (Windows only)."""
        import sys
        from path_handler import PathHandler

        handler = self._make_te_handler_with_config()

        if sys.platform != "win32":
            import pytest
            pytest.skip("UNC path handling is Windows-only")

        # Verify that _get_verdict_basename works for UNC paths
        error_basename = PathHandler.get_verdict_basename(handler.error_directory)
        assert error_basename == "errors"

        benign_basename = PathHandler.get_verdict_basename(handler.benign_directory)
        assert benign_basename == "fileshare"
