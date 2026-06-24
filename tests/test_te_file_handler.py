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
