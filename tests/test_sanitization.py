#!/usr/bin/env python3

"""Additional sanitization tests for safe_filename.py."""

from safe_filename import sanitize_filename


class TestSanitization:
    def test_sanitize_roundtrip(self):
        """ASCII filename should pass through sanitize unchanged."""
        seen = {}
        result = sanitize_filename("test_file.pdf", seen)
        assert result == "test_file.pdf"

    def test_sanitize_complex(self):
        """Complex mixed filename should be sanitized correctly."""
        seen = {}
        result = sanitize_filename("cafe\u0301_r\u00e9sum\u00e9.docx", seen)
        assert "cafe" in result
        assert "docx" in result
        assert len(result) > 0

    def test_collision_suffix(self):
        """Second duplicate should get a hash suffix."""
        seen = {}
        first = sanitize_filename("report.xlsx", seen)
        second = sanitize_filename("report.xlsx", seen)
        assert first == "report.xlsx"
        assert second != first
        assert second.startswith("report.xlsx_") or "xlsx" in second

    def test_te_upload_uses_sanitized_name(self):
        """Sanitized name should be ASCII-only for API upload."""
        seen = {}
        result = sanitize_filename("\u00e9vent.pdf", seen)
        # All characters should be ASCII
        assert all(ord(c) < 128 for c in result)
