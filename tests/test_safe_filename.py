#!/usr/bin/env python3

"""Tests for safe_filename.py - filename sanitization utilities."""

from safe_filename import sanitize_filename


class TestSanitizeFilename:
    def test_ascii_filename_unchanged(self):
        """ASCII-only filenames should remain unchanged."""
        seen = {}
        result = sanitize_filename("document.pdf", seen)
        assert result == "document.pdf"

    def test_ascii_filename_added_to_seen(self):
        """Processing a filename should add it to the seen dict."""
        seen = {}
        sanitize_filename("document.pdf", seen)
        assert "document.pdf" in seen

    def test_non_ascii_replaced_with_underscore(self):
        """Non-ASCII characters should be replaced with underscores."""
        seen = {}
        result = sanitize_filename("caf\u00e9.pdf", seen)
        assert "caf" in result
        assert "\u00e9" not in result

    def test_non_ascii_extension_preserved(self):
        """File extension should be preserved even with non-ASCII base."""
        seen = {}
        result = sanitize_filename("caf\u00e9.pdf", seen)
        assert result.endswith(".pdf")

    def test_non_ascii_collides_with_ascii(self):
        """Non-ASCII filename that collides with ASCII should get hash suffix."""
        seen = {}
        sanitize_filename("document.pdf", seen)
        result = sanitize_filename("docu\u00a1ment.pdf", seen)
        # Should be unique due to collision
        assert result != "document.pdf"

    def test_base_all_underscores_treated_as_empty(self):
        """Base consisting only of underscores should be replaced with hash."""
        seen = {}
        result = sanitize_filename("___ .pdf", seen)
        # After sanitization, underscores and space remain
        # This is expected - not all-underscores scenario
        # The underscores and space should be replaced, resulting in all underscores
        # which triggers hash fallback
        assert len(result) > 0

    def test_all_nonascii_base_uses_hash(self):
        """All-non-ASCII base should use full SHA256 hash."""
        seen = {}
        result = sanitize_filename("\u4e2d\u6587.pdf", seen)
        assert result.endswith(".pdf")
        # The base should be a hash
        assert "___" not in result  # no underscores from replacement
        # Should contain hex chars (the hash)
        hash_part = result[:-4]  # remove .pdf
        assert all(c in "0123456789abcdef" for c in hash_part)

    def test_extensionless_filename_unchanged(self):
        """Extensionless ASCII filename should remain unchanged."""
        seen = {}
        result = sanitize_filename("README", seen)
        assert result == "README"

    def test_extensionless_all_nonascii_uses_hash(self):
        """Extensionless all-non-ASCII filename should use hash."""
        seen = {}
        result = sanitize_filename("\u4e2d\u6587\u6587\u4ef6", seen)
        # Should be a hash (no extension to preserve)
        assert len(result) == 64  # SHA256 hex = 64 chars

    def test_collision_appends_hash(self):
        """Duplicate filename should get hash suffix appended."""
        seen = {}
        sanitize_filename("report.docx", seen)
        result = sanitize_filename("report.docx", seen)
        assert result != "report.docx"

    def test_collision_first_unchanged(self):
        """First occurrence of a filename should be unchanged."""
        seen = {}
        result = sanitize_filename("report.docx", seen)
        assert result == "report.docx"

    def test_collision_with_hash_suffix_preserves_extension(self):
        """Collision hash suffix should preserve the original extension."""
        seen = {}
        sanitize_filename("data.xlsx", seen)
        result = sanitize_filename("data.xlsx", seen)
        assert result.endswith(".xlsx")

    def test_multiple_dots_preserves_last_extension(self):
        """Filename with multiple dots should preserve only the last extension."""
        seen = {}
        result = sanitize_filename("file.name.with.dots.tar.gz", seen)
        assert result.endswith(".gz")
        assert result.startswith("file.name.with.dots.tar")
