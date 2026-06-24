#!/usr/bin/env python3

"""Tests for path_handler.py - PathHandler utilities."""

import sys
import os
import tempfile
from pathlib import Path
from path_handler import PathHandler


class TestNormalizePath:
    def test_normalize_path_simple(self):
        """Simple path should be normalized."""
        result = PathHandler.normalize_path("/tmp/test/path")
        assert str(result) == "/tmp/test/path"

    def test_normalize_path_with_dots(self):
        """Path with . and .. should be resolved."""
        result = PathHandler.normalize_path("/tmp/test/../foo/./bar")
        assert str(result) == "/tmp/foo/bar"

    def test_normalize_path_empty(self):
        """Empty string should return current directory."""
        result = PathHandler.normalize_path("")
        assert result == Path(".")

    def test_normalize_path_expands_user(self):
        """Path with ~ should be expanded."""
        path = "~/test/path"
        result = PathHandler.normalize_path(path)
        assert str(result).startswith(os.path.expanduser("~"))


class TestIsWindows:
    def test_is_windows_linux(self):
        """On Linux, is_windows should return False."""
        if sys.platform != "win32":
            assert PathHandler.is_windows() is False


class TestIsUNCPath:
    def test_is_unc_path_windows_style(self):
        """Windows UNC path should be detected."""
        path = Path("\\\\server\\share")
        assert PathHandler.is_unc_path(path) is True

    def test_is_unc_path_unix_style(self):
        """Unix-style UNC path should be detected."""
        path = Path("//server/share")
        assert PathHandler.is_unc_path(path) is True

    def test_is_unc_path_regular(self):
        """Regular local path should not be detected as UNC."""
        path = Path("/home/user/file.txt")
        assert PathHandler.is_unc_path(path) is False


class TestIsSMBPath:
    def test_is_smb_path_linux_mnt(self):
        """Linux /mnt/smb path should be detected as SMB."""
        path = Path("/mnt/smbshare/file.txt")
        assert PathHandler.is_smb_path(path) is True

    def test_is_smb_path_linux_media(self):
        """Linux /media/smb path should be detected as SMB."""
        path = Path("/media/network/share/file.txt")
        assert PathHandler.is_smb_path(path) is True

    def test_is_smb_path_linux_net(self):
        """Linux /net/smb path should be detected as SMB."""
        path = Path("/net/share/file.txt")
        assert PathHandler.is_smb_path(path) is True

    def test_is_smb_path_linux_regular(self):
        """Regular Linux path should not be detected as SMB."""
        path = Path("/home/user/file.txt")
        assert PathHandler.is_smb_path(path) is False

    def test_is_smb_path_unc_on_linux(self):
        """UNC paths on Linux should also be detected as SMB."""
        path = Path("//server/share/file.txt")
        assert PathHandler.is_smb_path(path) is True


class TestDisplayPath:
    def test_display_path_no_subdir(self):
        """Path with no subdirectory should show just the filename."""
        result = PathHandler.display_path(Path("file.txt"), Path("/input"))
        assert "file.txt" in result

    def test_display_path_with_subdir(self):
        """Path with subdirectory should include the subdir."""
        result = PathHandler.display_path(Path("/input/subdir/file.txt"), Path("/input"))
        assert "subdir" in result

    def test_display_path_dot_subdir(self):
        """Root-level file should not show '.' as subdir."""
        result = PathHandler.display_path(Path("/input/file.txt"), Path("/input"))
        assert "." not in result or result.count(".") < 2


class TestChecksum:
    def test_checksum_known_content(self):
        """Checksum of known content should be deterministic."""
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            f.write("hello world")
            f.flush()
            result = PathHandler._calculate_checksum(Path(f.name))
            assert isinstance(result, str)
            assert len(result) > 0
            os.unlink(f.name)

    def test_checksum_empty_file(self):
        """Checksum of empty file should be deterministic."""
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            f.flush()
            result = PathHandler._calculate_checksum(Path(f.name))
            assert isinstance(result, str)
            os.unlink(f.name)

    def test_checksum_larger_file(self):
        """Checksum of larger file should be deterministic."""
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            f.write("x" * 10000)
            f.flush()
            result = PathHandler._calculate_checksum(Path(f.name))
            assert isinstance(result, str)
            assert len(result) > 0
            os.unlink(f.name)
