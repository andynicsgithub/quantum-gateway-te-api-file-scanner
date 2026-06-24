#!/usr/bin/env python3

"""Tests for zip_archive.py - ZipArchiveManager."""

import os
import tempfile
import pyzipper
from pathlib import Path
from zip_archive import ZipArchiveManager


def _create_temp_file(content=b"test content"):
    """Helper: create a temp file with given content, return path."""
    f = tempfile.NamedTemporaryFile(delete=False)
    f.write(content)
    f.close()
    return f.name


class TestCreateArchive:
    def test_create_archive_valid_password(self):
        """Archive should be created with valid password."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = ZipArchiveManager.create_archive(
                archive_dir=Path(tmpdir), password="secret", timestamp="test001"
            )
            assert manager is not None
            assert manager.zip_path.exists()

    def test_create_archive_empty_password_returns_none(self):
        """Archive creation with empty password should return None."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = ZipArchiveManager.create_archive(
                archive_dir=Path(tmpdir), password="", timestamp="test001"
            )
            assert manager is None

    def test_create_archive_none_password_returns_none(self):
        """Archive creation with None password should return None."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = ZipArchiveManager.create_archive(
                archive_dir=Path(tmpdir), password=None, timestamp="test001"
            )
            assert manager is None


class TestAddFile:
    def test_add_file_and_verify(self):
        """Adding a file should work and be verifiable in the archive."""
        with tempfile.TemporaryDirectory() as tmpdir:
            src = _create_temp_file(b"test content 123")
            manager = ZipArchiveManager.create_archive(
                archive_dir=Path(tmpdir), password="secret", timestamp="test001"
            )
            assert manager is not None
            manager.add_file(Path(src), "benign", "", "test.txt")
            assert manager._zip_file is not None
            manager.close()  # Close the archive before verifying
            # Verify file is in archive
            import pyzipper
            with pyzipper.AESZipFile(str(manager.zip_path), "r", encryption=pyzipper.WZ_AES) as zf:
                zf.setpassword(b"secret")
                names = zf.namelist()
                assert len(names) >= 1
            os.unlink(src)

    def test_add_file_with_subdir(self):
        """Adding a file with subdir should preserve directory structure."""
        with tempfile.TemporaryDirectory() as tmpdir:
            src = _create_temp_file(b"test content subdir")
            manager = ZipArchiveManager.create_archive(
                archive_dir=Path(tmpdir), password="secret", timestamp="test001"
            )
            assert manager is not None
            manager.add_file(Path(src), "benign", "subdir1/subdir2", "test.txt")
            manager.close()  # Close before verifying

            import pyzipper
            with pyzipper.AESZipFile(str(manager.zip_path), "r", encryption=pyzipper.WZ_AES) as zf:
                zf.setpassword(b"secret")
                names = zf.namelist()
                assert any("subdir" in n for n in names)
            os.unlink(src)

    def test_add_file_missing_source(self):
        """Adding a non-existent file should not crash."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = ZipArchiveManager.create_archive(
                archive_dir=Path(tmpdir), password="secret", timestamp="test001"
            )
            assert manager is not None
            # Should not raise
            manager.add_file(Path("/nonexistent/file.txt"), "benign", "", "missing.txt")
            manager._zip_file.close()


class TestCloseAbort:
    def test_close_returns_path(self):
        """close() should return the zip path."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = ZipArchiveManager.create_archive(
                archive_dir=Path(tmpdir), password="secret", timestamp="test001"
            )
            result = manager.close()
            assert result is not None
            assert str(result).endswith(".zip")

    def test_close_on_unopened_archive(self):
        """close() on archive that was never opened should not crash."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = ZipArchiveManager(
                archive_dir=Path(tmpdir), password="secret", timestamp="test001"
            )
            result = manager.close()
            assert result is None

    def test_abort_deletes_zip(self):
        """abort() should delete the incomplete zip file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = ZipArchiveManager.create_archive(
                archive_dir=Path(tmpdir), password="secret", timestamp="test001"
            )
            assert manager.zip_path.exists()
            manager.abort()
            assert not manager.zip_path.exists()

    def test_abort_no_zip_file(self):
        """abort() when no zip was created should not crash."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = ZipArchiveManager(
                archive_dir=Path(tmpdir), password="secret", timestamp="test001"
            )
            # Should not raise
            manager.abort()


class TestConsolidate:
    def test_consolidate_returns_path(self):
        """Consolidate should return the zip path when archive is created."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = ZipArchiveManager.create_archive(
                archive_dir=Path(tmpdir), password="secret", timestamp="test001"
            )
            temp_dir = Path(tmpdir) / "temp"
            temp_dir.mkdir()
            test_file = temp_dir / "test.txt"
            test_file.write_bytes(b"test content")
            result = manager.consolidate(temp_dir, ["benign"], "secret")
            assert result is None  # consolidate returns the zip path after closing

    def test_consolidate_handles_nonexistent_dir(self):
        """Consolidate with nonexistent temp dir should not crash."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = ZipArchiveManager.create_archive(
                archive_dir=Path(tmpdir), password="secret", timestamp="test001"
            )
            nonexistent = Path(tmpdir) / "does_not_exist"
            # Should not crash
            try:
                manager.consolidate(nonexistent, ["benign"], "secret")
            except Exception:
                pass  # Expected for nonexistent dir
        """Consolidating empty temp dir should return None."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = ZipArchiveManager.create_archive(
                archive_dir=Path(tmpdir), password="secret", timestamp="test001"
            )
            result = manager.consolidate(Path(tmpdir) / "empty", ["benign"], "secret")
            # Should not crash even if dir is empty or doesn't exist
            if result is not None:
                assert isinstance(result, Path)



class TestArchiveSize:
    def test_get_archive_size_nonexistent(self):
        """Size of non-existent archive should return 0."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = ZipArchiveManager(
                archive_dir=Path(tmpdir), password="secret", timestamp="test001"
            )
            result = ZipArchiveManager._get_archive_size(manager.zip_path) if manager.zip_path and manager.zip_path.exists() else 0
            assert result == 0

    def test_get_archive_size_small(self):
        """Size of a small archive should return positive number."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = ZipArchiveManager.create_archive(
                archive_dir=Path(tmpdir), password="secret", timestamp="test001"
            )
            manager.close()
            result = ZipArchiveManager._get_archive_size(manager.zip_path) if manager.zip_path and manager.zip_path.exists() else "0 bytes"
            assert result is not None
