#!/usr/bin/env python3

"""Tests for te_api.py - file discovery and categorization."""

import os
import tempfile
from pathlib import Path
from te_api import discover_files, find_and_delete_empty_subdirectories


def _setup_test_directory(files_with_content=None):
    """Helper: create a temp directory with specified files, return (input_dir, files)."""
    tmpdir = tempfile.mkdtemp()
    input_dir = Path(tmpdir)
    if files_with_content:
        for filename, content in files_with_content.items():
            filepath = input_dir / filename
            filepath.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(content, str):
                filepath.write_text(content)
            else:
                filepath.write_bytes(content)
    return input_dir


class TestDiscoverFiles:
    def test_discover_files_basic(self):
        """Basic file discovery should return files categorized correctly."""
        input_dir = _setup_test_directory({
            "file1.exe": b"content1",
            "file2.doc": b"content2",
        })
        try:
            from config_manager import ScannerConfig
            config = ScannerConfig(
                input_directory=input_dir,
                reports_directory=Path("/tmp"),
                benign_directory=Path("/tmp"),
                quarantine_directory=Path("/tmp"),
                error_directory=Path("/tmp"),
                appliance_ip="10.0.0.1",
                archive_extensions={"zip", "rar"},
            )
            archives, others, av_files, signature_files = discover_files(input_dir, config)
            assert len(archives) == 0
            assert len(others) == 2
        finally:
            import shutil
            shutil.rmtree(input_dir, ignore_errors=True)

    def test_discover_files_archive_split(self):
        """Archive files should be separated from other files."""
        input_dir = _setup_test_directory({
            "data.zip": b"zip content",
            "data.rar": b"rar content",
            "document.pdf": b"pdf content",
        })
        try:
            from config_manager import ScannerConfig
            config = ScannerConfig(
                input_directory=input_dir,
                reports_directory=Path("/tmp"),
                benign_directory=Path("/tmp"),
                quarantine_directory=Path("/tmp"),
                error_directory=Path("/tmp"),
                appliance_ip="10.0.0.1",
                archive_extensions={"zip", "rar", "7z"},
            )
            archives, others, av_files, signature_files = discover_files(input_dir, config)
            assert len(archives) == 2
            assert len(others) == 1
        finally:
            import shutil
            shutil.rmtree(input_dir, ignore_errors=True)

    def test_discover_files_other_files_structure(self):
        """Other files should be returned as tuples of (name, safe_name, sub_dir, full_path)."""
        input_dir = _setup_test_directory({
            "file.exe": b"content",
        })
        try:
            from config_manager import ScannerConfig
            config = ScannerConfig(
                input_directory=input_dir,
                reports_directory=Path("/tmp"),
                benign_directory=Path("/tmp"),
                quarantine_directory=Path("/tmp"),
                error_directory=Path("/tmp"),
                appliance_ip="10.0.0.1",
                archive_extensions=set(),
            )
            archives, others, av_files, signature_files = discover_files(input_dir, config)
            assert len(others) == 1
            file_tuple = list(others)[0]
            assert len(file_tuple) == 4
            assert file_tuple[0] == "file.exe"
        finally:
            import shutil
            shutil.rmtree(input_dir, ignore_errors=True)

    def test_discover_files_empty_directory(self):
        """Empty directory should return empty sets."""
        input_dir = _setup_test_directory({})
        try:
            from config_manager import ScannerConfig
            config = ScannerConfig(
                input_directory=input_dir,
                reports_directory=Path("/tmp"),
                benign_directory=Path("/tmp"),
                quarantine_directory=Path("/tmp"),
                error_directory=Path("/tmp"),
                appliance_ip="10.0.0.1",
                archive_extensions=set(),
            )
            archives, others, av_files, signature_files = discover_files(input_dir, config)
            assert len(archives) == 0
            assert len(others) == 0
        finally:
            import shutil
            shutil.rmtree(input_dir, ignore_errors=True)

    def test_discover_files_no_archive_extensions(self):
        """Files with no matching archive extensions should be 'other' files."""
        input_dir = _setup_test_directory({
            "data.zip": b"zip content",
            "archive.7z": b"7z content",
        })
        try:
            from config_manager import ScannerConfig
            config = ScannerConfig(
                input_directory=input_dir,
                reports_directory=Path("/tmp"),
                benign_directory=Path("/tmp"),
                quarantine_directory=Path("/tmp"),
                error_directory=Path("/tmp"),
                appliance_ip="10.0.0.1",
                archive_extensions=set(),  # no archive extensions
            )
            archives, others, av_files, signature_files = discover_files(input_dir, config)
            assert len(archives) == 0
            assert len(others) == 2
        finally:
            import shutil
            shutil.rmtree(input_dir, ignore_errors=True)

    def test_discover_files_sub_dir_root(self):
        """Files in subdirectories should have correct sub_dir in tuples."""
        input_dir = _setup_test_directory({
            "subdir1/file.txt": b"content",
        })
        try:
            from config_manager import ScannerConfig
            config = ScannerConfig(
                input_directory=input_dir,
                reports_directory=Path("/tmp"),
                benign_directory=Path("/tmp"),
                quarantine_directory=Path("/tmp"),
                error_directory=Path("/tmp"),
                appliance_ip="10.0.0.1",
                archive_extensions=set(),
            )
            archives, others, av_files, signature_files = discover_files(input_dir, config)
            assert len(others) == 1
            file_tuple = list(others)[0]
            assert file_tuple[2] == "subdir1"  # sub_dir
        finally:
            import shutil
            shutil.rmtree(input_dir, ignore_errors=True)

    def test_discover_files_sub_dir_nested(self):
        """Files in nested subdirectories should have correct nested sub_dir."""
        input_dir = _setup_test_directory({
            "subdir1/subdir2/file.txt": b"content",
        })
        try:
            from config_manager import ScannerConfig
            config = ScannerConfig(
                input_directory=input_dir,
                reports_directory=Path("/tmp"),
                benign_directory=Path("/tmp"),
                quarantine_directory=Path("/tmp"),
                error_directory=Path("/tmp"),
                appliance_ip="10.0.0.1",
                archive_extensions=set(),
            )
            archives, others, av_files, signature_files = discover_files(input_dir, config)
            assert len(others) == 1
            file_tuple = list(others)[0]
            assert file_tuple[2] == "subdir1/subdir2"
        finally:
            import shutil
            shutil.rmtree(input_dir, ignore_errors=True)

    def test_discover_files_case_insensitive_extension(self):
        """Archive extension matching should be case-insensitive."""
        input_dir = _setup_test_directory({
            "data.ZIP": b"zip content upper",
            "data.Zip": b"zip content mixed",
            "data.zip": b"zip content lower",
        })
        try:
            from config_manager import ScannerConfig
            config = ScannerConfig(
                input_directory=input_dir,
                reports_directory=Path("/tmp"),
                benign_directory=Path("/tmp"),
                quarantine_directory=Path("/tmp"),
                error_directory=Path("/tmp"),
                appliance_ip="10.0.0.1",
                archive_extensions={"zip"},
            )
            archives, others, av_files, signature_files = discover_files(input_dir, config)
            assert len(archives) == 3
        finally:
            import shutil
            shutil.rmtree(input_dir, ignore_errors=True)


class TestFindDeleteEmptySubdirs:
    def test_find_delete_empty_subdirs_removes_empty(self):
        """Empty subdirectories should be removed."""
        input_dir = _setup_test_directory({})
        subdir = input_dir / "empty_sub"
        subdir.mkdir()
        try:
            find_and_delete_empty_subdirectories(input_dir)
            assert not subdir.exists()
        finally:
            import shutil
            shutil.rmtree(input_dir, ignore_errors=True)

    def test_find_delete_empty_subdirs_no_subdirs(self):
        """Directory with no subdirs should not be modified."""
        input_dir = _setup_test_directory({
            "file.txt": "content",
        })
        original_count = len(list(input_dir.iterdir()))
        try:
            find_and_delete_empty_subdirectories(input_dir)
            new_count = len(list(input_dir.iterdir()))
            assert new_count == original_count
        finally:
            import shutil
            shutil.rmtree(input_dir, ignore_errors=True)

    def test_find_delete_empty_subdirs_preserves_nonempty(self):
        """Non-empty subdirectories should be preserved."""
        input_dir = _setup_test_directory({
            "nonempty/file.txt": "content",
        })
        try:
            find_and_delete_empty_subdirectories(input_dir)
            assert (input_dir / "nonempty").exists()
            assert (input_dir / "nonempty" / "file.txt").exists()
        finally:
            import shutil
            shutil.rmtree(input_dir, ignore_errors=True)

    def test_find_delete_empty_subdirs_nested(self):
        """Nested empty directories should all be removed."""
        input_dir = _setup_test_directory({})
        (input_dir / "a" / "b" / "c").mkdir(parents=True)
        try:
            find_and_delete_empty_subdirectories(input_dir)
            assert not (input_dir / "a").exists()
        finally:
            import shutil
            shutil.rmtree(input_dir, ignore_errors=True)

    def test_find_delete_empty_subdirs_mixed(self):
        """Mixed empty and non-empty subdirs: only empty should be removed."""
        input_dir = _setup_test_directory({
            "keep_me/file.txt": "content",
        })
        # Create an empty subdirectory manually (no files)
        empty_dir = input_dir / "empty_dir"
        empty_dir.mkdir()
        try:
            find_and_delete_empty_subdirectories(input_dir)
            assert (input_dir / "keep_me").exists()
            assert not empty_dir.exists()
        finally:
            import shutil
            shutil.rmtree(input_dir, ignore_errors=True)
