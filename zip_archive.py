#!/usr/bin/env python3

"""
zip_archive.py v10.0 (alpha)
Manages creation of password-protected zip archives for batch file processing.
Files are added to the zip before they are moved to verdict directories.

In multiprocessing mode, workers copy files to a temp directory, then the
main process consolidates everything into the zip archive.
In single-process mode (watch mode), files are added directly to the zip.
"""

import os
import shutil
import zipfile
import logging
from pathlib import Path


class ZipArchiveManager:
    """
    Manages a password-protected zip archive.
    
    Usage:
        zip_mgr = ZipArchiveManager.create_archive(archive_dir, password, timestamp)
        if zip_mgr:
            zip_mgr.add_file(source_path, 'benign', 'subdir', 'file.txt')
            zip_mgr.close()  # returns path to .zip
            # or zip_mgr.abort()  # deletes incomplete zip
    """
    
    def __init__(self, archive_dir, password, timestamp):
        self.archive_dir = Path(archive_dir)
        self.password = password
        self.timestamp = timestamp
        self.zip_path = self.archive_dir / f"{timestamp}.zip"
        self.logger = logging.getLogger('te_scanner.zip_archive')
        self._zip_file = None
    
    def _open(self):
        """Open the zip file for writing."""
        self.archive_dir.mkdir(parents=True, exist_ok=True)
        self._zip_file = zipfile.ZipFile(
            str(self.zip_path), 'w',
            compression=zipfile.ZIP_DEFLATED
        )
        self._zip_file.setpassword(self.password.encode('utf-8'))
    
    @classmethod
    def create_archive(cls, archive_dir, password, timestamp):
        """
        Create a new zip archive.
        
        Args:
            archive_dir: Directory to store the zip file
            password: Password for the archive (must be non-empty)
            timestamp: Timestamp string in yyyymmddhhmmss format
            
        Returns:
            ZipArchiveManager instance, or None if archive cannot be created
        """
        if not password:
            return None
        
        try:
            mgr = cls(archive_dir, password, timestamp)
            mgr._open()
            mgr.logger.info(f"Created zip archive: {mgr.zip_path}")
            return mgr
        except Exception as e:
            logger = logging.getLogger('te_scanner.zip_archive')
            logger.error(f"Failed to create zip archive: {e}")
            return None
    
    def add_file(self, source_path, verdict_basename, sub_dir, file_name):
        """
        Copy a file into the zip archive.
        
        Args:
            source_path: Full path to the source file (must exist)
            verdict_basename: Directory name inside zip (e.g. 'benign', 'quarantine', 'error')
            sub_dir: Subdirectory relative to input (empty string if at root)
            file_name: Name of the file
        """
        if self._zip_file is None:
            return
        
        try:
            src = Path(source_path)
            if not src.exists():
                self.logger.warning(f"File no longer exists, cannot add to zip: {src}")
                return
            
            # Build internal zip path: {verdict_basename}/{sub_dir}/{file_name}
            if sub_dir:
                internal_path = f"{verdict_basename}/{sub_dir}/{file_name}"
            else:
                internal_path = f"{verdict_basename}/{file_name}"
            
            self._zip_file.write(src, internal_path)
            self.logger.debug(f"Added to zip: {internal_path}")
            
        except Exception as e:
            self.logger.error(f"Failed to add file to zip archive ({file_name}): {e}")
    
    def consolidate(self, temp_dir, verdict_basenames, password):
        """
        Consolidate files from a temp directory into the zip archive.
        Used after multiprocessing workers copy files to the temp directory.
        
        Args:
            temp_dir: Path to temp directory containing copies organized as {verdict}/{subdir}/{file}
            verdict_basenames: List of (verdict_basename, benign_basename, quarantine_basename, error_basename)
            password: Password for the zip archive
        """
        if self._zip_file is None:
            return
        
        temp_path = Path(temp_dir)
        if not temp_path.exists():
            self.logger.debug("No temp directory found, nothing to consolidate")
            return
        
        try:
            for verdict_basename in verdict_basenames:
                verdict_dir = temp_path / verdict_basename
                if not verdict_dir.exists():
                    continue
                self._consolidate_dir(verdict_dir, verdict_basename, "")
            self.logger.info(f"Consolidated files from temp directory into {self.zip_path}")
        except Exception as e:
            self.logger.error(f"Failed to consolidate temp directory into zip: {e}")
    
    def _consolidate_dir(self, dir_path, verdict_basename, rel_path):
        """Recursively walk temp dir and add files to zip."""
        for item in dir_path.iterdir():
            if item.is_file():
                if rel_path:
                    internal_path = f"{verdict_basename}/{rel_path}/{item.name}"
                else:
                    internal_path = f"{verdict_basename}/{item.name}"
                self._zip_file.write(item, internal_path)
                self.logger.debug(f"Consolidated to zip: {internal_path}")
            elif item.is_dir():
                new_rel = f"{rel_path}/{item.name}" if rel_path else item.name
                self._consolidate_dir(item, verdict_basename, new_rel)
    
    def close(self):
        """
        Close the zip archive and return its path.
        
        Returns:
            Path to the closed .zip file, or None if archive was never opened
        """
        if self._zip_file is None:
            return None
        
        try:
            self._zip_file.close()
            self.logger.info(f"Zip archive closed: {self.zip_path} ({self._get_archive_size(self.zip_path)})")
            return self.zip_path
        except Exception as e:
            self.logger.error(f"Error closing zip archive: {e}")
            self._zip_file = None
            return None
    
    def abort(self):
        """
        Abort the archive: close and delete the incomplete zip file.
        """
        if self._zip_file is not None:
            try:
                self._zip_file.close()
            except Exception:
                pass
        
        if self.zip_path.exists():
            try:
                self.zip_path.unlink()
                self.logger.info(f"Aborted zip archive deleted: {self.zip_path}")
            except Exception as e:
                self.logger.error(f"Failed to delete aborted zip archive: {e}")
        
        self._zip_file = None
    
    @staticmethod
    def _get_archive_size(zip_path):
        """Get human-readable archive size."""
        try:
            size = zip_path.stat().st_size
            if size < 1024:
                return f"{size} bytes"
            elif size < 1024 * 1024:
                return f"{size / 1024:.1f} KB"
            else:
                return f"{size / (1024 * 1024):.1f} MB"
        except Exception:
            return "unknown size"
